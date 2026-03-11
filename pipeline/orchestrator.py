from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from alert_pipeline.alerts import build_alerts
from config.settings import PipelineConfig
from correlation.campaigns import build_attack_campaigns
from detections.engine import run_detections
from ingest.log_reader import iter_log_lines
from llm.analysis_context import (
    build_case_analysis_context,
    build_control_effectiveness,
    build_exposure_analysis,
    extract_case_iocs,
)
from llm.incident_analyzer import analyze_cases_with_ollama, analyze_cases_with_openai
from models.schemas import CampaignRecord, CaseRecord, EventRecord, PipelineRunResult
from parsers.eb_log_parser import parse_eb_engine_line, parse_eb_hooks_line
from parsers.nginx_parser import parse_nginx_access_line, parse_nginx_error_line
from parsers.web_stdout_parser import parse_web_stdout_line
from reports.llm_report_writer import write_llm_summary
from reports.report_writer import (
    write_json_alerts,
    write_json_campaigns,
    write_json_cases,
    write_json_run_metadata,
    write_markdown_report,
)
from threat_intel.enrich import enrich_cases_with_threat_intel


ParserFn = Callable[[str], Optional[Dict[str, Any]]]

PARSERS: Dict[str, ParserFn] = {
    "/var/log/nginx/access.log": parse_nginx_access_line,
    "/var/log/nginx/error.log": parse_nginx_error_line,
    "/var/log/web.stdout.log": parse_web_stdout_line,
    "/var/log/eb-engine.log": parse_eb_engine_line,
    "/var/log/eb-hooks.log": parse_eb_hooks_line,
}


def parse_generic_line(line: str, source: str) -> Dict[str, Any]:
    return {
        "timestamp": None,
        "source": source,
        "severity": "unknown",
        "message": line.strip(),
        "raw_line": line,
    }


def _now_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_utc")


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _parse_events(log_path: Path) -> tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], List[str]]:
    events: List[Dict[str, Any]] = []
    parsed_ok: Counter[str] = Counter()
    parsed_fail: Counter[str] = Counter()
    parser_header: Optional[str] = None
    errors: List[str] = []

    for line in iter_log_lines(log_path):
        if not line or line.startswith("----"):
            continue

        if line in PARSERS:
            parser_header = line
            continue

        parser = PARSERS.get(parser_header) if parser_header else None
        event = parser(line) if parser else None
        if event:
            parsed_ok[parser_header or "unknown"] += 1
            typed = EventRecord.from_dict(event)
            if typed:
                events.append(typed.to_dict())
            else:
                errors.append("dropped_invalid_event_schema")
            continue

        parsed_fail[parser_header or "unknown"] += 1
        if parser_header:
            fallback = parse_generic_line(line, parser_header)
            typed = EventRecord.from_dict(fallback)
            if typed:
                events.append(typed.to_dict())

    parse_stats = {
        "parsed_ok": dict(parsed_ok),
        "parsed_fail": dict(parsed_fail),
    }
    return events, parse_stats, errors


def _augment_cases(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for idx, case in enumerate(cases, 1):
        clone = dict(case)
        clone["case_id"] = f"case-{idx:04d}"
        clone["analysis_context"] = build_case_analysis_context(clone)
        clone["ioc_summary"] = extract_case_iocs(clone)
        clone["exposure_analysis"] = build_exposure_analysis(clone)
        clone["control_effectiveness"] = build_control_effectiveness(clone)
        typed = CaseRecord.from_dict(clone)
        if typed:
            enriched.append(typed.to_dict())
    return enriched


def _validate_campaigns(campaigns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    valid: List[Dict[str, Any]] = []
    for campaign in campaigns:
        typed = CampaignRecord.from_dict(campaign)
        if typed:
            valid.append(typed.to_dict())
    return valid


def _run_llm_summary(
    cases: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]],
    config: PipelineConfig,
    out_dir: str,
) -> Optional[str]:
    if not config.llm.enabled or not cases:
        return None

    if config.llm.provider == "ollama":
        summary = analyze_cases_with_ollama(
            cases,
            campaigns=campaigns,
            model=config.llm.model,
            timeout=config.llm.timeout_seconds,
        )
    else:
        summary = analyze_cases_with_openai(cases, campaigns=campaigns, model=config.llm.model)

    return write_llm_summary(summary, out_dir=out_dir)


def run_pipeline(filepath: str, config: Optional[PipelineConfig] = None) -> PipelineRunResult:
    cfg = config or PipelineConfig.from_env()
    started = time.perf_counter()
    run_id = _now_run_id()
    log_path = Path(filepath)
    errors: List[str] = []

    if not log_path.exists():
        result = PipelineRunResult(
            run_id=run_id,
            status="file_not_found",
            filepath=str(log_path),
            input_sha256="",
            counts={"events": 0, "cases": 0, "campaigns": 0, "alerts": 0},
            parse_stats={"parsed_ok": {}, "parsed_fail": {}},
            artifacts={},
            timings_ms={"total": int((time.perf_counter() - started) * 1000)},
            errors=["file_not_found"],
        )
        metadata_path = write_json_run_metadata(result.to_dict(), run_id=run_id, out_dir=cfg.out_dir)
        result.artifacts["metadata"] = str(metadata_path)
        return result

    t_parse_start = time.perf_counter()
    events, parse_stats, parse_errors = _parse_events(log_path)
    timings_ms: Dict[str, int] = {
        "parse": int((time.perf_counter() - t_parse_start) * 1000),
    }
    errors.extend(parse_errors)

    input_hash = _sha256(log_path)

    t_detect_start = time.perf_counter()
    cases = run_detections(
        events,
        scan_unique_paths_threshold=cfg.detection.scan_unique_paths_threshold,
        scan_404_ratio_threshold=cfg.detection.scan_404_ratio_threshold,
        brute_force_threshold=cfg.detection.brute_force_threshold,
        dos_rpm_threshold=cfg.detection.dos_rpm_threshold,
        window_minutes=cfg.detection.window_minutes,
    )
    timings_ms["detect"] = int((time.perf_counter() - t_detect_start) * 1000)

    t_enrich_start = time.perf_counter()
    cases = enrich_cases_with_threat_intel(cases)
    cases = _augment_cases(cases)
    timings_ms["enrich_and_augment"] = int((time.perf_counter() - t_enrich_start) * 1000)

    t_campaign_start = time.perf_counter()
    campaigns = build_attack_campaigns(cases, correlation_window_minutes=cfg.detection.correlation_window_minutes)
    campaigns = _validate_campaigns(campaigns)
    timings_ms["campaign_correlation"] = int((time.perf_counter() - t_campaign_start) * 1000)

    t_alert_start = time.perf_counter()
    alerts = build_alerts(cases, run_id=run_id)
    timings_ms["alert_pipeline"] = int((time.perf_counter() - t_alert_start) * 1000)

    t_report_start = time.perf_counter()
    report_path = write_markdown_report(cases, campaigns=campaigns, out_dir=cfg.out_dir)
    cases_path = write_json_cases(cases, out_dir=cfg.out_dir)
    campaigns_path = write_json_campaigns(campaigns, out_dir=cfg.out_dir)
    alerts_path = write_json_alerts(alerts, out_dir=cfg.out_dir)
    timings_ms["reporting"] = int((time.perf_counter() - t_report_start) * 1000)

    llm_path = None
    try:
        t_llm_start = time.perf_counter()
        llm_path = _run_llm_summary(cases, campaigns, config=cfg, out_dir=cfg.out_dir)
        timings_ms["llm"] = int((time.perf_counter() - t_llm_start) * 1000)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"llm_analysis_failed:{exc}")

    timings_ms["total"] = int((time.perf_counter() - started) * 1000)

    artifacts = {
        "incident_report": str(report_path),
        "cases": str(cases_path),
        "campaigns": str(campaigns_path),
        "alerts": str(alerts_path),
    }
    if llm_path:
        artifacts["llm_summary"] = str(llm_path)

    result = PipelineRunResult(
        run_id=run_id,
        status="completed",
        filepath=str(log_path),
        input_sha256=input_hash,
        counts={
            "events": len(events),
            "cases": len(cases),
            "campaigns": len(campaigns),
            "alerts": len(alerts),
        },
        parse_stats=parse_stats,
        artifacts=artifacts,
        timings_ms=timings_ms,
        errors=errors,
    )

    metadata_payload = result.to_dict()
    metadata_payload["generated_utc"] = datetime.now(timezone.utc).isoformat()
    metadata_path = write_json_run_metadata(metadata_payload, run_id=run_id, out_dir=cfg.out_dir)
    result.artifacts["metadata"] = str(metadata_path)

    return result


def load_run_metadata(run_id: str, out_dir: str = "reports") -> Optional[Dict[str, Any]]:
    path = Path(out_dir) / f"run_metadata_{run_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _load_json_artifact(path: str) -> List[Dict[str, Any]]:
    artifact = Path(path)
    if not artifact.exists():
        return []
    raw = json.loads(artifact.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    return []


def load_cases_for_run(run_id: str, out_dir: str = "reports") -> List[Dict[str, Any]]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if not metadata:
        return []
    cases_path = (metadata.get("artifacts") or {}).get("cases")
    if not isinstance(cases_path, str):
        return []
    return _load_json_artifact(cases_path)


def load_campaigns_for_run(run_id: str, out_dir: str = "reports") -> List[Dict[str, Any]]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if not metadata:
        return []
    campaigns_path = (metadata.get("artifacts") or {}).get("campaigns")
    if not isinstance(campaigns_path, str):
        return []
    return _load_json_artifact(campaigns_path)


def load_alerts_for_run(run_id: str, out_dir: str = "reports") -> List[Dict[str, Any]]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if not metadata:
        return []
    alerts_path = (metadata.get("artifacts") or {}).get("alerts")
    if not isinstance(alerts_path, str):
        return []
    return _load_json_artifact(alerts_path)
