from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from alert_pipeline.alerts import build_alerts
from config.settings import PipelineConfig
from correlation.campaigns import build_attack_campaigns
from detections.engine import run_detections
from ingest.compat import source_context_from_section
from ingest.intake_models import IntakeRequest
from ingest.log_reader import iter_log_lines
from ingest.router import build_router
from llm.analysis_context import (
    build_case_analysis_context,
    build_control_effectiveness,
    build_exposure_analysis,
    extract_case_iocs,
)
from llm.incident_analyzer import analyze_cases_with_ollama, analyze_cases_with_openai
from models.schemas import CampaignRecord, CaseRecord, PipelineRunResult
from normalize.mappers import normalize_to_canonical
from reports.llm_report_writer import write_llm_summary
from reports.report_writer import (
    write_json_alerts,
    write_json_campaigns,
    write_json_cases,
    write_json_run_metadata,
    write_markdown_report,
)
from threat_intel.enrich import enrich_cases_with_threat_intel
from utils.timezone import APP_TIMEZONE_NAME, iso_to_local, local_tag_precise, now_local_iso


ParserFn = Callable[[str], Optional[Dict[str, Any]]]


def _now_run_id() -> str:
    return local_tag_precise()


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _app_version() -> str:
    version_file = Path(__file__).resolve().parents[1] / "VERSION"
    try:
        return version_file.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


def _metadata_path_for_run(run_id: str, out_dir: str) -> Path:
    return Path(out_dir) / f"run_metadata_{run_id}.json"


def _parse_events(log_path: Path, tenant_id: str) -> tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], List[str]]:
    events: List[Dict[str, Any]] = []
    parsed_ok: Counter[str] = Counter()
    parsed_fail: Counter[str] = Counter()
    errors: List[str] = []

    router = build_router()
    current_parser_hint: Optional[str] = None
    current_source: Dict[str, Any] = {
        "vendor": "unknown",
        "product": "unknown",
        "service": "unknown",
        "type": "unknown",
        "format": "raw",
    }

    for line in iter_log_lines(log_path):
        if not line or line.startswith("----"):
            continue

        context = source_context_from_section(line)
        if context.get("parser_hint") is not None:
            current_parser_hint = context.get("parser_hint")
            current_source = dict(context.get("source") or current_source)
            continue

        routed = router.route(line, parser_hint=current_parser_hint, context={"source": current_source})
        canonical = normalize_to_canonical(
            tenant_id=tenant_id,
            source=current_source,
            raw_message=line,
            raw_timestamp=None,
            raw_attributes={},
            parse_result=routed.result,
        )
        events.append(canonical.to_dict())
        if routed.result.success:
            parsed_ok[routed.result.parser_name] += 1
        else:
            parsed_fail[routed.result.parser_name] += 1
            if routed.result.error:
                errors.append(routed.result.error)

    parse_stats = {"parsed_ok": dict(parsed_ok), "parsed_fail": dict(parsed_fail)}
    return events, parse_stats, errors


def _canonical_events_from_intake(
    intake_request: IntakeRequest, tenant_id: str
) -> tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], List[str]]:
    router = build_router()
    events: List[Dict[str, Any]] = []
    parsed_ok: Counter[str] = Counter()
    parsed_fail: Counter[str] = Counter()
    errors: List[str] = []
    source = intake_request.source.model_dump(exclude_none=True)

    for intake_event in intake_request.iter_events():
        routed = router.route(
            intake_event.message,
            parser_hint=intake_request.parser_hint,
            context={"source": source},
        )
        canonical = normalize_to_canonical(
            tenant_id=tenant_id,
            source=source,
            raw_message=intake_event.message,
            raw_timestamp=intake_event.timestamp,
            raw_attributes=intake_event.attributes,
            parse_result=routed.result,
        )
        events.append(canonical.to_dict())
        if routed.result.success:
            parsed_ok[routed.result.parser_name] += 1
        else:
            parsed_fail[routed.result.parser_name] += 1
            if routed.result.error:
                errors.append(routed.result.error)

    parse_stats = {"parsed_ok": dict(parsed_ok), "parsed_fail": dict(parsed_fail)}
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


def _localize_case_timestamps(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    localized: List[Dict[str, Any]] = []
    for case in cases:
        clone = dict(case)
        start = clone.get("timestamp_start")
        end = clone.get("timestamp_end")
        if isinstance(start, str):
            clone["timestamp_start"] = iso_to_local(start)
        if isinstance(end, str):
            clone["timestamp_end"] = iso_to_local(end)
        localized.append(clone)
    return localized


def _localize_campaign_timestamps(campaigns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    localized: List[Dict[str, Any]] = []
    for campaign in campaigns:
        clone = dict(campaign)
        first_seen = clone.get("first_seen")
        last_seen = clone.get("last_seen")
        if isinstance(first_seen, str):
            clone["first_seen"] = iso_to_local(first_seen)
        if isinstance(last_seen, str):
            clone["last_seen"] = iso_to_local(last_seen)

        timeline = clone.get("timeline")
        if isinstance(timeline, list):
            updated_timeline: List[Dict[str, Any]] = []
            for item in timeline:
                if not isinstance(item, dict):
                    continue
                timeline_item = dict(item)
                ts_start = timeline_item.get("timestamp_start")
                ts_end = timeline_item.get("timestamp_end")
                if isinstance(ts_start, str):
                    timeline_item["timestamp_start"] = iso_to_local(ts_start)
                if isinstance(ts_end, str):
                    timeline_item["timestamp_end"] = iso_to_local(ts_end)
                updated_timeline.append(timeline_item)
            clone["timeline"] = updated_timeline
        localized.append(clone)
    return localized


def _localize_alert_timestamps(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    localized: List[Dict[str, Any]] = []
    for alert in alerts:
        clone = dict(alert)
        start = clone.get("timestamp_start")
        end = clone.get("timestamp_end")
        if isinstance(start, str):
            clone["timestamp_start"] = iso_to_local(start)
        if isinstance(end, str):
            clone["timestamp_end"] = iso_to_local(end)
        localized.append(clone)
    return localized


def run_pipeline(
    filepath: str,
    config: Optional[PipelineConfig] = None,
    run_id: Optional[str] = None,
    tenant_id: str = "default",
) -> PipelineRunResult:
    cfg = config or PipelineConfig.from_env()
    started = time.perf_counter()
    resolved_run_id = run_id or _now_run_id()
    log_path = Path(filepath)
    errors: List[str] = []

    if not log_path.exists():
        metadata_path = _metadata_path_for_run(resolved_run_id, cfg.out_dir)
        result = PipelineRunResult(
            run_id=resolved_run_id,
            tenant_id=tenant_id,
            status="file_not_found",
            filepath=str(log_path),
            input_sha256="",
            counts={"events": 0, "cases": 0, "campaigns": 0, "alerts": 0},
            parse_stats={"parsed_ok": {}, "parsed_fail": {}},
            artifacts={"metadata": str(metadata_path)},
            timings_ms={"total": int((time.perf_counter() - started) * 1000)},
            errors=["file_not_found"],
        )
        missing_payload = result.to_dict()
        missing_payload["service"] = "AI-SOC-Agent"
        missing_payload["version"] = _app_version()
        missing_payload["generated_at"] = now_local_iso()
        missing_payload["timezone"] = APP_TIMEZONE_NAME
        write_json_run_metadata(missing_payload, run_id=resolved_run_id, out_dir=cfg.out_dir)
        return result

    t_parse_start = time.perf_counter()
    events, parse_stats, parse_errors = _parse_events(log_path, tenant_id=tenant_id)
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
    alerts = build_alerts(cases, run_id=resolved_run_id)
    timings_ms["alert_pipeline"] = int((time.perf_counter() - t_alert_start) * 1000)

    cases = _localize_case_timestamps(cases)
    campaigns = _localize_campaign_timestamps(campaigns)
    alerts = _localize_alert_timestamps(alerts)

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
    metadata_path = _metadata_path_for_run(resolved_run_id, cfg.out_dir)
    artifacts["metadata"] = str(metadata_path)

    result = PipelineRunResult(
        run_id=resolved_run_id,
        tenant_id=tenant_id,
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
    metadata_payload["service"] = "AI-SOC-Agent"
    metadata_payload["version"] = _app_version()
    metadata_payload["generated_at"] = now_local_iso()
    metadata_payload["timezone"] = APP_TIMEZONE_NAME
    write_json_run_metadata(metadata_payload, run_id=resolved_run_id, out_dir=cfg.out_dir)

    return result


def run_pipeline_from_intake(
    intake_request: IntakeRequest,
    config: Optional[PipelineConfig] = None,
    run_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> PipelineRunResult:
    cfg = config or PipelineConfig.from_env()
    started = time.perf_counter()
    resolved_run_id = run_id or _now_run_id()
    resolved_tenant_id = tenant_id or intake_request.tenant_id

    events, parse_stats, parse_errors = _canonical_events_from_intake(
        intake_request=intake_request,
        tenant_id=resolved_tenant_id,
    )
    timings_ms: Dict[str, int] = {"parse": int((time.perf_counter() - started) * 1000)}
    errors: List[str] = list(parse_errors)

    raw_fingerprint = "\n".join(event.message for event in intake_request.iter_events())
    input_hash = hashlib.sha256(raw_fingerprint.encode("utf-8")).hexdigest()

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
    alerts = build_alerts(cases, run_id=resolved_run_id)
    timings_ms["alert_pipeline"] = int((time.perf_counter() - t_alert_start) * 1000)

    cases = _localize_case_timestamps(cases)
    campaigns = _localize_campaign_timestamps(campaigns)
    alerts = _localize_alert_timestamps(alerts)

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
    metadata_path = _metadata_path_for_run(resolved_run_id, cfg.out_dir)
    artifacts["metadata"] = str(metadata_path)

    result = PipelineRunResult(
        run_id=resolved_run_id,
        tenant_id=resolved_tenant_id,
        status="completed",
        filepath="intake_payload",
        input_sha256=input_hash,
        counts={"events": len(events), "cases": len(cases), "campaigns": len(campaigns), "alerts": len(alerts)},
        parse_stats=parse_stats,
        artifacts=artifacts,
        timings_ms=timings_ms,
        errors=errors,
    )

    metadata_payload = result.to_dict()
    metadata_payload["service"] = "AI-SOC-Agent"
    metadata_payload["version"] = _app_version()
    metadata_payload["generated_at"] = now_local_iso()
    metadata_payload["timezone"] = APP_TIMEZONE_NAME
    write_json_run_metadata(metadata_payload, run_id=resolved_run_id, out_dir=cfg.out_dir)
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


def load_artifact_path_for_run(run_id: str, artifact_name: str, out_dir: str = "reports") -> Optional[str]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if not metadata:
        return None
    artifacts = metadata.get("artifacts") or {}
    if not isinstance(artifacts, dict):
        return None
    artifact = artifacts.get(artifact_name)
    if not isinstance(artifact, str):
        return None
    return artifact
