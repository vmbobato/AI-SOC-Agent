from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import json

import boto3

from aws.cloudwatch_logs import fetch_log_messages
from aws.config import AwsPipelineConfig
from aws.openai_summary import summarize_cases_with_openai
from aws.s3_reports import upload_file_report, upload_text_report
from aws.ses_email import build_email_bodies, send_email_with_ses
from detections.engine import run_detections
from parsers.nginx_parser import parse_nginx_access_line, parse_nginx_error_line
from parsers.web_stdout_parser import parse_web_stdout_line
from reports.llm_report_writer import write_llm_summary
from reports.report_writer import write_json_cases, write_markdown_report


PARSER_BY_SOURCE = {
    "nginx_access": parse_nginx_access_line,
    "nginx_error": parse_nginx_error_line,
    "web_stdout": parse_web_stdout_line,
}


def _parse_generic_line(line: str, source: str) -> Dict[str, Any]:
    return {
        "timestamp": None,
        "source": source,
        "severity": "unknown",
        "message": line.strip(),
        "raw_line": line,
    }


def parse_messages_by_source(raw_messages: Dict[str, List[str]]) -> tuple[List[Dict[str, Any]], Dict[str, int], Dict[str, int]]:
    events: List[Dict[str, Any]] = []
    parsed_ok: Counter[str] = Counter()
    parsed_fail: Counter[str] = Counter()

    for source_name, messages in raw_messages.items():
        parser = PARSER_BY_SOURCE.get(source_name)
        for line in messages:
            event = parser(line) if parser else None
            if event:
                parsed_ok[source_name] += 1
                events.append(event)
            else:
                parsed_fail[source_name] += 1
                events.append(_parse_generic_line(line, source_name))

    return events, dict(parsed_ok), dict(parsed_fail)


def _build_s3_key(prefix: str, run_id: str, filename: str) -> str:
    normalized_prefix = prefix.strip("/")
    return f"{normalized_prefix}/{run_id}/{filename}" if normalized_prefix else f"{run_id}/{filename}"


def run_pipeline(event: Optional[Dict[str, Any]] = None, context: Any = None) -> Dict[str, Any]:
    cfg = AwsPipelineConfig.from_env()
    now = datetime.now(timezone.utc)

    event = event or {}
    window_minutes = int(event.get("window_minutes") or cfg.window_minutes)
    end_time = now
    start_time = end_time - timedelta(minutes=window_minutes)

    logs_client = boto3.client("logs", region_name=cfg.region)
    s3_client = boto3.client("s3", region_name=cfg.region)
    ses_client = boto3.client("ses", region_name=cfg.region)

    raw_messages: Dict[str, List[str]] = {}
    for source in cfg.log_sources:
        raw_messages[source.source_name] = fetch_log_messages(
            logs_client=logs_client,
            log_group_name=source.log_group_name,
            start_time_ms=int(start_time.timestamp() * 1000),
            end_time_ms=int(end_time.timestamp() * 1000),
            filter_pattern=source.filter_pattern,
        )

    events, parsed_ok, parsed_fail = parse_messages_by_source(raw_messages)
    cases = run_detections(
        events,
        scan_unique_paths_threshold=40,
        scan_404_ratio_threshold=0.85,
        brute_force_threshold=20,
        dos_rpm_threshold=120,
        window_minutes=2,
    )

    tmp_dir = Path("/tmp/soc_reports")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    markdown_path = write_markdown_report(cases, out_dir=str(tmp_dir))
    cases_path = write_json_cases(cases, out_dir=str(tmp_dir))

    try:
        llm_summary = summarize_cases_with_openai(
            cases=cases,
            api_key=cfg.openai_api_key,
            model=cfg.openai_model,
        )
    except Exception as exc:
        llm_summary = (
            "## AI SOC Analyst Summary\n\n"
            f"LLM summary unavailable due to error: {exc}\n\n"
            f"Detected cases: {len(cases)}"
        )

    llm_summary_path = Path(write_llm_summary(llm_summary, out_dir=str(tmp_dir)))

    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    md_s3_uri = upload_file_report(
        s3_client,
        cfg.s3_bucket,
        _build_s3_key(cfg.s3_prefix, run_id, markdown_path.name),
        markdown_path,
        "text/markdown",
    )
    json_s3_uri = upload_file_report(
        s3_client,
        cfg.s3_bucket,
        _build_s3_key(cfg.s3_prefix, run_id, cases_path.name),
        cases_path,
        "application/json",
    )
    llm_s3_uri = upload_file_report(
        s3_client,
        cfg.s3_bucket,
        _build_s3_key(cfg.s3_prefix, run_id, llm_summary_path.name),
        llm_summary_path,
        "text/markdown",
    )

    meta = {
        "run_id": run_id,
        "start_time_utc": start_time.isoformat(),
        "end_time_utc": end_time.isoformat(),
        "window_minutes": window_minutes,
        "events_processed": len(events),
        "cases_detected": len(cases),
        "parsed_ok": parsed_ok,
        "parsed_fail": parsed_fail,
        "reports": {
            "incident_markdown": md_s3_uri,
            "cases_json": json_s3_uri,
            "llm_summary": llm_s3_uri,
        },
    }

    meta_s3_uri = upload_text_report(
        s3_client,
        cfg.s3_bucket,
        _build_s3_key(cfg.s3_prefix, run_id, "run_metadata.json"),
        json.dumps(meta, indent=2),
        "application/json",
    )

    report_links = {
        "Incident report": md_s3_uri,
        "Cases JSON": json_s3_uri,
        "LLM summary": llm_s3_uri,
        "Run metadata": meta_s3_uri,
    }
    text_body, html_body = build_email_bodies(
        total_events=len(events),
        total_cases=len(cases),
        summary_text=llm_summary,
        report_links=report_links,
    )

    subject = f"[AI SOC] Scheduled Report {run_id} ({len(cases)} cases)"
    ses_result = send_email_with_ses(
        ses_client,
        sender=cfg.ses_sender,
        recipients=cfg.ses_recipients,
        subject=subject,
        text_body=text_body,
        html_body=html_body,
    )

    meta["ses_message_id"] = ses_result.get("MessageId")
    return meta
