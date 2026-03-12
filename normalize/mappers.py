from __future__ import annotations

from typing import Any, Dict, Optional

from normalize.canonical import CanonicalEvent
from parsers.base import ParseResult
from utils.timezone import iso_to_local

SENSITIVE_PATH_KEYWORDS = (
    "/.env",
    "/.git/config",
    "phpinfo",
    "wp-config",
    "config.",
    ".sql",
    ".yml",
    ".yaml",
)

PROBE_KEYWORDS = (
    "scan",
    "probe",
    "sql",
    "env",
    "php",
    "admin",
    "login",
)


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _path_depth(path: Optional[str]) -> int:
    if not isinstance(path, str) or not path:
        return 0
    return len([segment for segment in path.split("/") if segment])


def _is_sensitive(path: Optional[str]) -> bool:
    if not isinstance(path, str):
        return False
    lowered = path.lower()
    return any(keyword in lowered for keyword in SENSITIVE_PATH_KEYWORDS)


def _is_probe_like(path: Optional[str], message: Optional[str]) -> bool:
    combined = f"{path or ''} {message or ''}".lower()
    return any(keyword in combined for keyword in PROBE_KEYWORDS)


def normalize_to_canonical(
    *,
    tenant_id: str,
    source: Dict[str, Any],
    raw_message: str,
    raw_timestamp: Optional[str],
    raw_attributes: Dict[str, Any],
    parse_result: ParseResult,
) -> CanonicalEvent:
    fields = dict(parse_result.fields or {})
    attributes = dict(raw_attributes or {})

    parsed_attributes = fields.get("attributes")
    if isinstance(parsed_attributes, dict):
        attributes.update(parsed_attributes)

    ts_raw = fields.get("ts") or raw_timestamp
    ts = iso_to_local(ts_raw) if isinstance(ts_raw, str) else None

    status_code = _as_int(fields.get("status_code"))
    url_path = fields.get("url_path") if isinstance(fields.get("url_path"), str) else None
    message = fields.get("message") if isinstance(fields.get("message"), str) else raw_message

    event = CanonicalEvent(
        ts=ts,
        tenant_id=tenant_id,
        event_family=parse_result.event_family,
        event_kind=fields.get("event_kind") if isinstance(fields.get("event_kind"), str) else None,
        vendor=source.get("vendor"),
        product=source.get("product"),
        service=source.get("service"),
        environment=source.get("environment"),
        host=source.get("host"),
        source_type=source.get("type"),
        parser_name=parse_result.parser_name,
        parser_confidence=float(parse_result.confidence or 0.0),
        src_ip=fields.get("src_ip") if isinstance(fields.get("src_ip"), str) else None,
        src_port=_as_int(fields.get("src_port")),
        dest_ip=fields.get("dest_ip") if isinstance(fields.get("dest_ip"), str) else None,
        dest_port=_as_int(fields.get("dest_port")),
        http_method=fields.get("http_method") if isinstance(fields.get("http_method"), str) else None,
        url_path=url_path,
        url_query=fields.get("url_query") if isinstance(fields.get("url_query"), str) else None,
        http_version=fields.get("http_version") if isinstance(fields.get("http_version"), str) else None,
        host_header=fields.get("host_header") if isinstance(fields.get("host_header"), str) else None,
        user_agent=fields.get("user_agent") if isinstance(fields.get("user_agent"), str) else None,
        referer=fields.get("referer") if isinstance(fields.get("referer"), str) else None,
        status_code=status_code,
        bytes_sent=_as_int(fields.get("bytes_sent")),
        request_time_ms=float(fields["request_time_ms"]) if isinstance(fields.get("request_time_ms"), (int, float)) else None,
        action=fields.get("action") if isinstance(fields.get("action"), str) else None,
        outcome=fields.get("outcome") if isinstance(fields.get("outcome"), str) else None,
        severity=fields.get("severity") if isinstance(fields.get("severity"), str) else None,
        category=fields.get("category") if isinstance(fields.get("category"), str) else None,
        rule_id=fields.get("rule_id") if isinstance(fields.get("rule_id"), str) else None,
        rule_name=fields.get("rule_name") if isinstance(fields.get("rule_name"), str) else None,
        message=message,
        raw_message=raw_message,
        attributes=attributes,
        parse_error=parse_result.error,
        is_4xx=bool(status_code is not None and 400 <= status_code <= 499),
        is_5xx=bool(status_code is not None and status_code >= 500),
        is_sensitive_path=_is_sensitive(url_path),
        is_probe_like=_is_probe_like(url_path, message),
        path_depth=_path_depth(url_path),
    )
    return event
