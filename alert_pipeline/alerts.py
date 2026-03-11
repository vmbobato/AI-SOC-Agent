from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from models.schemas import AlertRecord


SEVERITY_RANK: Dict[str, int] = {"High": 3, "Medium": 2, "Low": 1}

CASE_CATEGORY_MAP: Dict[str, str] = {
    "Sensitive File / Exploit Probe": "exploitation_probe",
    "Blocked App-Layer Probe": "app_layer_probe",
    "Brute Force Attempt": "credential_attack",
    "Web Enumeration Scan": "reconnaissance",
    "Traffic Burst / Possible DoS": "service_abuse",
}


def _stable_alert_id(run_id: str, incident_type: str, source_ip: str, ts_start: str, ts_end: str) -> str:
    raw = f"{run_id}|{incident_type}|{source_ip}|{ts_start}|{ts_end}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"alert-{digest}"


def _severity_value(value: Any) -> str:
    if not isinstance(value, str):
        return "Medium"
    normalized = value.capitalize()
    if normalized in SEVERITY_RANK:
        return normalized
    return "Medium"


def build_alerts(cases: List[Dict[str, Any]], run_id: str) -> List[Dict[str, Any]]:
    dedupe: Dict[str, AlertRecord] = {}

    for case in cases:
        incident_type = str(case.get("incident_type") or "Unknown Incident")
        source_ips = [ip for ip in (case.get("source_ips") or []) if isinstance(ip, str) and ip]
        source_ip = source_ips[0] if source_ips else "unknown"
        timestamp_start = str(case.get("timestamp_start") or "")
        timestamp_end = str(case.get("timestamp_end") or "")
        severity = _severity_value(case.get("severity"))
        confidence = float(case.get("confidence") or 0.0)
        case_id = str(case.get("case_id") or "")

        dedupe_key = f"{incident_type}|{source_ip}|{timestamp_start}|{timestamp_end}"
        if dedupe_key in dedupe:
            if case_id and case_id not in dedupe[dedupe_key].linked_case_ids:
                dedupe[dedupe_key].linked_case_ids.append(case_id)
            continue

        category = CASE_CATEGORY_MAP.get(incident_type, "suspicious_activity")
        evidence_obj = case.get("evidence")
        evidence: Dict[str, Any]
        if isinstance(evidence_obj, dict):
            evidence = dict(evidence_obj)
        else:
            evidence = {}
        alert = AlertRecord(
            alert_id=_stable_alert_id(run_id, incident_type, source_ip, timestamp_start, timestamp_end),
            run_id=run_id,
            title=incident_type,
            severity=severity,
            confidence=round(max(0.0, min(1.0, confidence)), 2),
            source_ips=source_ips,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
            category=category,
            recommended_actions=[
                action for action in (case.get("recommended_actions") or []) if isinstance(action, str)
            ],
            evidence=evidence,
            linked_case_ids=[case_id] if case_id else [],
        )
        dedupe[dedupe_key] = alert

    alerts = [record.to_dict() for record in dedupe.values()]
    alerts.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity")), 0),
            str(item.get("timestamp_start") or ""),
            str(item.get("title") or ""),
        )
    )
    return alerts
