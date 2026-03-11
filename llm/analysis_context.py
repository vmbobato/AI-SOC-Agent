from __future__ import annotations

from typing import Any, Dict, List


SENSITIVE_KEYWORDS = ("phpinfo", "config", ".git", "env", "sql", "yaml", "yml", "backup", "old")


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _compute_scan_volume(total_requests: int) -> str:
    if total_requests < 100:
        return "low"
    if total_requests <= 999:
        return "medium"
    if total_requests <= 9999:
        return "high"
    return "very_high"


def _confidence_reason(confidence: Any) -> str:
    if not isinstance(confidence, (int, float)):
        return "confidence_not_provided"
    value = float(confidence)
    if value >= 0.9:
        return "high_confidence_from_strong_detection_signal"
    if value >= 0.7:
        return "moderate_confidence_from_consistent_pattern"
    return "lower_confidence_requires_additional_validation"


def _likely_scan_behavior(case: Dict[str, Any], evidence: Dict[str, Any], sensitive_targets_detected: bool) -> str:
    incident_type = str(case.get("incident_type", "")).lower()
    if "blocked app-layer probe" in incident_type:
        return "blocked_app_probe"
    if "sensitive file / exploit probe" in incident_type or sensitive_targets_detected:
        return "sensitive_file_probe"
    if "web enumeration scan" in incident_type:
        if _to_int(evidence.get("unique_paths"), 0) >= 100:
            return "broad_path_enumeration"
        return "single_vector_scan"
    if "brute force" in incident_type:
        return "credential_attack_pattern"
    return "mixed_reconnaissance"


def build_case_analysis_context(case: dict) -> dict:
    """
    Build deterministic SOC-ready context from case evidence.

    The output is designed for LLM grounding and analyst readability, so all
    fields are explicit and defaults are safe when keys are missing.
    """
    evidence = case.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    total_requests = _to_int(evidence.get("requests"), 0)
    if total_requests == 0:
        total_requests = _to_int(evidence.get("hits"), 0)

    unique_paths = _to_int(evidence.get("unique_paths"), 0)

    status_counts = evidence.get("status_counts") or {}
    if not isinstance(status_counts, dict):
        status_counts = {}

    successful_responses = _to_int(status_counts.get("200"), 0)
    if successful_responses == 0:
        successful_responses = _to_int(status_counts.get(200), 0)
    failed_responses = 0
    for status_code, count in status_counts.items():
        if str(status_code) != "200":
            failed_responses += _to_int(count, 0)

    successful_ratio = 0.0
    if total_requests > 0:
        successful_ratio = successful_responses / total_requests

    top_paths = evidence.get("top_paths") or {}
    sensitive_targets_detected = False
    if isinstance(top_paths, dict):
        for path in top_paths.keys():
            lowered = str(path).lower()
            if any(keyword in lowered for keyword in SENSITIVE_KEYWORDS):
                sensitive_targets_detected = True
                break

    blocked_requests = bool(evidence.get("reasons"))

    successful_paths = evidence.get("successful_paths")
    successful_paths_known = isinstance(successful_paths, list)
    if not successful_paths_known:
        successful_paths = []

    likely_behavior = _likely_scan_behavior(case, evidence, sensitive_targets_detected)
    exposure_review_required = successful_responses > 0 and likely_behavior in {
        "broad_path_enumeration",
        "single_vector_scan",
        "sensitive_file_probe",
        "mixed_reconnaissance",
    }

    return {
        "total_requests": total_requests,
        "unique_paths": unique_paths,
        "successful_responses": successful_responses,
        "failed_responses": failed_responses,
        "successful_ratio": successful_ratio,
        "blocked_requests": blocked_requests,
        "sensitive_targets_detected": sensitive_targets_detected,
        "scan_volume": _compute_scan_volume(total_requests),
        "confidence_reason": _confidence_reason(case.get("confidence")),
        "exposure_review_required": exposure_review_required,
        "likely_scan_behavior": likely_behavior,
        "successful_paths_known": successful_paths_known,
        "successful_paths": successful_paths,
    }


def build_analysis_context(case: dict) -> dict:
    """Backward-compatible wrapper around build_case_analysis_context."""
    return build_case_analysis_context(case)


def extract_case_iocs(case: dict) -> dict:
    evidence = case.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}

    threat_intel = case.get("threat_intel") or {}
    if not isinstance(threat_intel, dict):
        threat_intel = {}

    suspicious_paths: List[str] = []
    top_paths = evidence.get("top_paths") or {}
    if isinstance(top_paths, dict):
        suspicious_paths = [str(path) for path in list(top_paths.keys())[:20]]

    top_user_agents: List[str] = []
    uas = evidence.get("top_user_agents") or {}
    if isinstance(uas, dict):
        top_user_agents = [str(ua) for ua in list(uas.keys())[:10]]

    asns = sorted({str(v.get("asn")) for v in threat_intel.values() if isinstance(v, dict) and v.get("asn")})
    orgs = sorted({str(v.get("org")) for v in threat_intel.values() if isinstance(v, dict) and v.get("org")})
    hosting_flags = sorted({
        bool(v.get("is_hosting_provider"))
        for v in threat_intel.values()
        if isinstance(v, dict) and v.get("is_hosting_provider") is not None
    })

    return {
        "source_ips": [str(ip) for ip in (case.get("source_ips") or [])],
        "suspicious_paths": suspicious_paths,
        "top_user_agents": top_user_agents,
        "asns": asns,
        "orgs": orgs,
        "hosting_provider_flags": hosting_flags,
    }


def build_exposure_analysis(case: dict) -> dict:
    context = case.get("analysis_context") or build_case_analysis_context(case)
    successful_count = _to_int(context.get("successful_responses"), 0)
    successful_detected = successful_count > 0
    successful_paths_known = bool(context.get("successful_paths_known"))
    successful_paths = context.get("successful_paths") if successful_paths_known else []

    if successful_detected:
        exposure_risk = "high" if successful_count >= 5 else "medium"
        exposure_reason = "successful_http_responses_detected_during_scan_or_probe"
    else:
        exposure_risk = "low"
        exposure_reason = "no_successful_http_responses_detected_in_scan_or_probe"

    return {
        "successful_responses_detected": successful_detected,
        "successful_response_count": successful_count,
        "successful_paths_known": successful_paths_known,
        "successful_paths": successful_paths,
        "exposure_risk": exposure_risk,
        "exposure_reason": exposure_reason,
    }


def build_control_effectiveness(case: dict) -> dict:
    evidence = case.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    context = case.get("analysis_context") or build_case_analysis_context(case)
    exposure = case.get("exposure_analysis") or build_exposure_analysis(case)

    blocked_by_app_layer = bool(evidence.get("reasons"))
    blocked_secret_path_probe = False
    reasons = evidence.get("reasons") or {}
    if isinstance(reasons, dict):
        blocked_secret_path_probe = "secret_path" in reasons

    ratio_404 = evidence.get("404_ratio")
    high_404_ratio = isinstance(ratio_404, (int, float)) and float(ratio_404) >= 0.85
    no_successes = not exposure.get("successful_responses_detected", False)

    defenses_effective = bool((high_404_ratio or blocked_by_app_layer) and no_successes)
    defenses_partially_effective = bool(exposure.get("successful_responses_detected", False) and (high_404_ratio or blocked_by_app_layer))

    notes: List[str] = []
    if high_404_ratio:
        notes.append("high_404_ratio_observed")
    if blocked_by_app_layer:
        notes.append("app_layer_blocks_observed")
    if exposure.get("successful_responses_detected", False):
        notes.append("successful_http_responses_detected_during_scan")

    return {
        "blocked_by_app_layer": blocked_by_app_layer,
        "high_404_ratio": high_404_ratio,
        "blocked_secret_path_probe": blocked_secret_path_probe,
        "defenses_effective": defenses_effective,
        "defenses_partially_effective": defenses_partially_effective,
        "notes": notes,
    }


def prepare_cases_for_llm(cases: List[dict]) -> List[dict]:
    compact: List[dict] = []
    for case in cases:
        compact.append(
            {
                "case_id": case.get("case_id"),
                "incident_type": case.get("incident_type"),
                "timestamp_start": case.get("timestamp_start"),
                "timestamp_end": case.get("timestamp_end"),
                "source_ips": case.get("source_ips") or [],
                "severity": case.get("severity"),
                "confidence": case.get("confidence"),
                "analysis_context": case.get("analysis_context") or {},
                "exposure_analysis": case.get("exposure_analysis") or {},
                "ioc_summary": case.get("ioc_summary") or {},
                "control_effectiveness": case.get("control_effectiveness") or {},
                "threat_intel": case.get("threat_intel") or {},
                "selected_evidence": {
                    "requests": (case.get("evidence") or {}).get("requests"),
                    "hits": (case.get("evidence") or {}).get("hits"),
                    "unique_paths": (case.get("evidence") or {}).get("unique_paths"),
                    "status_counts": (case.get("evidence") or {}).get("status_counts"),
                    "successful_paths": (case.get("evidence") or {}).get("successful_paths") or [],
                    "top_paths": dict(list(((case.get("evidence") or {}).get("top_paths") or {}).items())[:10]),
                    "top_user_agents": dict(list(((case.get("evidence") or {}).get("top_user_agents") or {}).items())[:10]),
                },
            }
        )
    return compact
