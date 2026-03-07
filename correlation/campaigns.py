from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from llm.analysis_context import (
    build_control_effectiveness,
    build_exposure_analysis,
    extract_case_iocs,
)


INCIDENT_BASE_WEIGHTS: Dict[str, float] = {
    "Sensitive File / Exploit Probe": 3.0,
    "Blocked App-Layer Probe": 2.4,
    "Brute Force Attempt": 2.8,
    "Web Enumeration Scan": 2.0,
    "Traffic Burst / Possible DoS": 1.8,
}

SEVERITY_MULTIPLIER: Dict[str, float] = {
    "low": 0.9,
    "medium": 1.1,
    "high": 1.3,
}


def _parse_ts(value: Optional[str]) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    ts = value
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _primary_ip(case: Dict[str, Any]) -> Optional[str]:
    ips = case.get("source_ips") or []
    if not ips:
        return None
    value = ips[0]
    return value if isinstance(value, str) and value else None


def _case_confidence_factor(case: Dict[str, Any]) -> float:
    conf = case.get("confidence")
    if isinstance(conf, (int, float)):
        bounded = max(0.0, min(1.0, float(conf)))
        return 0.85 + (bounded * 0.45)
    return 1.0


def _case_volume_bonus(case: Dict[str, Any]) -> float:
    evidence = case.get("evidence") or {}
    if not isinstance(evidence, dict):
        return 0.0

    bonus = 0.0
    requests = evidence.get("requests")
    hits = evidence.get("hits")
    distinct_targets = evidence.get("distinct_targets")
    unique_paths = evidence.get("unique_paths")
    status_counts = evidence.get("status_counts")

    if isinstance(requests, (int, float)):
        bonus += min(1.5, float(requests) / 2500.0)
    if isinstance(hits, (int, float)):
        bonus += min(1.2, float(hits) / 200.0)
    if isinstance(distinct_targets, (int, float)):
        bonus += min(1.2, float(distinct_targets) / 40.0)
    if isinstance(unique_paths, (int, float)):
        bonus += min(1.0, float(unique_paths) / 250.0)
    if isinstance(status_counts, dict):
        suspicious_success = int(status_counts.get(200, 0)) + int(status_counts.get(302, 0))
        if suspicious_success > 0:
            bonus += min(1.0, suspicious_success / 30.0)
    return bonus


def build_timeline_item(case: Dict[str, Any]) -> Dict[str, str]:
    incident_type = case.get("incident_type", "Unknown")
    evidence = case.get("evidence") or {}
    summary = "No significant evidence summary."

    if incident_type == "Sensitive File / Exploit Probe":
        hits = evidence.get("hits")
        distinct = evidence.get("distinct_targets")
        summary = f"{hits or 0} hits across {distinct or 0} distinct sensitive targets"
    elif incident_type == "Web Enumeration Scan":
        req = evidence.get("requests")
        unique = evidence.get("unique_paths")
        summary = f"{req or 0} requests across {unique or 0} unique paths"
    elif incident_type == "Brute Force Attempt":
        attempts = evidence.get("login_attempts")
        fail_ratio = evidence.get("fail_ratio")
        summary = f"{attempts or 0} login attempts with fail ratio {fail_ratio}"
    elif incident_type == "Blocked App-Layer Probe":
        hits = evidence.get("hits")
        reasons = evidence.get("reasons") or {}
        summary = f"{hits or 0} blocked app-layer probes; reasons={reasons}"
    elif incident_type == "Traffic Burst / Possible DoS":
        req = evidence.get("requests")
        summary = f"{req or 0} requests in a short window"

    return {
        "timestamp_start": str(case.get("timestamp_start", "")),
        "timestamp_end": str(case.get("timestamp_end", "")),
        "incident_type": str(incident_type),
        "summary": summary,
    }


def _summary_flags(incident_types: List[str]) -> Dict[str, bool]:
    lowered = {value.lower() for value in incident_types}
    return {
        "contains_exploitation_probe": any("sensitive file / exploit probe" in value for value in lowered),
        "contains_scan": any("web enumeration scan" in value for value in lowered),
        "contains_bruteforce": any("brute force attempt" in value for value in lowered),
        "contains_app_probe": any("blocked app-layer probe" in value for value in lowered),
    }


def score_campaign(campaign: Dict[str, Any]) -> float:
    total = 0.0
    cases = campaign.get("cases") or []

    for case in cases:
        incident_type = case.get("incident_type", "")
        base_weight = INCIDENT_BASE_WEIGHTS.get(str(incident_type), 1.5)
        severity_value = str(case.get("severity", "Medium")).lower()
        severity_mult = SEVERITY_MULTIPLIER.get(severity_value, 1.0)
        confidence_factor = _case_confidence_factor(case)
        volume_bonus = _case_volume_bonus(case)
        total += (base_weight * severity_mult * confidence_factor) + volume_bonus

    incident_types = campaign.get("incident_types") or []
    distinct_types = len(set(incident_types))
    if distinct_types >= 2:
        total += 1.2
    if distinct_types >= 3:
        total += 0.8
    return round(total, 2)


def _risk_level(score: float) -> str:
    if score >= 8.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _campaign_note(campaign: Dict[str, Any]) -> str:
    source_ip = campaign.get("source_ip", "unknown")
    incident_types = campaign.get("incident_types") or []
    risk_level = campaign.get("risk_level", "Unknown")
    risk_score = campaign.get("risk_score", 0)
    type_text = ", ".join(incident_types) if incident_types else "no typed incidents"
    return (
        f"Source IP {source_ip} showed coordinated activity across {len(incident_types)} incident type(s): "
        f"{type_text}. Overall campaign risk is {risk_level} ({risk_score})."
    )


def _cases_are_related(prev_case: Dict[str, Any], new_case: Dict[str, Any], correlation_window_minutes: int) -> bool:
    prev_end = _parse_ts(prev_case.get("timestamp_end"))
    new_start = _parse_ts(new_case.get("timestamp_start"))
    delta_minutes = (new_start - prev_end).total_seconds() / 60.0
    return delta_minutes <= correlation_window_minutes


def extract_campaign_iocs(campaign: dict) -> dict:
    source_ips: set[str] = set()
    suspicious_paths: set[str] = set()
    top_user_agents: set[str] = set()
    asns: set[str] = set()
    orgs: set[str] = set()
    hosting_provider_flags: set[bool] = set()

    for case in campaign.get("cases") or []:
        case_iocs = case.get("ioc_summary") or extract_case_iocs(case)
        for ip in case_iocs.get("source_ips") or []:
            source_ips.add(str(ip))
        for path in case_iocs.get("suspicious_paths") or []:
            suspicious_paths.add(str(path))
        for ua in case_iocs.get("top_user_agents") or []:
            top_user_agents.add(str(ua))
        for asn in case_iocs.get("asns") or []:
            asns.add(str(asn))
        for org in case_iocs.get("orgs") or []:
            orgs.add(str(org))
        for flag in case_iocs.get("hosting_provider_flags") or []:
            hosting_provider_flags.add(bool(flag))

    return {
        "source_ips": sorted(source_ips),
        "suspicious_paths": sorted(suspicious_paths),
        "top_user_agents": sorted(top_user_agents),
        "asns": sorted(asns),
        "orgs": sorted(orgs),
        "hosting_provider_flags": sorted(hosting_provider_flags),
    }


def build_campaign_exposure_analysis(campaign: dict) -> dict:
    successful_count = 0
    successful_paths: set[str] = set()
    successful_paths_known = True

    for case in campaign.get("cases") or []:
        case_exposure = case.get("exposure_analysis") or build_exposure_analysis(case)
        successful_count += int(case_exposure.get("successful_response_count") or 0)
        if case_exposure.get("successful_paths_known"):
            for path in case_exposure.get("successful_paths") or []:
                successful_paths.add(str(path))
        else:
            successful_paths_known = False

    successful_detected = successful_count > 0
    if successful_detected:
        exposure_risk = "high" if successful_count >= 10 else "medium"
        exposure_reason = "successful_http_responses_detected_during_campaign"
    else:
        exposure_risk = "low"
        exposure_reason = "no_successful_http_responses_detected_during_campaign"

    return {
        "successful_responses_detected": successful_detected,
        "successful_response_count": successful_count,
        "successful_paths_known": successful_paths_known,
        "successful_paths": sorted(successful_paths) if successful_paths_known else [],
        "exposure_risk": exposure_risk,
        "exposure_reason": exposure_reason,
    }


def build_campaign_control_effectiveness(campaign: dict) -> dict:
    blocked_by_app_layer = False
    high_404_ratio = False
    blocked_secret_path_probe = False
    successful_during_campaign = False

    for case in campaign.get("cases") or []:
        control = case.get("control_effectiveness") or build_control_effectiveness(case)
        blocked_by_app_layer = blocked_by_app_layer or bool(control.get("blocked_by_app_layer"))
        high_404_ratio = high_404_ratio or bool(control.get("high_404_ratio"))
        blocked_secret_path_probe = blocked_secret_path_probe or bool(control.get("blocked_secret_path_probe"))

        exposure = case.get("exposure_analysis") or build_exposure_analysis(case)
        successful_during_campaign = successful_during_campaign or bool(exposure.get("successful_responses_detected"))

    defenses_effective = bool((blocked_by_app_layer or high_404_ratio) and not successful_during_campaign)
    defenses_partially_effective = bool(successful_during_campaign and (blocked_by_app_layer or high_404_ratio))

    notes: List[str] = []
    if blocked_by_app_layer:
        notes.append("app_layer_blocks_observed")
    if high_404_ratio:
        notes.append("high_404_ratio_observed")
    if blocked_secret_path_probe:
        notes.append("blocked_secret_path_probe_observed")
    if successful_during_campaign:
        notes.append("successful_http_responses_detected_during_scan")

    return {
        "blocked_by_app_layer": blocked_by_app_layer,
        "high_404_ratio": high_404_ratio,
        "blocked_secret_path_probe": blocked_secret_path_probe,
        "defenses_effective": defenses_effective,
        "defenses_partially_effective": defenses_partially_effective,
        "notes": notes,
    }


def _threat_reputation_level(campaign: dict) -> str:
    max_score = 0
    max_reports = 0
    found = False
    for case in campaign.get("cases") or []:
        threat_intel = case.get("threat_intel") or {}
        if not isinstance(threat_intel, dict):
            continue
        for intel in threat_intel.values():
            if not isinstance(intel, dict):
                continue
            score = intel.get("abuse_confidence_score")
            reports = intel.get("abuse_reports")
            if isinstance(score, (int, float)):
                max_score = max(max_score, int(score))
                found = True
            if isinstance(reports, (int, float)):
                max_reports = max(max_reports, int(reports))
                found = True
    if not found:
        return "unknown"
    if max_score >= 70 or max_reports >= 50:
        return "high"
    if max_score >= 30 or max_reports >= 10:
        return "medium"
    return "low"


def _campaign_type(campaign: dict) -> str:
    flags = campaign.get("summary") or {}
    if flags.get("contains_scan") and flags.get("contains_exploitation_probe"):
        return "mixed_reconnaissance_campaign"
    if flags.get("contains_app_probe") and not flags.get("contains_scan"):
        return "blocked_probe_campaign"
    return "reconnaissance_campaign"


def _attack_pattern(campaign: dict) -> str:
    incident_types = campaign.get("incident_types") or []
    lowered = {value.lower() for value in incident_types}
    if "sensitive file / exploit probe" in lowered and "web enumeration scan" in lowered:
        return "probe_then_enumerate"
    if "blocked app-layer probe" in lowered:
        return "blocked_secret_path_probe"
    return "single_vector_scan"


def _risk_factors(campaign: dict) -> List[str]:
    factors: List[str] = []
    for case in campaign.get("cases") or []:
        context = case.get("analysis_context") or {}
        if context.get("scan_volume") in {"high", "very_high"} and "high_scan_volume" not in factors:
            factors.append("high_scan_volume")
        if context.get("sensitive_targets_detected") and "sensitive_target_probing" not in factors:
            factors.append("sensitive_target_probing")
        exposure = case.get("exposure_analysis") or {}
        if exposure.get("successful_responses_detected") and "successful_http_responses_detected" not in factors:
            factors.append("successful_http_responses_detected")
    if campaign.get("incident_count", 0) >= 2 and "multi_stage_activity" not in factors:
        factors.append("multi_stage_activity")
    return factors


def _shared_infrastructure_context(campaign: dict, all_campaigns: List[dict]) -> dict:
    current_iocs = campaign.get("ioc_summary") or extract_campaign_iocs(campaign)
    current_asns = set(current_iocs.get("asns") or [])
    current_orgs = set(current_iocs.get("orgs") or [])
    shared_asn: Optional[str] = None
    shared_org: Optional[str] = None

    for other in all_campaigns:
        if other is campaign:
            continue
        other_iocs = other.get("ioc_summary") or extract_campaign_iocs(other)
        overlap_asn = current_asns.intersection(set(other_iocs.get("asns") or []))
        overlap_org = current_orgs.intersection(set(other_iocs.get("orgs") or []))
        if overlap_asn and not shared_asn:
            shared_asn = sorted(overlap_asn)[0]
        if overlap_org and not shared_org:
            shared_org = sorted(overlap_org)[0]

    shared_provider = bool(shared_asn or shared_org)
    return {
        "shared_provider_across_campaigns": shared_provider,
        "shared_asn_across_campaigns": shared_asn is not None,
        "shared_asn": shared_asn,
        "shared_org": shared_org,
        "note": (
            "Campaigns are temporally separate but originate from the same hosting provider infrastructure."
            if shared_provider
            else "No shared ASN or organization observed across campaigns."
        ),
    }


def build_analyst_playbook(campaign: dict) -> List[str]:
    actions: List[str] = []
    exposure = campaign.get("exposure_analysis") or {}
    context = campaign.get("analysis_context") or {}
    control = campaign.get("control_effectiveness") or {}

    if exposure.get("successful_responses_detected"):
        actions.append("Review successful HTTP 200 responses for potential exposed endpoints.")
        actions.append("Verify sensitive paths associated with successful responses.")
    if context.get("campaign_type") in {"reconnaissance_campaign", "mixed_reconnaissance_campaign"}:
        actions.append("Apply IP-based blocking or strict rate limits for repeated reconnaissance sources.")
    if control.get("blocked_secret_path_probe"):
        actions.append("Tune and extend app-layer secret-path blocking rules.")
    if context.get("threat_reputation_level") in {"high", "medium"}:
        actions.append("Prioritize monitoring for repeat traffic from same ASN/organization.")
    actions.append("Monitor for recurrence of the same suspicious paths and user agents.")

    deduped: List[str] = []
    for item in actions:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _severity_explanation(campaign: dict) -> dict:
    factors = _risk_factors(campaign)
    top_factors = factors[:3]
    return {
        "risk_level": campaign.get("risk_level"),
        "risk_score": campaign.get("risk_score"),
        "top_risk_factors": top_factors,
        "reasoning": (
            f"Risk set to {campaign.get('risk_level')} based on score {campaign.get('risk_score')} "
            f"and factors: {', '.join(top_factors) if top_factors else 'none'}."
        ),
    }


def build_campaign_analysis_context(campaign: dict, all_campaigns: List[dict]) -> dict:
    campaign_iocs = campaign.get("ioc_summary") or extract_campaign_iocs(campaign)
    shared_context = campaign.get("shared_infrastructure_context") or _shared_infrastructure_context(campaign, all_campaigns)
    exposure = campaign.get("exposure_analysis") or build_campaign_exposure_analysis(campaign)
    control = campaign.get("control_effectiveness") or build_campaign_control_effectiveness(campaign)
    factors = _risk_factors(campaign)

    control_effectiveness = "ineffective"
    if control.get("defenses_effective"):
        control_effectiveness = "effective"
    elif control.get("defenses_partially_effective"):
        control_effectiveness = "partially_effective"

    control_gaps: List[str] = []
    if exposure.get("successful_responses_detected"):
        control_gaps.append("successful_http_responses_detected_during_scan")

    llm_ioc_summary = {
        "source_ips": campaign_iocs.get("source_ips") or [],
        "suspicious_paths": campaign_iocs.get("suspicious_paths") or [],
        "top_user_agents": campaign_iocs.get("top_user_agents") or [],
        "infra_indicators": {
            "asns": campaign_iocs.get("asns") or [],
            "orgs": campaign_iocs.get("orgs") or [],
            "hosting_provider_flags": campaign_iocs.get("hosting_provider_flags") or [],
        },
    }

    return {
        "campaign_type": _campaign_type(campaign),
        "attack_pattern": _attack_pattern(campaign),
        "risk_factors": factors,
        "exposure_review_required": bool(exposure.get("successful_responses_detected")),
        "shared_infrastructure_across_campaigns": bool(shared_context.get("shared_provider_across_campaigns")),
        "shared_asn": shared_context.get("shared_asn"),
        "shared_org": shared_context.get("shared_org"),
        "threat_reputation_level": _threat_reputation_level(campaign),
        "control_effectiveness": control_effectiveness,
        "control_gaps": control_gaps,
        "llm_ioc_summary": llm_ioc_summary,
    }


def build_attack_campaigns(cases: List[Dict[str, Any]], correlation_window_minutes: int = 60) -> List[Dict[str, Any]]:
    if not cases:
        return []

    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for case in cases:
        ip = _primary_ip(case)
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(case)

    campaigns: List[Dict[str, Any]] = []
    campaign_index = 1

    for source_ip in sorted(by_ip.keys()):
        sorted_cases = sorted(by_ip[source_ip], key=lambda item: _parse_ts(item.get("timestamp_start")))
        current_group: List[Dict[str, Any]] = []

        for case in sorted_cases:
            if not current_group:
                current_group.append(case)
                continue
            if _cases_are_related(current_group[-1], case, correlation_window_minutes):
                current_group.append(case)
            else:
                campaigns.append(_build_campaign_object(campaign_index, source_ip, current_group))
                campaign_index += 1
                current_group = [case]

        if current_group:
            campaigns.append(_build_campaign_object(campaign_index, source_ip, current_group))
            campaign_index += 1

    campaigns.sort(key=lambda item: item.get("first_seen", ""))

    for campaign in campaigns:
        campaign["ioc_summary"] = extract_campaign_iocs(campaign)
        campaign["exposure_analysis"] = build_campaign_exposure_analysis(campaign)
        campaign["control_effectiveness"] = build_campaign_control_effectiveness(campaign)
        campaign["shared_infrastructure_context"] = _shared_infrastructure_context(campaign, campaigns)
        campaign["analysis_context"] = build_campaign_analysis_context(campaign, campaigns)
        campaign["severity_explanation"] = _severity_explanation(campaign)
        campaign["analyst_playbook"] = build_analyst_playbook(campaign)

    return campaigns


def _build_campaign_object(campaign_index: int, source_ip: str, grouped_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered_cases = sorted(grouped_cases, key=lambda item: _parse_ts(item.get("timestamp_start")))
    first_seen_dt = _parse_ts(ordered_cases[0].get("timestamp_start"))
    last_seen_dt = _parse_ts(ordered_cases[-1].get("timestamp_end"))
    duration_minutes = max(0, int((last_seen_dt - first_seen_dt).total_seconds() / 60.0))

    incident_types = []
    for case in ordered_cases:
        incident_type = case.get("incident_type")
        if isinstance(incident_type, str) and incident_type not in incident_types:
            incident_types.append(incident_type)

    timeline = [build_timeline_item(case) for case in ordered_cases]
    campaign = {
        "campaign_id": f"campaign-{campaign_index:03d}",
        "source_ip": source_ip,
        "first_seen": first_seen_dt.isoformat(),
        "last_seen": last_seen_dt.isoformat(),
        "duration_minutes": duration_minutes,
        "incident_count": len(ordered_cases),
        "incident_types": incident_types,
        "cases": ordered_cases,
        "summary": _summary_flags(incident_types),
        "timeline": timeline,
    }
    risk_score = score_campaign(campaign)
    campaign["risk_score"] = risk_score
    campaign["risk_level"] = _risk_level(risk_score)
    campaign["analyst_note"] = _campaign_note(campaign)
    return campaign


def prepare_campaigns_for_llm(campaigns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compact: List[Dict[str, Any]] = []
    for campaign in campaigns:
        compact.append(
            {
                "campaign_id": campaign.get("campaign_id"),
                "source_ip": campaign.get("source_ip"),
                "first_seen": campaign.get("first_seen"),
                "last_seen": campaign.get("last_seen"),
                "duration_minutes": campaign.get("duration_minutes"),
                "incident_count": campaign.get("incident_count"),
                "incident_types": campaign.get("incident_types") or [],
                "risk_score": campaign.get("risk_score"),
                "risk_level": campaign.get("risk_level"),
                "timeline": campaign.get("timeline") or [],
                "analysis_context": campaign.get("analysis_context") or {},
                "exposure_analysis": campaign.get("exposure_analysis") or {},
                "ioc_summary": campaign.get("ioc_summary") or {},
                "shared_infrastructure_context": campaign.get("shared_infrastructure_context") or {},
                "control_effectiveness": campaign.get("control_effectiveness") or {},
                "severity_explanation": campaign.get("severity_explanation") or {},
                "analyst_playbook": campaign.get("analyst_playbook") or [],
            }
        )
    return compact
