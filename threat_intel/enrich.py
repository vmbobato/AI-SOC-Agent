from __future__ import annotations

import ipaddress
import os
from typing import Any, Dict, Iterable, Optional
from dotenv import load_dotenv
load_dotenv()
import requests


IPINFO_URL = "https://api.ipinfo.io/lite/{ip}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT_SECONDS = 5


def _parse_asn_and_org(org_value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not org_value:
        return None, None
    parts = org_value.split(maxsplit=1)
    if len(parts) == 2 and parts[0].upper().startswith("AS") and parts[0][2:].isdigit():
        return parts[0].upper(), parts[1]
    return None, org_value


def _extract_ipinfo_asn_and_org(payload: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """
    Normalize ASN/org across IPinfo response variants.

    Common variants:
    - {"org": "AS15169 Google LLC"}
    - {"asn": "AS15169", "org": "Google LLC"}
    - {"asn": {"asn": "AS15169", "name": "Google LLC"}}
    """
    asn_value: Optional[str] = None
    org_value: Optional[str] = None

    asn_field = payload.get("asn")
    if isinstance(asn_field, str) and asn_field.strip():
        asn_value = asn_field.strip().upper()
    elif isinstance(asn_field, dict):
        nested_asn = asn_field.get("asn") or asn_field.get("id")
        if isinstance(nested_asn, str) and nested_asn.strip():
            asn_value = nested_asn.strip().upper()
        nested_org = asn_field.get("name") or asn_field.get("org")
        if isinstance(nested_org, str) and nested_org.strip():
            org_value = nested_org.strip()

    org_field = payload.get("org")
    parsed_asn, parsed_org = _parse_asn_and_org(org_field if isinstance(org_field, str) else None)
    if not asn_value:
        asn_value = parsed_asn
    if not org_value:
        if isinstance(org_field, str) and org_field.strip():
            org_value = parsed_org or org_field.strip()

    return asn_value, org_value


def _extract_ipinfo_country(payload: Dict[str, Any]) -> Optional[str]:
    country_code = payload.get("country_code")
    if isinstance(country_code, str) and country_code.strip():
        return country_code.strip()
    country = payload.get("country")
    if isinstance(country, str) and country.strip():
        return country.strip()
    country_alt = payload.get("countryCode")
    if isinstance(country_alt, str) and country_alt.strip():
        return country_alt.strip()
    return None


def _is_hosting_provider_hint(value: Optional[str]) -> Optional[bool]:
    if not value:
        return None
    lowered = value.lower()
    keywords = ("cloud", "hosting", "datacenter", "data center", "vps", "colo")
    return any(keyword in lowered for keyword in keywords)


def classify_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "skipped_invalid_ip"

    if parsed.is_loopback:
        return "skipped_loopback_ip"
    if parsed.is_link_local:
        return "skipped_link_local_ip"
    if parsed.is_private:
        return "skipped_private_ip"
    if parsed.is_reserved:
        return "skipped_reserved_ip"
    if parsed.is_multicast:
        return "skipped_multicast_ip"
    if parsed.is_unspecified:
        return "skipped_unspecified_ip"
    return "enrichable_public_ip"


def lookup_ipinfo(ip: str, token: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    if not token:
        return {}
    try:
        response = requests.get(
            IPINFO_URL.format(ip=ip),
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout_seconds
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return {}

    asn, org_name = _extract_ipinfo_asn_and_org(payload)
    if not org_name:
        as_name = payload.get("as_name")
        if isinstance(as_name, str) and as_name.strip():
            org_name = as_name.strip()
    if not org_name:
        as_domain = payload.get("as_domain")
        if isinstance(as_domain, str) and as_domain.strip():
            org_name = as_domain.strip()

    country = _extract_ipinfo_country(payload)
    hosting_flag = _is_hosting_provider_hint(org_name)
    return {
        "country": country,
        "city": payload.get("city"),
        "asn": asn,
        "org": org_name,
        "is_hosting_provider": hosting_flag,
        "source": "ipinfo",
    }


def lookup_abuseipdb(ip: str, api_key: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    if not api_key:
        return {}
    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json().get("data", {})
    except (requests.RequestException, ValueError):
        return {}

    usage = payload.get("usageType")
    return {
        "country": payload.get("countryCode"),
        "org": payload.get("isp"),
        "abuse_confidence_score": payload.get("abuseConfidenceScore"),
        "abuse_reports": payload.get("totalReports"),
        "is_hosting_provider": _is_hosting_provider_hint(usage),
        "source": "abuseipdb",
    }


def _base_intel_record(status: str) -> Dict[str, Any]:
    return {
        "intel_status": status,
        "country": None,
        "city": None,
        "asn": None,
        "org": None,
        "is_hosting_provider": None,
        "abuse_confidence_score": None,
        "abuse_reports": None,
        "source": [],
    }


def _merge_provider_data(ipinfo_data: Dict[str, Any], abuse_data: Dict[str, Any], status: str) -> Dict[str, Any]:
    record = _base_intel_record(status=status)
    sources: list[str] = []

    if ipinfo_data:
        sources.append("ipinfo")
        record["country"] = ipinfo_data.get("country")
        record["city"] = ipinfo_data.get("city")
        record["asn"] = ipinfo_data.get("asn")
        record["org"] = ipinfo_data.get("org")
        record["is_hosting_provider"] = ipinfo_data.get("is_hosting_provider")

    if abuse_data:
        sources.append("abuseipdb")
        record["country"] = record["country"] or abuse_data.get("country")
        record["org"] = record["org"] or abuse_data.get("org")
        record["abuse_confidence_score"] = abuse_data.get("abuse_confidence_score")
        record["abuse_reports"] = abuse_data.get("abuse_reports")
        abuse_hosting = abuse_data.get("is_hosting_provider")
        if record["is_hosting_provider"] is None:
            record["is_hosting_provider"] = abuse_hosting
        elif abuse_hosting is True:
            record["is_hosting_provider"] = True

    record["source"] = sources
    return record


def _extract_source_ips(cases: Iterable[Dict[str, Any]]) -> list[str]:
    unique: set[str] = set()
    for case in cases:
        for ip in case.get("source_ips") or []:
            if isinstance(ip, str) and ip.strip():
                unique.add(ip.strip())
    return sorted(unique)


def _enrich_ip(ip: str, ipinfo_token: str, abuse_key: str) -> Dict[str, Any]:
    status = classify_ip(ip)
    if status != "enrichable_public_ip":
        return _base_intel_record(status=status)

    if not ipinfo_token and not abuse_key:
        return _base_intel_record(status="skipped_no_api_keys")

    ipinfo_data = lookup_ipinfo(ip=ip, token=ipinfo_token) if ipinfo_token else {}
    abuse_data = lookup_abuseipdb(ip=ip, api_key=abuse_key) if abuse_key else {}
    merged = _merge_provider_data(
        ipinfo_data=ipinfo_data,
        abuse_data=abuse_data,
        status="enriched" if (ipinfo_data or abuse_data) else "lookup_failed",
    )
    return merged


def enrich_cases_with_threat_intel(cases: list[dict]) -> list[dict]:
    ipinfo_token = os.getenv("AUTH_BEARER_IP_INFO", "").strip()
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    unique_ips = _extract_source_ips(cases)
    intel_by_ip = {ip: _enrich_ip(ip, ipinfo_token=ipinfo_token, abuse_key=abuse_key) for ip in unique_ips}

    enriched_cases: list[dict] = []
    for case in cases:
        cloned_case = dict(case)
        case_ips = [ip for ip in (case.get("source_ips") or []) if isinstance(ip, str)]
        cloned_case["threat_intel"] = {ip: intel_by_ip[ip] for ip in case_ips if ip in intel_by_ip}
        enriched_cases.append(cloned_case)
    return enriched_cases


def _compact_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    kept_keys = {
        "requests",
        "unique_paths",
        "404_ratio",
        "login_attempts",
        "fail_ratio",
        "hits",
        "distinct_targets",
        "status_counts",
        "reasons",
    }
    compact: Dict[str, Any] = {}
    for key, value in evidence.items():
        if key in kept_keys:
            compact[key] = value
        elif key == "top_paths" and isinstance(value, dict):
            compact[key] = dict(list(value.items())[:5])
    return compact


def compact_cases_for_llm(cases: list[dict]) -> list[dict]:
    compact_cases: list[dict] = []
    for case in cases:
        threat_intel = case.get("threat_intel") or {}
        compact_ti: Dict[str, Dict[str, Any]] = {}
        for ip, intel in threat_intel.items():
            if not isinstance(intel, dict):
                continue
            compact_ti[ip] = {
                "intel_status": intel.get("intel_status"),
                "country": intel.get("country"),
                "city": intel.get("city"),
                "asn": intel.get("asn"),
                "org": intel.get("org"),
                "is_hosting_provider": intel.get("is_hosting_provider"),
                "abuse_confidence_score": intel.get("abuse_confidence_score"),
                "abuse_reports": intel.get("abuse_reports"),
                "source": intel.get("source") or [],
            }

        compact_cases.append(
            {
                "incident_type": case.get("incident_type"),
                "timestamp_start": case.get("timestamp_start"),
                "timestamp_end": case.get("timestamp_end"),
                "source_ips": case.get("source_ips") or [],
                "severity": case.get("severity"),
                "confidence": case.get("confidence"),
                "evidence": _compact_evidence(case.get("evidence") or {}),
                "analysis_context": case.get("analysis_context") or {},
                "threat_intel": compact_ti,
            }
        )
    return compact_cases
