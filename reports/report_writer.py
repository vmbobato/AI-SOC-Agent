from pathlib import Path
import json
from typing import Any, Dict, List
from utils.timezone import now_local_iso, local_tag

_VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"
try:
    _APP_VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() or "unknown"
except OSError:
    _APP_VERSION = "unknown"
_APP_SERVICE = "AI-SOC-Agent"
	
def _now_tag() -> str:
    return local_tag()


def _render_mapping(lines: List[str], mapping: Dict[str, Any], prefix: str = "- ") -> None:
    if not mapping:
        lines.append(f"{prefix}(none)")
        return
    for key, value in mapping.items():
        lines.append(f"{prefix}**{key}**: {value}")
	
def _append_campaign_section(lines: List[str], campaigns: List[Dict[str, Any]]) -> None:
    lines.append("# Attack Campaigns")
    lines.append("")
    if not campaigns:
        lines.append("No correlated campaigns identified.")
        lines.append("")
        return

    for idx, campaign in enumerate(campaigns, 1):
        lines.append(f"## Campaign {idx}: {campaign.get('campaign_id', 'unknown')}")
        lines.append(f"- Source IP: {campaign.get('source_ip', 'N/A')}")
        lines.append(f"- First seen: {campaign.get('first_seen', 'N/A')}")
        lines.append(f"- Last seen: {campaign.get('last_seen', 'N/A')}")
        lines.append(f"- Duration (minutes): {campaign.get('duration_minutes', 'N/A')}")
        lines.append(f"- Incident count: {campaign.get('incident_count', 0)}")
        incident_types = campaign.get("incident_types") or []
        lines.append(f"- Incident types: {', '.join(incident_types) if incident_types else 'N/A'}")
        lines.append(f"- Risk score: {campaign.get('risk_score', 'N/A')}")
        lines.append(f"- Risk level: {campaign.get('risk_level', 'N/A')}")
        lines.append("")

        lines.append("### Analysis Context")
        _render_mapping(lines, campaign.get("analysis_context") or {})
        lines.append("")

        lines.append("### Exposure Analysis")
        _render_mapping(lines, campaign.get("exposure_analysis") or {})
        lines.append("")

        lines.append("### IOC Extraction")
        _render_mapping(lines, campaign.get("ioc_summary") or {})
        lines.append("")

        lines.append("### Infrastructure Analysis")
        _render_mapping(lines, campaign.get("shared_infrastructure_context") or {})
        lines.append("")

        lines.append("### Defensive Control Effectiveness")
        _render_mapping(lines, campaign.get("control_effectiveness") or {})
        lines.append("")

        lines.append("### Campaign Severity Explanation")
        _render_mapping(lines, campaign.get("severity_explanation") or {})
        lines.append("")

        lines.append("### Analyst Playbook")
        playbook = campaign.get("analyst_playbook") or []
        if not playbook:
            lines.append("- (none)")
        else:
            for action in playbook:
                lines.append(f"- {action}")
        lines.append("")

        lines.append("### Timeline")
        timeline = campaign.get("timeline") or []
        if not timeline:
            lines.append("- (none)")
        else:
            for item in timeline:
                lines.append(
                    f"- {item.get('timestamp_start', 'N/A')} → {item.get('timestamp_end', 'N/A')} | "
                    f"{item.get('incident_type', 'Unknown')} | {item.get('summary', '')}"
                )
        lines.append("")
        lines.append("### Analyst Note")
        lines.append(campaign.get("analyst_note", "No analyst note."))
        lines.append("")


def write_markdown_report(cases, campaigns=None, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tag = _now_tag()
    out_path = out_dir / f"incident_report_{tag}.md"

    lines = []
    lines.append("# AI SOC Incident Report (MVP)")
    lines.append("")
    lines.append(f"- Service: {_APP_SERVICE}")
    lines.append(f"- Version: {_APP_VERSION}")
    lines.append(f"- Generated (America/Chicago): {now_local_iso()}")
    lines.append(f"- Cases detected: {len(cases)}")
    campaign_count = len(campaigns or [])
    lines.append(f"- Campaigns correlated: {campaign_count}")
    lines.append("")

    _append_campaign_section(lines, campaigns or [])

    if not cases:
        lines.append("No incidents detected with current thresholds.")
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path

    for i, c in enumerate(cases, 1):
        lines.append("---")
        lines.append(f"## Case {i}: {c.get('incident_type', 'Unknown')}")
        lines.append("")
        lines.append(f"**Time window:** {c.get('timestamp_start')} → {c.get('timestamp_end')}")
        lines.append("")
        ips = c.get("source_ips") or []
        lines.append(f"**Source IP(s):** {', '.join(ips) if ips else 'N/A'}")
        lines.append("")
        lines.append(f"**Severity:** {c.get('severity', 'Unknown')}")
        lines.append(f"**Confidence:** {c.get('confidence', 'N/A')}")
        lines.append("")

        lines.append("### Evidence")
        ev = c.get("evidence") or {}
        if not ev:
            lines.append("- (none)")
        else:
            for k, v in ev.items():
                if isinstance(v, dict):
                    lines.append(f"- **{k}**:")
                    # show top few so report stays readable
                    for kk, vv in list(v.items())[:12]:
                        lines.append(f"  - {kk}: {vv}")
                else:
                    lines.append(f"- **{k}**: {v}")
        lines.append("")

        lines.append("### Threat Intelligence")
        threat_intel = c.get("threat_intel") or {}
        if not threat_intel:
            lines.append("- (none)")
        else:
            for ip, intel in threat_intel.items():
                if not isinstance(intel, dict):
                    continue
                lines.append(f"- **IP:** {ip}")
                lines.append(f"  - Status: {intel.get('intel_status', 'unknown')}")
                lines.append(f"  - Country: {intel.get('country') or 'N/A'}")
                lines.append(f"  - City: {intel.get('city') or 'N/A'}")
                lines.append(f"  - ASN: {intel.get('asn') or 'N/A'}")
                lines.append(f"  - Org: {intel.get('org') or 'N/A'}")
                lines.append(f"  - Infrastructure: {intel.get('is_hosting_provider')}")
                lines.append(f"  - Abuse Score: {intel.get('abuse_confidence_score')}")
                lines.append(f"  - Abuse Reports: {intel.get('abuse_reports')}")
                source_value: Any = intel.get("source") or []
                source_str = ", ".join(source_value) if isinstance(source_value, list) else str(source_value)
                lines.append(f"  - Intel Sources: {source_str or 'N/A'}")
        lines.append("")

        lines.append("### Analysis Context")
        _render_mapping(lines, c.get("analysis_context") or {})
        lines.append("")

        lines.append("### Exposure Analysis")
        _render_mapping(lines, c.get("exposure_analysis") or {})
        lines.append("")

        lines.append("### IOC Extraction")
        _render_mapping(lines, c.get("ioc_summary") or {})
        lines.append("")

        lines.append("### Defensive Control Effectiveness")
        _render_mapping(lines, c.get("control_effectiveness") or {})
        lines.append("")

        lines.append("### Recommended Actions")
        actions = c.get("recommended_actions") or []
        if not actions:
            lines.append("- (none)")
        else:
            for a in actions:
                lines.append(f"- {a}")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path

def write_json_cases(cases, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tag = _now_tag()
    out_path = out_dir / f"cases_{tag}.json"
    out_path.write_text(json.dumps(cases, indent=2), encoding="utf-8")
    return out_path


def write_json_campaigns(campaigns, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tag = _now_tag()
    out_path = out_dir / f"campaigns_{tag}.json"
    out_path.write_text(json.dumps(campaigns, indent=2), encoding="utf-8")
    return out_path


def write_json_alerts(alerts, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tag = _now_tag()
    out_path = out_dir / f"alerts_{tag}.json"
    out_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    return out_path


def write_json_run_metadata(metadata: dict, run_id: str, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / f"run_metadata_{run_id}.json"
    out_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return out_path
