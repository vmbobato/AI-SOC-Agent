from pathlib import Path
from datetime import datetime, timezone
import json

def _now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_utc")

def write_markdown_report(cases, out_dir="reports") -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tag = _now_tag()
    out_path = out_dir / f"incident_report_{tag}.md"

    lines = []
    lines.append("# AI SOC Incident Report (MVP)")
    lines.append("")
    lines.append(f"- Generated (UTC): {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Cases detected: {len(cases)}")
    lines.append("")

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