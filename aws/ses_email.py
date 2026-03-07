from __future__ import annotations

from typing import Dict, List


def build_email_bodies(
    total_events: int,
    total_cases: int,
    summary_text: str,
    report_links: Dict[str, str],
) -> tuple[str, str]:
    text_lines = [
        "AI SOC Scheduled Report",
        "",
        f"Events processed: {total_events}",
        f"Cases detected: {total_cases}",
        "",
        "LLM Summary:",
        summary_text[:4000],
        "",
        "Report locations:",
    ]
    for name, uri in report_links.items():
        text_lines.append(f"- {name}: {uri}")

    html_items = "".join([f"<li><b>{k}</b>: {v}</li>" for k, v in report_links.items()])
    html_body = (
        "<html><body>"
        "<h2>AI SOC Scheduled Report</h2>"
        f"<p><b>Events processed:</b> {total_events}<br>"
        f"<b>Cases detected:</b> {total_cases}</p>"
        "<h3>LLM Summary</h3>"
        f"<pre>{summary_text[:4000]}</pre>"
        "<h3>Report locations</h3>"
        f"<ul>{html_items}</ul>"
        "</body></html>"
    )

    return "\n".join(text_lines), html_body


def send_email_with_ses(
    ses_client,
    sender: str,
    recipients: List[str],
    subject: str,
    text_body: str,
    html_body: str,
) -> dict:
    return ses_client.send_email(
        Source=sender,
        Destination={"ToAddresses": recipients},
        Message={
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": text_body, "Charset": "UTF-8"},
                "Html": {"Data": html_body, "Charset": "UTF-8"},
            },
        },
    )
