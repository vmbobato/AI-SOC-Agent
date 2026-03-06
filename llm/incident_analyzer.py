import json
import requests
from typing import List, Dict, Any


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"


def build_soc_prompt(cases) -> str:
    cases_json = json.dumps(cases, indent=2)

    return f"""
You are a professional SOC (Security Operations Center) analyst.

Your task is to analyze structured security incident cases and produce a concise,
accurate analyst report.

The cases were generated automatically from server logs by a detection engine.

IMPORTANT RULES:

- Only use the evidence provided in the cases.
- Do NOT invent vulnerabilities, files, or behaviors that are not in the evidence.
- If something is uncertain, clearly state that it is uncertain.
- Be concise and professional.
- Treat repeated probing of sensitive files or application paths as reconnaissance
  or exploitation attempts.
- Do not speculate about attacker intent beyond what the evidence suggests.

Attack priority guidance:

1. Exploitation attempts
2. Application-layer probes or blocked exploit attempts
3. Large-scale scanning or reconnaissance
4. Brute force attempts
5. Traffic anomalies or bursts

When referencing evidence:
- Only reference paths, IPs, user agents, and counts present in the case data.
- Do not assume additional files (ex: .env, phpunit, etc) unless explicitly present.

Output format must be Markdown.

--------------------------------------------------

# AI SOC Analyst Summary

## Executive Summary
Provide a short high-level summary of the overall activity detected across all cases.

Focus on:
- attacker behavior
- number of incidents
- whether the activity appears to be scanning, probing, exploitation attempts,
  brute force attempts, or service abuse.

Keep this section brief (3–5 sentences).

--------------------------------------------------

## Incident Breakdown

For each case include:

### Incident: <incident_type>

**Impact**
Explain why this behavior matters from a security perspective.

**Evidence Observed**
Summarize the key evidence such as:
- request counts
- targeted paths
- error ratios
- suspicious patterns

Use only the data provided.

**Assessment**
Classify the behavior as one of the following:

- Reconnaissance / scanning
- Exploitation attempt
- Brute force attack
- Service abuse / DoS
- Suspicious but inconclusive

Explain briefly why.

**Confidence Reasoning**
Explain why the detection is high, medium, or low confidence.

--------------------------------------------------

## Priority Assessment

Identify:

- The highest priority incident
- Why it should be prioritized
- Whether there is any evidence suggesting successful exposure or compromise.

If there is no evidence of compromise, explicitly state that.

--------------------------------------------------

## Recommended Next Actions

Provide practical next steps for a security engineer or SOC analyst.

Examples:

- Block offending IP addresses
- Enable WAF rate limiting
- Review server logs for successful responses
- Monitor for repeated activity
- Harden exposed endpoints

Recommendations should be realistic and operational.

--------------------------------------------------

## MITRE ATT&CK Mapping

Map each incident to relevant ATT&CK techniques where appropriate.

Common mappings for web attacks include:

Reconnaissance
- T1595 – Active Scanning

Initial Access
- T1190 – Exploit Public-Facing Application

Discovery
- T1046 – Network Service Discovery

Only map techniques that are supported by the evidence.

Do NOT invent techniques.

--------------------------------------------------

Here are the structured incident cases:

{cases_json}
""".strip()


def analyze_cases_with_ollama(
    cases: List[Dict[str, Any]],
    model: str = OLLAMA_MODEL,
    url: str = OLLAMA_URL,
    timeout: int = 500,
) -> str:
    if not cases:
        return "## AI SOC Analyst Summary\n\nNo incidents to analyze."

    prompt = build_soc_prompt(cases)

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()

    data = resp.json()
    return data.get("response", "").strip()