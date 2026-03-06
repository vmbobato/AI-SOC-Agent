import json
import requests
from typing import List, Dict, Any


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"


def build_soc_prompt(cases) -> str:
    cases_json = json.dumps(cases, indent=2)

    return f"""
You are a cybersecurity SOC analyst assistant.

Your task is to analyze structured incident cases detected from server logs and produce a professional SOC analysis.

Use ONLY the information provided in the cases. Do not invent facts or assume compromise.

Write the output in markdown using the exact sections below.

# AI SOC Analyst Summary

## Executive Summary
Briefly describe the overall security activity observed. Focus on patterns such as reconnaissance, scanning, exploitation attempts, or abnormal traffic behavior.

## Incident Breakdown
For EACH incident case:

### Incident: <incident_type>

Include:
- What happened
- Why this behavior is suspicious
- What the evidence suggests
- Whether the behavior looks like:
  - reconnaissance / scanning
  - exploitation attempt
  - brute force
  - service abuse
  - or benign noise

Reference the provided evidence fields such as:
- request volume
- status codes
- unique paths
- sensitive file targets
- application block reasons

## Priority Assessment
Explain which incident should be investigated first.

Consider:
- exploitation indicators
- sensitive file probing
- application layer blocking
- request volume
- unusual HTTP response codes

Explicitly state whether the evidence suggests:

- reconnaissance only
- attempted exploitation
- possible successful exposure
- inconclusive outcome

If compromise is uncertain, clearly say **"no evidence of compromise in the provided data."**

## Recommended Next Actions
Provide practical SOC actions such as:

- blocking IPs
- enabling rate limiting
- checking server logs
- verifying exposed files
- reviewing application firewall rules
- monitoring for repeat activity

Actions should be realistic for a cloud-hosted web application.

## MITRE ATT&CK Mapping
For each relevant incident, map it to likely MITRE ATT&CK techniques.

Format:

Incident → Technique → ID

Example:
Web Enumeration Scan → Active Scanning → T1595

If applicable, also mention:

CWE:
Common weakness being probed

Possible CVE classes:
Examples of vulnerabilities commonly targeted by these probes.

If no specific CVE can be inferred, say:
"Generic vulnerability probing (no specific CVE inferred)."

## Analyst Notes
Add short analyst-style observations such as:

- patterns across incidents
- whether the same attacker IP appears in multiple cases
- whether behavior suggests automated scanning tools

Important rules:
- Do not invent vulnerabilities
- Do not assume compromise without evidence
- If something cannot be determined, state that it is uncertain
- Be concise but be thorough 

Below are the structured incident cases to analyze:

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