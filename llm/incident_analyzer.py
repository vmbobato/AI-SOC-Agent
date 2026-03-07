import json
import requests
from openai import OpenAI
from typing import List, Dict, Any
from threat_intel.enrich import compact_cases_for_llm


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

OPENAI_MODEL = "gpt-4.1"


def build_soc_prompt(cases: List[Dict[str, Any]]) -> str:
    compact_cases = compact_cases_for_llm(cases)
    cases_json = json.dumps(compact_cases, indent=2)

    return f"""
You are a professional SOC (Security Operations Center) analyst.

Your task is to analyze structured security incident cases and produce a concise,
accurate analyst report.

The cases were generated automatically from server logs by a detection engine.

You must behave like a cautious SOC analyst performing log triage.

--------------------------------------------------
STRICT ANALYSIS RULES
--------------------------------------------------

1. Use ONLY the information provided in the case data.
2. Do NOT invent vulnerabilities, attacker intent, files, endpoints, infrastructure, or locations.
3. Do NOT infer geolocation, hosting providers, threat actors, or campaigns unless explicitly present.
4. If evidence is insufficient for a claim, explicitly state that the conclusion is uncertain.
5. Never assume compromise unless the evidence explicitly shows successful access.
6. Do not reference files such as ".env", "phpunit", ".git", etc unless they appear in the case evidence.
7. When referencing evidence, cite the specific paths, counts, or fields provided.
8. If multiple incidents involve the same source IP, mention this correlation.
9. Pay special attention to any HTTP 200 responses in scanning activity, as these may indicate exposed endpoints.
10. If threat intelligence fields exist (reputation, ASN, abuse score, etc), use them cautiously to prioritize risk but do not overclaim.

If the available evidence does not support a conclusion, clearly say:

"Evidence is insufficient to determine X."

--------------------------------------------------
ATTACK PRIORITY GUIDANCE
--------------------------------------------------

Prioritize incidents in the following order:

1. Exploitation attempts
2. Application-layer probes or blocked exploit attempts
3. Large-scale scanning or reconnaissance
4. Brute force attempts
5. Traffic anomalies or bursts

--------------------------------------------------
OUTPUT FORMAT
--------------------------------------------------

Your output must be Markdown.

--------------------------------------------------
# AI SOC Analyst Summary

## Executive Summary

Provide a short high-level summary of the activity detected across all incidents.

Include:
- number of incidents
- attacker behavior patterns
- whether activity appears to be reconnaissance, probing, exploitation attempts,
  brute force attempts, or service abuse.

Mention if multiple incidents appear to originate from the same source IP.

Limit to 3–5 sentences.

--------------------------------------------------

## Incident Breakdown

For each case include the following section:

### Incident: <incident_type>

**Impact**

Explain why this activity is relevant from a security perspective.

Do not speculate beyond the evidence.

**Evidence Observed**

Summarize key indicators from the case data such as:

- request counts
- targeted paths
- HTTP status ratios
- user agents
- blocked requests
- suspicious patterns

Only reference data present in the case.

**Assessment**

Classify the behavior as ONE of the following:

- Reconnaissance / scanning
- Exploitation attempt
- Brute force attack
- Service abuse / DoS
- Suspicious but inconclusive

Briefly justify the classification using the observed evidence.

**Confidence Reasoning**

Explain why the detection appears high, medium, or low confidence.

Base reasoning strictly on the evidence.

--------------------------------------------------

## Priority Assessment

Identify:

- the highest priority incident
- why it should be prioritized
- whether any evidence suggests successful exposure or compromise

If there is no evidence of compromise, clearly state:

"No evidence of successful compromise was observed."

--------------------------------------------------

## Recommended Next Actions

Provide realistic operational steps for a security engineer or SOC analyst.

Examples include:

- block offending IP addresses
- enable or tune WAF rules
- review server logs for successful responses
- monitor for repeated activity
- investigate successful HTTP responses during scans
- harden exposed endpoints

Recommendations must be grounded in the observed activity.

--------------------------------------------------

## MITRE ATT&CK Mapping

Map each incident to relevant ATT&CK techniques **only if the evidence supports it**.

Examples for web attacks:

Reconnaissance
- T1595 – Active Scanning

Initial Access
- T1190 – Exploit Public-Facing Application

Discovery
- T1046 – Network Service Discovery

For each technique provide a short justification.

If mapping is uncertain, state:

"Evidence insufficient for confident MITRE mapping."

Do NOT invent techniques.

--------------------------------------------------

Before writing the report, internally review the evidence and ensure all conclusions are supported by the case data.

Here are the structured incident cases:

{cases_json}
""".strip()


def analyze_cases_with_openai(
    cases: List[Dict[str, Any]],
    model: str = OPENAI_MODEL,
):
    client = OpenAI()
    response = client.responses.create(
        model=model,
        input=build_soc_prompt(cases)
    )
    return response.output_text


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
