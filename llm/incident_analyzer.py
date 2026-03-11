import json
import requests
from typing import List, Dict, Any
from llm.analysis_context import prepare_cases_for_llm
from correlation.campaigns import prepare_campaigns_for_llm


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3"

OPENAI_MODEL = "gpt-4.1"


def build_soc_prompt(cases: List[Dict[str, Any]], campaigns: List[Dict[str, Any]] | None = None) -> str:
    campaigns = campaigns or []
    compact_cases = prepare_cases_for_llm(cases)
    compact_campaigns = prepare_campaigns_for_llm(campaigns)
    cases_json = json.dumps(compact_cases, indent=2)
    campaigns_json = json.dumps(compact_campaigns, indent=2)

    return f"""
You are a professional SOC (Security Operations Center) analyst.

Your task is to analyze structured security campaigns and incident cases and produce a concise, accurate SOC analyst report.

The campaigns and incidents were generated automatically from server logs by a detection engine and enriched with deterministic analysis fields.

You must behave like a cautious SOC analyst performing log triage.

--------------------------------------------------
STRICT ANALYSIS RULES
--------------------------------------------------

1. Use ONLY the information provided in the campaign and case data.
2. Do NOT invent vulnerabilities, attacker intent, files, endpoints, infrastructure, locations, successful paths, or exposure details.
3. Do NOT infer geolocation, hosting providers, threat actors, reputation, or campaign coordination unless explicitly present in the structured data.
4. If evidence is insufficient for a claim, explicitly state that the conclusion is uncertain.
5. Never assume compromise unless the evidence explicitly shows successful access to sensitive resources.
6. Do not reference files such as ".env", "phpunit", ".git", etc unless they appear in the provided evidence or precomputed summaries.
7. When referencing evidence, cite the specific paths, counts, ratios, or fields provided.
8. If campaigns are present, analyze campaigns first and treat related cases as coordinated activity only when supported by the campaign data.
9. Pay special attention to:
   - successful HTTP 200 responses during scans or probes
   - precomputed exposure_analysis
   - IOC summaries
   - infrastructure context
   - defensive control effectiveness
10. Threat intelligence fields (ASN, org, hosting provider status, abuse score, abuse reports) may be used for context, but must not be overinterpreted.
11. If user agent data is present anywhere in the campaign or case data, include it in IOC Extraction.
12. If multiple campaigns share the same ASN or org, mention this as shared infrastructure context, but do NOT assume coordination unless the structured data supports it.
13. If exact successful paths are not known, explicitly say that they are unknown rather than guessing.
14. Use deterministic analysis fields such as analysis_context, exposure_analysis, severity_explanation, control_effectiveness, IOC summaries, and analyst_playbook as primary sources of interpretation.
15. If a deterministic field conflicts with your own inference, trust the deterministic field.

If the available evidence does not support a conclusion, clearly say:

"Evidence is insufficient to determine X."

--------------------------------------------------
ATTACK PRIORITY GUIDANCE
--------------------------------------------------

Prioritize activity in the following order:

1. Confirmed exploitation or exposure
2. Sensitive file probing with exposure indicators
3. Application-layer probes or blocked exploit attempts
4. Large-scale scanning or reconnaissance
5. Brute force attempts
6. Traffic anomalies or bursts

--------------------------------------------------
OUTPUT FORMAT
--------------------------------------------------

Your output must be Markdown.

--------------------------------------------------
# AI SOC Analyst Summary

## Executive Summary

Provide a short high-level overview of activity detected across campaigns.

Include:
- number of campaigns
- number of incidents
- attacker behavior patterns
- whether activity appears to be reconnaissance, probing, exploitation attempts, brute force attempts, or service abuse
- whether campaigns appear coordinated, independent, or only share infrastructure context

Limit to 3–5 sentences.

--------------------------------------------------

## Attack Classification

Classify the overall attack patterns observed.

Possible classifications include:
- Automated vulnerability scanning
- Web path enumeration
- Sensitive file probing
- Blocked exploit probing
- Brute force attempts
- Suspicious but inconclusive activity

Base classification strictly on observed evidence and deterministic analysis fields.

--------------------------------------------------

## Campaign Overview

For each campaign include:

### Campaign: <campaign_id>

**Behavior Pattern**

Describe the sequence of activity using the campaign timeline and attack_pattern if present.

**Risk Assessment**

Explain campaign risk using:
- risk_score
- risk_level
- evidence volume
- types of scanning or probing
- exposure indicators
- risk_factors if present

**Campaign Severity Explanation**

Explain WHY the campaign risk level was assigned using:
- number of incidents
- number of requests
- sensitive targets
- successful HTTP responses
- severity_explanation
- analysis_context

**Infrastructure Analysis**

If threat intelligence or shared infrastructure context exists, summarize:
- ASN
- organization
- hosting provider status
- abuse reports or abuse score
- shared infrastructure across campaigns

Do not speculate beyond the provided information.

--------------------------------------------------

## Exposure Analysis

Identify any indicators suggesting possible exposure.

Examples:
- HTTP 200 responses during scanning
- successful access to sensitive paths
- configuration files returning success codes
- explicit exposure_review_required flags

If successful responses occurred:
- state the count
- state whether exact successful paths are known
- if known, list them
- if unknown, explicitly state that the exact successful paths are unknown and require log review

If no exposure indicators are present, state:

"No evidence of exposed sensitive resources was observed."

--------------------------------------------------

## Indicators of Compromise (IOC Extraction)

Extract observable indicators from the data.

Include:

**Source IPs**
List attacker IP addresses.

**Suspicious Paths**
List notable targeted paths or endpoints.

**User Agents**
List repeated or suspicious user agents if present.

**Infrastructure Indicators**
Include ASN, hosting provider, or organization if present.

Do not add indicators that are not present in the data.

--------------------------------------------------

## Defensive Control Effectiveness

Evaluate whether security controls appear to have mitigated the activity.

Examples:
- high 404 ratios suggesting paths were not exposed
- WAF blocks or "secret_path" rules triggered
- blocked probes with no successful responses
- partially effective controls when scans still receive HTTP 200 responses

Explain whether defenses appear effective, partially effective, or in need of improvement.

--------------------------------------------------

## Incident Breakdown

For each case include:

### Incident: <incident_type>

**Impact**
Explain why this activity is relevant from a security perspective.

**Evidence Observed**
Summarize key indicators such as:
- request counts
- targeted paths
- HTTP status ratios
- blocked attempts
- suspicious patterns
- case-level analysis_context if present

Only reference evidence present in the case data.

**Assessment**
Classify behavior as ONE of the following:
- Reconnaissance / scanning
- Exploitation attempt
- Brute force attack
- Service abuse / DoS
- Suspicious but inconclusive

Provide brief justification.

**Confidence Reasoning**
Explain why the detection appears high, medium, or low confidence.

Base reasoning on the case evidence and deterministic analysis fields.

--------------------------------------------------

## Priority Assessment

Identify:
- the highest priority campaign
- why it should be prioritized
- whether evidence suggests exposure or compromise

If compromise evidence is absent, clearly state:

"No evidence of successful compromise was observed."

If exposure indicators exist but exact resource exposure is unknown, clearly state that follow-up review is required.

--------------------------------------------------

## Analyst Playbook

Provide practical SOC response steps based on the observed activity.

Use the provided analyst_playbook if present, and expand only when clearly supported by the evidence.

Examples include:
- investigate successful HTTP responses
- block or rate-limit offending IPs
- verify exposed endpoints
- tune WAF or app-layer protection rules
- monitor for repeated scanning behavior
- review sensitive file exposure

Recommendations must be grounded in the observed activity.

--------------------------------------------------

## MITRE ATT&CK Mapping

Map incidents to ATT&CK techniques ONLY when supported by evidence.

Examples:
- T1595 – Active Scanning
- T1190 – Exploit Public-Facing Application
- T1046 – Network Service Discovery

Rules:
- Do NOT invent techniques.
- Do NOT map to T1190 unless the evidence shows confirmed exploit behavior, exploit payloads, or successful exploitation/exposure that clearly supports initial access.
- If mapping is uncertain, state:
  "Evidence insufficient for confident MITRE mapping."

Provide short justifications for each mapping.

--------------------------------------------------

Before writing the report, internally verify that all conclusions are supported by the provided campaign and case data.

Here are the structured attack campaigns:

{campaigns_json}

Here are the structured incident cases:

{cases_json}
""".strip()


def analyze_cases_with_openai(
    cases: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]] | None = None,
    model: str = OPENAI_MODEL,
):
    from openai import OpenAI

    client = OpenAI()
    response = client.responses.create(
        model=model,
        input=build_soc_prompt(cases, campaigns=campaigns)
    )
    return response.output_text


def analyze_cases_with_ollama(
    cases: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]] | None = None,
    model: str = OLLAMA_MODEL,
    url: str = OLLAMA_URL,
    timeout: int = 500,
) -> str:
    if not cases:
        return "## AI SOC Analyst Summary\n\nNo incidents to analyze."

    prompt = build_soc_prompt(cases, campaigns=campaigns)

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()

    data = resp.json()
    return data.get("response", "").strip()
