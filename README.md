# AI SOC Agent

AI SOC Agent is a local SOC analysis pipeline that:

1. Parses infrastructure and application logs
2. Detects suspicious behavior
3. Builds structured incident cases
4. Enriches attacker IPs with threat intelligence
5. Generates markdown/JSON reports
6. Produces an LLM SOC analyst summary

## Current Architecture

This repository currently runs as a local CLI workflow (no AWS module in the current tree).

### Pipeline layers

1. `ingestion`: reads log files line-by-line (`ingest/log_reader.py`)
2. `detection_engine`: builds cases from parsed events (`detections/engine.py`)
3. `threat_intel`: enriches case source IPs (`threat_intel/enrich.py`)
4. `llm_analysis`: summarizes cases with Ollama/OpenAI (`llm/incident_analyzer.py`)
5. `alert_pipeline`: creates normalized, deduplicated alerts (`alert_pipeline/alerts.py`)
6. `reporting`: writes markdown + JSON + run metadata files (`reports/*`)

### Main execution flow

Entry points: `main.py` (CLI) and `api/app.py` (FastAPI control plane).

1. `pipeline/orchestrator.py` reads and parses a log file by section headers
2. The parser context switches based on section headers like:
   - `/var/log/nginx/access.log`
   - `/var/log/nginx/error.log`
   - `/var/log/web.stdout.log`
   - `/var/log/eb-engine.log`
   - `/var/log/eb-hooks.log`
3. Parsed events are sent to `run_detections(...)`
4. Cases are enriched with threat intel via `enrich_cases_with_threat_intel(...)`
5. Cases are correlated into campaigns
6. Alerts are generated via `build_alerts(...)`
7. Reports and metadata are written to `reports/`
8. If enabled (`SOC_LLM_ENABLED=true`), an LLM summary is generated and saved

## Detection Coverage

Implemented detections:

1. Web Enumeration Scan
2. Sensitive File / Exploit Probe
3. Blocked App-Layer Probe
4. Brute Force Attempt
5. Traffic Burst / Possible DoS

## Threat Intelligence Enrichment

Threat intel is attached per case under `case["threat_intel"]`.

### Providers

1. IPinfo (geo/org/asn context)
2. AbuseIPDB (abuse score/report count context)

### Safe IP handling

IPs are classified before enrichment. The pipeline skips:

1. Private IPs
2. Loopback
3. Link-local
4. Reserved/multicast/unspecified
5. Invalid IP strings

Skipped values are marked with `intel_status` (for example: `skipped_private_ip`).

### Behavior when keys are missing

If provider keys are not configured, pipeline execution continues and marks public IP enrichment as `skipped_no_api_keys`.

## LLM Summary Layer

LLM analysis runs through Ollama using:

1. URL: `http://localhost:11434/api/generate`
2. Model default in code: `llama3`

Before prompt generation, cases are compacted with `compact_cases_for_llm(...)` to include normalized intel fields without noisy raw payloads.

## Project Structure

```text
.
├── main.py
├── pipeline/
│   └── orchestrator.py
├── config/
│   └── settings.py
├── models/
│   └── schemas.py
├── alert_pipeline/
│   └── alerts.py
├── ingest/
│   └── log_reader.py
├── parsers/
│   ├── nginx_parser.py
│   ├── web_stdout_parser.py
│   └── eb_log_parser.py
├── detections/
│   └── engine.py
├── threat_intel/
│   ├── __init__.py
│   └── enrich.py
├── llm/
│   └── incident_analyzer.py
├── reports/
│   ├── report_writer.py
│   └── llm_report_writer.py
├── api/
│   └── app.py
├── data/
├── saved_states/
└── requirements.txt
```

## Requirements

`requirements.txt` is version pinned:

1. `pandas==3.0.1`
2. `numpy==2.4.2`
3. `requests==2.32.5`
4. `python-dotenv==1.0.1`

## Setup

1. Create venv:

```bash
python3 -m venv .soc_agent
```

2. Activate:

Linux/macOS:

```bash
source .soc_agent/bin/activate
```

Windows PowerShell:

```powershell
.\.soc_agent\Scripts\Activate.ps1
```

3. Install deps:

```bash
pip install -r requirements.txt
```

4. (Optional) configure `.env` in repo root for threat intel:

```env
AUTH_BEARER_IP_INFO=your_ipinfo_token
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

Notes:

1. `threat_intel/enrich.py` calls `load_dotenv()`, so `.env` is auto-loaded.
2. Current code reads `AUTH_BEARER_IP_INFO` for IPinfo auth token.

5. Start Ollama (optional but needed for LLM summary):

```bash
ollama serve
ollama pull llama3
```

## Running the Project

### Interactive mode

```bash
python main.py
```

Available commands:

1. `run` -> executes full pipeline on the default sample file
2. `exit` -> exits and saves state JSON into `saved_states/`

### Run against a custom file path

```bash
python -c "import main; main.run('path/to/your_log_file.log')"
```

### API mode (control plane)

Run with Uvicorn:

```bash
uvicorn api.app:app --reload
```

Endpoints:

1. `POST /pipeline/run?filepath=/path/to/log` (synchronous run)
2. `POST /pipeline/submit` (async run from log content payload)
3. `GET /pipeline/runs/{run_id}` (status + metadata + links)
4. `GET /pipeline/runs/{run_id}/cases`
5. `GET /pipeline/runs/{run_id}/campaigns`
6. `GET /pipeline/runs/{run_id}/alerts`
7. `GET /pipeline/runs/{run_id}/downloads/{artifact_name}` (`cases`, `campaigns`, `alerts`, `incident_report`, `llm_summary`, `metadata`)

## Outputs

Generated artifacts:

1. Incident markdown report: `reports/incident_report_<timestamp>.md`
2. Cases JSON: `reports/cases_<timestamp>.json`
3. Campaigns JSON: `reports/campaigns_<timestamp>.json`
4. Alerts JSON: `reports/alerts_<timestamp>.json`
5. Run metadata JSON: `reports/run_metadata_<run_id>.json`
6. LLM markdown summary (if enabled and cases exist): `reports/llm_summary_<timestamp>.md`
7. Session state on exit: `saved_states/<timestamp>_Saved-State.json`

## Case Schema (simplified)

Each case includes:

1. `incident_type`
2. `timestamp_start`, `timestamp_end`
3. `source_ips`
4. `evidence`
5. `severity`, `confidence`
6. `recommended_actions`
7. `threat_intel` (added during enrichment)

Example threat intel block:

```json
{
  "threat_intel": {
    "84.247.182.240": {
      "intel_status": "enriched",
      "country": "NL",
      "city": "Amsterdam",
      "asn": "AS12345",
      "org": "Example ISP",
      "is_hosting_provider": true,
      "abuse_confidence_score": 67,
      "abuse_reports": 24,
      "source": ["ipinfo", "abuseipdb"]
    }
  }
}
```

## Operational Notes

1. If external TI providers are unreachable, enrichment fails gracefully and detection/reporting still complete.
2. Logs are consumed as input only; outputs are written as new files.
3. This repo currently does not include automated detection tests yet; adding tests for each detector is recommended as the next hardening step.
