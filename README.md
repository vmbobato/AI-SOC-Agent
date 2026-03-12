# AI SOC Agent

AI SOC Agent is a Python SOC pipeline that parses infrastructure logs, detects suspicious activity, correlates incidents into campaigns, generates alerts, enriches IPs with threat intel, and produces analyst-ready reports with optional LLM summaries.

## Current Architecture

### Pipeline layers

1. `ingestion`: reads log files line-by-line (`ingest/log_reader.py`)
2. `detection_engine`: builds incident cases from parsed events (`detections/engine.py`)
3. `threat_intel`: enriches case source IPs (`threat_intel/enrich.py`)
4. `llm_analysis`: generates SOC summaries with OpenAI/Ollama (`llm/incident_analyzer.py`)
5. `alert_pipeline`: creates normalized, deduplicated alerts (`alert_pipeline/alerts.py`)
6. `reporting`: writes markdown/JSON artifacts and run metadata (`reports/*`)

### Execution flow

Entry points: `main.py` (CLI) and `api/app.py` (FastAPI control plane).

1. `pipeline/orchestrator.py` parses logs by section header:
   - `/var/log/nginx/access.log`
   - `/var/log/nginx/error.log`
   - `/var/log/web.stdout.log`
   - `/var/log/eb-engine.log`
   - `/var/log/eb-hooks.log`
2. Parsed events run through `run_detections(...)`
3. Cases are enriched with threat intel
4. Cases are augmented with deterministic analysis fields
5. Cases are correlated into campaigns
6. Alerts are generated
7. Reports and metadata are persisted
8. LLM summary is generated when enabled and cases exist

## Detection Coverage

Implemented detections:

1. Web Enumeration Scan
2. Sensitive File / Exploit Probe
3. Blocked App-Layer Probe
4. Brute Force Attempt
5. Traffic Burst / Possible DoS

## Threat Intelligence

Per-case enrichment is attached under `case["threat_intel"]`.

Providers:

1. IPinfo (country/city/asn/org)
2. AbuseIPDB (abuse confidence/reports)

Safe-IP handling:

1. Private
2. Loopback
3. Link-local
4. Reserved/multicast/unspecified
5. Invalid IPs

When API keys are missing, public IPs are marked `skipped_no_api_keys` and pipeline execution continues.

## LLM Summary Layer

Supported providers:

1. OpenAI (default)
2. Ollama

Defaults from config:

1. `SOC_LLM_ENABLED=true`
2. `SOC_LLM_PROVIDER=openai`
3. `SOC_LLM_MODEL=gpt-4.1`

For Ollama, default endpoint is `http://localhost:11434/api/generate`.

## Project Structure

```text
.
├── main.py
├── api/
│   └── app.py
├── pipeline/
│   ├── orchestrator.py
│   └── jobs.py
├── config/
│   └── settings.py
├── models/
│   └── schemas.py
├── alert_pipeline/
│   └── alerts.py
├── ingest/
├── parsers/
├── detections/
├── correlation/
├── threat_intel/
├── llm/
├── reports/
├── tests/
├── data/
└── requirements.txt
```

## Requirements

Pinned dependencies in `requirements.txt`:

1. `pandas==3.0.1`
2. `numpy==2.4.2`
3. `requests==2.32.5`
4. `python-dotenv==1.0.1`
5. `fastapi==0.116.1`
6. `uvicorn==0.35.0`
7. `openai==2.8.0`

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

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure `.env` (recommended):

```env
# Threat intel
AUTH_BEARER_IP_INFO=your_ipinfo_token
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# LLM defaults
SOC_LLM_ENABLED=true
SOC_LLM_PROVIDER=openai
SOC_LLM_MODEL=gpt-4.1
OPENAI_API_KEY=your_openai_key

# Optional directories
SOC_REPORTS_DIR=reports
SOC_UPLOADS_DIR=uploads
```

For Ollama instead of OpenAI:

```env
SOC_LLM_PROVIDER=ollama
SOC_LLM_MODEL=llama3
```

## Running the Project

### CLI mode

```bash
python main.py
```

Commands:

1. `run` -> runs pipeline on default sample file
2. `run <path>` -> runs pipeline on a custom log file
3. `exit` -> exits and saves session state

### API mode

Start server:

```bash
uvicorn api.app:app --reload
```

Endpoints:

1. `POST /pipeline/run?filepath=/path/to/log` (synchronous)
2. `POST /pipeline/submit` (asynchronous; JSON payload)
3. `GET /pipeline/runs/{run_id}` (status + metadata + links)
4. `GET /pipeline/runs/{run_id}/cases`
5. `GET /pipeline/runs/{run_id}/campaigns`
6. `GET /pipeline/runs/{run_id}/alerts`
7. `GET /pipeline/runs/{run_id}/downloads/{artifact_name}`

Async submit payload example:

```json
{
  "tenant_id": "acme",
  "filename": "customer.log",
  "log_content": "...raw log text..."
}
```

## Outputs

Artifacts written per run:

1. `reports/incident_report_<timestamp>.md`
2. `reports/cases_<timestamp>.json`
3. `reports/campaigns_<timestamp>.json`
4. `reports/alerts_<timestamp>.json`
5. `reports/run_metadata_<run_id>.json`
6. `reports/llm_summary_<timestamp>.md` (if generated)
7. `reports/run_status_<run_id>.json` (async jobs)

Uploaded async logs are saved under `uploads/<tenant_id>/`.

## Testing and Quality

Run tests:

```bash
python -m unittest discover -s tests -v
```

Static checks:

```bash
ruff check .
mypy .
```

CI workflow is defined in `.github/workflows/ci.yml`.

## Operational Notes

1. Input logs are read-only; pipeline writes new output artifacts.
2. TI provider failures do not stop detection/report generation.
3. LLM failures do not fail the run; they are recorded under `errors` in run metadata.
4. Detection coverage includes automated tests for all implemented detector types.
