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

1. Ingestion accepts either:
   - multi-tenant intake payloads (`POST /pipeline/intake`)
   - legacy file/section-header logs (`run_pipeline(filepath=...)`) via compatibility mapping
2. Raw events route through parser hint + auto-detection parser plugins
3. Parsed results normalize into one canonical event schema
4. Canonical events run through `run_detections(...)`
5. Cases are enriched with threat intel
6. Cases are augmented with deterministic analysis fields
7. Cases are correlated into campaigns
8. Alerts are generated
9. Reports and metadata are persisted
10. LLM summary is generated when enabled and cases exist

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
3. `POST /pipeline/intake` (synchronous, canonical ingestion payload)
4. `GET /pipeline/runs/{run_id}` (status + metadata + links)
5. `GET /pipeline/runs/{run_id}/cases`
6. `GET /pipeline/runs/{run_id}/campaigns`
7. `GET /pipeline/runs/{run_id}/alerts`
8. `GET /pipeline/runs/{run_id}/downloads/{artifact_name}`
9. `POST /auth/keys/create` (admin only)
10. `GET /auth/keys` (admin only)
11. `POST /auth/keys/revoke` (admin only)
12. `GET /auth/status`

Async submit payload example:

```json
{
  "tenant_id": "acme",
  "filename": "customer.log",
  "log_content": "...raw log text..."
}
```

Canonical intake payload example:

```json
{
  "tenant_id": "acme-prod",
  "parser_hint": "nginx_access",
  "source": {
    "vendor": "nginx",
    "product": "nginx",
    "service": "frontend",
    "type": "access",
    "format": "combined",
    "host": "web-01",
    "environment": "prod"
  },
  "events": [
    {
      "message": "84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\"",
      "timestamp": null,
      "attributes": {}
    }
  ]
}
```

### API keys and tenant isolation

Auth can be enabled with:

```env
SOC_API_AUTH_ENABLED=true
SOC_ADMIN_TOKEN=your_admin_token
SOC_API_KEYS_PATH=data/api_keys.json
SOC_AUDIT_LOG_PATH=logs/api_audit.log
```

Behavior:

1. When auth is enabled, pipeline endpoints require `Authorization: Bearer <api_key>`.
2. Each API key belongs to one tenant.
3. Run metadata/status/artifacts can only be accessed by API keys from the same tenant.
4. API calls are audit-logged to `logs/api_audit.log` as append-only JSON lines.

Create a tenant key (admin token required):

```bash
curl -X POST http://127.0.0.1:8000/auth/keys/create \
  -H "x-admin-token: your_admin_token" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","label":"acme-prod"}'
```

Use returned `api_key` with pipeline calls:

```bash
curl -X POST "http://127.0.0.1:8000/pipeline/submit" \
  -H "Authorization: Bearer <api_key>" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","filename":"customer.log","log_content":"..."}'
```

### Client examples (`client/`)

Use the local client script to submit, poll, and download artifacts.

Without API auth:

```bash
python client/smb_client.py \
  --base-url http://127.0.0.1:8000 \
  --tenant-id acme \
  --file client/example_2.log \
  --out-dir client/client_downloads
```

With API auth enabled:

```bash
python client/smb_client.py \
  --base-url http://127.0.0.1:8000 \
  --tenant-id acme \
  --api-key <api_key> \
  --file client/example_2.log \
  --out-dir client/client_downloads
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

Security artifacts:

1. API key store: `data/api_keys.json` (hashed keys, metadata only)
2. API audit log: `logs/api_audit.log` (JSON lines)

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

## API Documentation

- Full endpoint + onboarding guide (auth setup, API keys, request/response schemas, field definitions, client playbooks, smoke tests): `docs/api_reference.md`
- Client-facing quickstart (what clients need, exact commands, troubleshooting): `docs/client_quickstart.md`

## Operational Notes

1. Input logs are read-only; pipeline writes new output artifacts.
2. TI provider failures do not stop detection/report generation.
3. LLM failures do not fail the run; they are recorded under `errors` in run metadata.
4. Detection coverage includes automated tests for all implemented detector types.
5. Parser routing uses `parser_hint` as first attempt, then auto-detection, then `fallback_raw`.
6. Canonical ingestion details and plugin extension guide: `docs/ingestion_v2.md`.
