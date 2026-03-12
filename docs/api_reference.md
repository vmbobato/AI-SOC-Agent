# API Reference (Operator Guide)

Base URL (local): `http://127.0.0.1:8000`

This document is written for three roles:

1. Platform admin: configures auth and creates/revokes tenant API keys.
2. Client integrator: sends logs and retrieves results.
3. Analyst/consumer: fetches cases, campaigns, alerts, and report files.

## 1) Authentication Model

The API supports two modes.

1. Auth disabled: `SOC_API_AUTH_ENABLED=false`
- Pipeline endpoints are open.
- No bearer token required.

2. Auth enabled: `SOC_API_AUTH_ENABLED=true`
- Pipeline endpoints require `Authorization: Bearer <api_key>`.
- Each API key belongs to one tenant.
- Tenant isolation is enforced for run access and downloads.

Admin endpoints always require:
- `x-admin-token: <SOC_ADMIN_TOKEN>`

## 2) Required Environment Variables

Minimum recommended `.env`:

```env
SOC_API_AUTH_ENABLED=true
SOC_ADMIN_TOKEN=replace_with_secure_admin_token
SOC_API_KEYS_PATH=data/api_keys.json
SOC_AUDIT_LOG_PATH=logs/api_audit.log

SOC_REPORTS_DIR=reports
SOC_UPLOADS_DIR=uploads

SOC_LLM_ENABLED=true
SOC_LLM_PROVIDER=openai
SOC_LLM_MODEL=gpt-4.1
SOC_LLM_TIMEOUT_SECONDS=60
OPENAI_API_KEY=replace_with_openai_key
```

Optional threat-intel keys:

```env
AUTH_BEARER_IP_INFO=replace_with_ipinfo_token
ABUSEIPDB_API_KEY=replace_with_abuseipdb_key
```

## 3) Client Onboarding Flows

### Flow A: First-time platform setup (admin)

1. Set `.env` with auth + admin token.
2. Start API server.
3. Confirm health and auth mode.
4. Create tenant API key.
5. Share only tenant API key with customer, never admin token.

### Flow B: Tenant integration

1. Use tenant API key in `Authorization: Bearer`.
2. Send logs using one ingestion endpoint (`/pipeline/intake` preferred).
3. Save `run_id` from response.
4. Poll `/pipeline/runs/{run_id}` if async path is used.
5. Download needed artifacts.

### Flow C: Key rotation/recovery

1. Admin creates replacement key.
2. Client updates integration to new key.
3. Admin revokes old key.

## 4) Field Definitions (Core Models)

## 4.1 Tenant identifier

Field: `tenant_id`

- Type: `string`
- Normalized to lowercase.
- Allowed characters at API runtime: letters, digits, `_`, `-`.
- Max length: `64`.
- Purpose: tenant isolation boundary for runs, artifacts, and access control.

## 4.2 Source metadata (`source` object)

All fields optional but recommended:

- `vendor`: technology vendor, example `nginx`
- `product`: product name, example `nginx`
- `service`: logical service, example `frontend`
- `type`: stream type, example `access`, `error`, `application`
- `format`: log format hint, example `combined`, `json`, `plain`
- `host`: source hostname, example `web-01`
- `environment`: environment, example `prod`, `staging`

Purpose: improves context and parser confidence; not a strict parser selector.

## 4.3 Intake event object (`events[]`)

- `message`: raw log line (required)
- `timestamp`: optional timestamp from client
- `attributes`: optional key/value metadata map

## 4.4 Parser hint

Field: `parser_hint` (optional)

- Example values: `nginx_access`, `nginx_error`, `web_stdout`, `generic_json`
- Behavior:
1. Hint parser is tried first.
2. If hint parse fails, auto-detection runs.
3. If no parser matches confidently, fallback parser is used.

Use hint when stream is known single-type. Omit hint for mixed log files.

## 4.5 `events` vs `log_content`

In `POST /pipeline/intake`, provide at least one:

1. `events`: pre-structured line items.
2. `log_content`: entire file text.

Resolution rule:

- If `events` is present and non-empty, it is used.
- Else `log_content` is split into non-empty lines and converted to events server-side.

## 5) Endpoint Reference

## 5.1 Health

### `GET /health`

Purpose: liveness check.

Auth: none.

Response:

```json
{
  "status": "ok"
}
```

Example:

```bash
curl http://127.0.0.1:8000/health
```

## 5.2 Auth status

### `GET /auth/status`

Purpose: confirms if bearer auth is currently enforced.

Auth: none.

Response:

```json
{
  "auth_enabled": true
}
```

Example:

```bash
curl http://127.0.0.1:8000/auth/status
```

## 5.3 Create tenant API key (admin)

### `POST /auth/keys/create`

Purpose: creates one active key for a tenant.

Headers:

- `x-admin-token: <SOC_ADMIN_TOKEN>`

Request:

```json
{
  "tenant_id": "acme",
  "label": "acme-prod"
}
```

Response:

```json
{
  "key_id": "key_abc123...",
  "tenant_id": "acme",
  "api_key": "soc_xxx..."
}
```

Notes:

- Returns `409` if tenant already has active key (`tenant_active_key_already_exists`).
- Save `api_key` immediately; stored value is hashed server-side.

Example:

```bash
curl -X POST http://127.0.0.1:8000/auth/keys/create \
  -H "x-admin-token: $SOC_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","label":"acme-prod"}'
```

## 5.4 List API keys (admin)

### `GET /auth/keys`

Purpose: list keys for all tenants or one tenant.

Headers:

- `x-admin-token: <SOC_ADMIN_TOKEN>`

Query params:

- `tenant_id` optional

Response:

```json
{
  "keys": [
    {
      "key_id": "key_...",
      "tenant_id": "acme",
      "label": "acme-prod",
      "active": true,
      "created_utc": "2026-03-12T15:10:00+00:00",
      "last_used_utc": null,
      "revoked_utc": null
    }
  ]
}
```

Example:

```bash
curl "http://127.0.0.1:8000/auth/keys?tenant_id=acme" \
  -H "x-admin-token: $SOC_ADMIN_TOKEN"
```

## 5.5 Revoke API key (admin)

### `POST /auth/keys/revoke`

Purpose: deactivate key by key ID.

Headers:

- `x-admin-token: <SOC_ADMIN_TOKEN>`

Request:

```json
{
  "key_id": "key_abc123..."
}
```

Response:

```json
{
  "status": "revoked",
  "key_id": "key_abc123..."
}
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/auth/keys/revoke \
  -H "x-admin-token: $SOC_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key_id":"key_abc123"}'
```

## 5.6 Run pipeline on server-side file path

### `POST /pipeline/run`

Purpose: synchronous run using file already present on server.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Query params:

- `filepath` required
- `tenant_id` optional (validated against bearer tenant)

Example:

```bash
curl -X POST "http://127.0.0.1:8000/pipeline/run?filepath=tests/fixtures/sample_pipeline.log" \
  -H "Authorization: Bearer $API_KEY"
```

## 5.7 Submit async run with file content

### `POST /pipeline/submit`

Purpose: async ingestion endpoint for full file content.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Request schema:

- `tenant_id`: string
- `filename`: string
- `log_content`: string

Request example:

```json
{
  "tenant_id": "acme",
  "filename": "nginx.log",
  "log_content": "...full file text..."
}
```

Response example:

```json
{
  "run_id": "20260312_103015_123456_ct",
  "status": "queued",
  "filepath": "uploads/acme/20260312_..._nginx.log",
  "tenant_id": "acme",
  "links": {
    "status": "http://127.0.0.1:8000/pipeline/runs/20260312_...",
    "cases": ".../cases",
    "campaigns": ".../campaigns",
    "alerts": ".../alerts"
  }
}
```

## 5.8 Canonical intake endpoint (recommended)

### `POST /pipeline/intake`

Purpose: synchronous ingest with parser routing + canonical normalization.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Request schema:

```json
{
  "tenant_id": "string",
  "parser_hint": "string|null",
  "source": {
    "vendor": "string|null",
    "product": "string|null",
    "service": "string|null",
    "type": "string|null",
    "format": "string|null",
    "host": "string|null",
    "environment": "string|null"
  },
  "events": [
    {
      "message": "string",
      "timestamp": "string|null",
      "attributes": {}
    }
  ],
  "log_content": "string|null"
}
```

Validation rules:

- At least one of `events` or `log_content` must be present.
- If both are present, `events` is used.

Example A: `events` mode

```bash
curl -X POST http://127.0.0.1:8000/pipeline/intake \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id":"acme",
    "source":{"vendor":"nginx","product":"nginx","service":"frontend","type":"access"},
    "events":[
      {"message":"84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\"","timestamp":null,"attributes":{}}
    ]
  }'
```

Example B: full-file `log_content` mode

```bash
curl -X POST http://127.0.0.1:8000/pipeline/intake \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "tenant_id":"acme",
  "source":{"vendor":"nginx","product":"nginx","service":"frontend","type":"access"},
  "log_content":"84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\"\n84.247.182.240 - - [12/Mar/2026:04:21:12 +0000] \"GET /.git/config HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\""
}
JSON
```

Response shape for sync runs (`/pipeline/run` and `/pipeline/intake`):

```json
{
  "run_id": "string",
  "tenant_id": "string",
  "status": "completed|file_not_found",
  "filepath": "string",
  "input_sha256": "string",
  "counts": {"events": 0, "cases": 0, "campaigns": 0, "alerts": 0},
  "parse_stats": {"parsed_ok": {}, "parsed_fail": {}},
  "artifacts": {"incident_report": "path", "cases": "path", "campaigns": "path", "alerts": "path", "metadata": "path"},
  "timings_ms": {"parse": 0, "detect": 0, "enrich_and_augment": 0, "campaign_correlation": 0, "alert_pipeline": 0, "reporting": 0, "llm": 0, "total": 0},
  "errors": [],
  "links": {"status": "url", "cases": "url", "campaigns": "url", "alerts": "url"},
  "download_links": {"incident_report": "url", "cases": "url", "campaigns": "url", "alerts": "url", "llm_summary": "url", "metadata": "url"}
}
```

## 5.9 Get run status/metadata

### `GET /pipeline/runs/{run_id}`

Purpose: returns completed metadata or async in-progress status.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

In-progress response example:

```json
{
  "run_id": "20260312_...",
  "status": "queued|running|failed",
  "filepath": "uploads/acme/...",
  "tenant_id": "acme",
  "updated_at": "2026-03-12T10:34:11-05:00",
  "timezone": "America/Chicago",
  "error": "optional",
  "links": {"status": "url", "cases": "url", "campaigns": "url", "alerts": "url"}
}
```

## 5.10 Get cases

### `GET /pipeline/runs/{run_id}/cases`

Purpose: returns `cases` for completed run.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Response:

```json
{
  "run_id": "string",
  "tenant_id": "string",
  "cases": [],
  "links": {"status": "url", "cases": "url", "campaigns": "url", "alerts": "url"}
}
```

## 5.11 Get campaigns

### `GET /pipeline/runs/{run_id}/campaigns`

Purpose: returns `campaigns` for completed run.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Response:

```json
{
  "run_id": "string",
  "tenant_id": "string",
  "campaigns": [],
  "links": {"status": "url", "cases": "url", "campaigns": "url", "alerts": "url"}
}
```

## 5.12 Get alerts

### `GET /pipeline/runs/{run_id}/alerts`

Purpose: returns `alerts` for completed run.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Response:

```json
{
  "run_id": "string",
  "tenant_id": "string",
  "alerts": [],
  "links": {"status": "url", "cases": "url", "campaigns": "url", "alerts": "url"}
}
```

## 5.13 Download artifact

### `GET /pipeline/runs/{run_id}/downloads/{artifact_name}`

Purpose: downloads one artifact from a completed run.

Headers when auth enabled:

- `Authorization: Bearer <api_key>`

Path param `artifact_name` allowed values:

- `incident_report`
- `cases`
- `campaigns`
- `alerts`
- `llm_summary`
- `metadata`

Query params:

- `inline` optional boolean (`false` default)

Examples:

```bash
curl -L -H "Authorization: Bearer $API_KEY" \
  -o cases.json \
  "http://127.0.0.1:8000/pipeline/runs/<run_id>/downloads/cases"
```

```bash
curl -H "Authorization: Bearer $API_KEY" \
  "http://127.0.0.1:8000/pipeline/runs/<run_id>/downloads/incident_report?inline=true"
```

## 6) Practical Client Playbooks

### Playbook 1: Small business client using raw file text (recommended)

1. Admin creates tenant key once.
2. Client stores key securely.
3. Client sends `/pipeline/intake` with `log_content` and source metadata.
4. Client reads response `run_id` and `download_links`.
5. Client downloads `incident_report`, `cases`, `campaigns`, `alerts`, optional `llm_summary`.

### Playbook 2: Client with structured log shipper

1. Build `events[]` from lines.
2. Add optional `timestamp` and `attributes` per event.
3. Send one `/pipeline/intake` request per batch/window.
4. Use `parser_hint` only for single-type streams.

### Playbook 3: Legacy async upload path

1. Send `/pipeline/submit` with `filename` + `log_content`.
2. Poll `/pipeline/runs/{run_id}` until `completed`.
3. Download artifacts.

## 7) Error Codes and Meanings

Common HTTP codes:

- `400`: invalid tenant ID, invalid payload, empty upload
- `401`: missing/invalid bearer token when auth enabled
- `403`: invalid admin token, tenant access denied
- `404`: run not found, artifact not found, key not found
- `409`: run not completed yet, tenant already has active key

Typical error body:

```json
{
  "detail": "error_code_or_message"
}
```

## 8) Security and Operations Notes

1. Never share `SOC_ADMIN_TOKEN` with customers.
2. Share only per-tenant API keys.
3. Rotate API keys on personnel changes or suspected leakage.
4. API audit log records endpoint, method, status, tenant_id, run_id, client IP, and `x-forwarded-for`.
5. Keep `data/api_keys.json` and audit logs in restricted storage.
6. If LLM fails, run still completes and error appears in run `errors`.

## 9) Minimal End-to-End Smoke Test

1. Check health:

```bash
curl http://127.0.0.1:8000/health
```

2. Check auth mode:

```bash
curl http://127.0.0.1:8000/auth/status
```

3. Create key (admin):

```bash
curl -X POST http://127.0.0.1:8000/auth/keys/create \
  -H "x-admin-token: $SOC_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","label":"acme-prod"}'
```

4. Run intake:

```bash
curl -X POST http://127.0.0.1:8000/pipeline/intake \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"acme","source":{"vendor":"nginx","product":"nginx","type":"access"},"log_content":"84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\""}'
```

5. Download cases:

```bash
curl -L -H "Authorization: Bearer $API_KEY" \
  -o cases.json \
  "http://127.0.0.1:8000/pipeline/runs/<run_id>/downloads/cases"
```
