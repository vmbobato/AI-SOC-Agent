# Client Quickstart

Audience: SMB clients sending logs to the platform and downloading SOC outputs.

Base URL example: `http://127.0.0.1:8000`

## 1) What you need from your provider

Ask your provider for:

1. `API_BASE_URL` (example: `http://127.0.0.1:8000`)
2. `TENANT_ID` (example: `acme`)
3. `API_KEY` (your tenant API key)

Do not ask for or use an admin token.

## 2) Verify connectivity

```bash
curl "$API_BASE_URL/health"
curl "$API_BASE_URL/auth/status"
```

Expected `/health` response example:

```json
{
  "service": "AI-SOC-Agent",
  "version": "0.3.0",
  "status": "ok"
}
```

If auth is enabled, all pipeline calls require:

```http
Authorization: Bearer <API_KEY>
```

## 3) Fastest path: use the provided client script

Input file example in this repo: `client/example_2.log`

### A) Send structured events (`intake-events`)

Use this if your shipper already thinks in per-line events.

```bash
python client/smb_client.py \
  --base-url "$API_BASE_URL" \
  --tenant-id "$TENANT_ID" \
  --api-key "$API_KEY" \
  --file client/example_2.log \
  --out-dir client/client_downloads_events \
  --mode intake-events
```

### B) Send full log file (`intake-log-content`) (recommended default)

Use this when you want server-side splitting and parsing.

```bash
python client/smb_client.py \
  --base-url "$API_BASE_URL" \
  --tenant-id "$TENANT_ID" \
  --api-key "$API_KEY" \
  --file client/example_2.log \
  --out-dir client/client_downloads_logcontent \
  --mode intake-log-content
```

Notes:

1. For mixed log types in one file, do not set `--parser-hint`.
2. For known single-type streams, optional hint example: `--parser-hint nginx_access`.

## 4) Direct API usage (without client script)

## 4.1 Send full file to `/pipeline/intake`

```bash
curl -X POST "$API_BASE_URL/pipeline/intake" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "tenant_id": "acme",
  "source": {
    "vendor": "nginx",
    "product": "nginx",
    "service": "frontend",
    "type": "access",
    "environment": "prod"
  },
  "log_content": "84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\""
}
JSON
```

Response includes `run_id`, `links`, and `download_links`.

## 4.2 Send structured events to `/pipeline/intake`

```bash
curl -X POST "$API_BASE_URL/pipeline/intake" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme",
    "source": {"vendor":"nginx","product":"nginx","type":"access"},
    "events": [
      {
        "message": "84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] \"GET /.env HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\"",
        "timestamp": null,
        "attributes": {}
      }
    ]
  }'
```

## 4.3 Fetch status/results by `run_id`

```bash
curl -H "Authorization: Bearer $API_KEY" \
  "$API_BASE_URL/pipeline/runs/<run_id>"
```

## 4.4 Download generated files

```bash
curl -L -H "Authorization: Bearer $API_KEY" \
  -o cases.json \
  "$API_BASE_URL/pipeline/runs/<run_id>/downloads/cases"
```

Supported artifact names:

1. `incident_report`
2. `cases`
3. `campaigns`
4. `alerts`
5. `llm_summary` (if generated)
6. `metadata`

## 5) Common issues

1. `401 missing_bearer_token` or `401 invalid_api_key`
- Ensure `Authorization: Bearer <API_KEY>` is set.

2. `403 tenant_access_denied`
- Your key belongs to a different tenant than `tenant_id` in request.

3. `409` on key creation (admin side)
- Tenant already has an active key.

4. `404 artifact_not_found`
- Run not completed yet or artifact not generated (for example `llm_summary` when LLM disabled/fails).

## 6) Recommended client defaults

1. Use `/pipeline/intake` with `log_content` as default.
2. Send source metadata (`vendor/product/service/type/environment`) whenever possible.
3. Keep requests batched (file/window), not one HTTP call per single line.
4. Retry transient HTTP failures with exponential backoff.
