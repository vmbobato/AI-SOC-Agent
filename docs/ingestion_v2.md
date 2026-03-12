# Ingestion V2 (Multi-tenant Canonical Pipeline)

This project now supports a generalized ingestion flow that accepts tenant metadata and raw events, routes through parser plugins, and normalizes all data into a canonical event schema before detections run.

## Pipeline flow

`raw intake payload -> intake validation -> parser routing (hint + autodetect) -> parser plugin parse result -> canonical normalization -> detections -> correlation/alerts/reports/LLM`

## Intake payload

Endpoint: `POST /pipeline/intake`

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

## `parser_hint` behavior

1. If `parser_hint` is provided, that parser is attempted first.
2. If hinted parse fails or confidence is weak, auto-detection runs across parser plugins.
3. The highest-confidence parser above threshold is used.
4. If none match confidently, `fallback_raw` is used.

## Parser plugin system

Base interface (`parsers/base.py`):

- `name: str`
- `matches(raw: str, context: dict | None = None) -> float`
- `parse(raw: str, context: dict | None = None) -> ParseResult`

Default plugins (`parsers/plugins.py`):

- `nginx_access`
- `nginx_error`
- `web_stdout`
- `eb_engine`
- `eb_hooks`
- `generic_json`
- `syslog_generic`
- `fallback_raw`

## Canonical event schema

Canonical model is defined in `normalize/canonical.py` and produced by `normalize/mappers.py`.

Core fields include:

- identity/context: `ts`, `tenant_id`, `vendor`, `product`, `service`, `environment`, `host`, `source_type`
- parser metadata: `parser_name`, `parser_confidence`, `parser_version`, `parse_error`
- network/http: `src_ip`, `src_port`, `dest_ip`, `dest_port`, `http_method`, `url_path`, `url_query`, `http_version`, `host_header`, `user_agent`, `referer`, `status_code`, `bytes_sent`, `request_time_ms`
- detection semantics: `event_family`, `event_kind`, `action`, `outcome`, `severity`, `category`, `rule_id`, `rule_name`
- payload: `message`, `raw_message`, `attributes`
- derived: `is_4xx`, `is_5xx`, `is_sensitive_path`, `is_probe_like`, `path_depth`

Detections consume canonical fields only.

## Backward compatibility

Legacy file/section-header ingestion still works through a compatibility adapter (`ingest/compat.py`) that maps known section headers into source metadata and parser hints, then routes through the same new router + normalizer.

This preserves existing `run_pipeline(filepath=...)` behavior while using the new ingestion architecture under the hood.

## Adding a new parser plugin

1. Implement the parser class with the base interface.
2. Add it to the parser list in `build_default_parsers()`.
3. Map any parser-specific fields in `normalize/mappers.py` if needed.
4. Add focused tests for routing, parsing, and normalization.
