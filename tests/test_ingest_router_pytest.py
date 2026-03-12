from __future__ import annotations

from ingest.compat import source_context_from_section
from ingest.intake_models import IntakeRequest
from ingest.router import build_router
from normalize.mappers import normalize_to_canonical
from detections.engine import run_detections


def test_router_parser_hint_routing_nginx_access() -> None:
    router = build_router()
    raw = '84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"'
    routed = router.route(raw, parser_hint="nginx_access", context={})
    assert routed.result.success is True
    assert routed.result.parser_name == "nginx_access"


def test_router_auto_detection_without_hint() -> None:
    router = build_router()
    raw = '84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"'
    routed = router.route(raw, parser_hint=None, context={})
    assert routed.result.success is True
    assert routed.result.parser_name == "nginx_access"


def test_router_fallback_behavior_unknown_log() -> None:
    router = build_router()
    raw = "totally unknown format line"
    routed = router.route(raw, parser_hint=None, context={})
    assert routed.result.success is False
    assert routed.result.parser_name == "fallback_raw"
    assert routed.result.error == "no_parser_matched"


def test_nginx_access_parse_and_normalize() -> None:
    router = build_router()
    raw = '84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"'
    routed = router.route(raw, parser_hint="nginx_access", context={})
    event = normalize_to_canonical(
        tenant_id="acme-prod",
        source={"vendor": "nginx", "product": "nginx", "service": "frontend", "type": "access", "environment": "prod"},
        raw_message=raw,
        raw_timestamp=None,
        raw_attributes={},
        parse_result=routed.result,
    )
    assert event.tenant_id == "acme-prod"
    assert event.parser_name == "nginx_access"
    assert event.src_ip == "84.247.182.240"
    assert event.http_method == "GET"
    assert event.url_path == "/.env"
    assert event.status_code == 404
    assert event.is_4xx is True


def test_nginx_error_parse() -> None:
    router = build_router()
    raw = '2026/03/12 04:21:11 [error] 123#456: *12 open() "/var/www/html/.env" failed (2: No such file or directory), client: 84.247.182.240, server: _, request: "GET /.env HTTP/1.1", host: "example.com"'
    routed = router.route(raw, parser_hint="nginx_error", context={})
    assert routed.result.success is True
    assert routed.result.parser_name == "nginx_error"


def test_generic_json_parse() -> None:
    router = build_router()
    raw = '{"timestamp":"2026-03-12T04:21:11+00:00","client_ip":"1.2.3.4","method":"POST","path":"/login","status":401,"message":"failed"}'
    routed = router.route(raw, parser_hint=None, context={})
    assert routed.result.success is True
    assert routed.result.parser_name == "generic_json"
    assert routed.result.fields.get("status_code") == 401


def test_compatibility_adapter_section_mapping() -> None:
    ctx = source_context_from_section("/var/log/nginx/access.log")
    assert ctx["parser_hint"] == "nginx_access"
    assert ctx["source"]["type"] == "access"


def test_api_request_model_validation() -> None:
    payload = IntakeRequest.model_validate(
        {
            "tenant_id": "Acme-Prod",
            "parser_hint": "nginx_access",
            "source": {"vendor": "nginx", "product": "nginx", "service": "frontend", "type": "access", "format": "combined", "host": "web-01", "environment": "prod"},
            "events": [{"message": '84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"', "timestamp": None, "attributes": {}}],
        }
    )
    assert payload.tenant_id == "acme-prod"
    assert payload.source.vendor == "nginx"
    assert len(payload.events) == 1


def test_api_request_model_validation_with_log_content() -> None:
    payload = IntakeRequest.model_validate(
        {
            "tenant_id": "Acme-Prod",
            "parser_hint": "nginx_access",
            "source": {"vendor": "nginx", "product": "nginx", "service": "frontend", "type": "access"},
            "log_content": '84.247.182.240 - - [12/Mar/2026:04:21:11 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.5.0"\n'
            '84.247.182.240 - - [12/Mar/2026:04:21:12 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "curl/8.5.0"',
        }
    )
    events = payload.iter_events()
    assert payload.tenant_id == "acme-prod"
    assert len(events) == 2
    assert events[0].message.startswith("84.247.182.240")


def test_detections_on_canonical_events() -> None:
    events = []
    for i in range(40):
        events.append(
            {
                "ts": f"2026-03-12T01:00:{i:02d}-05:00",
                "tenant_id": "acme-prod",
                "event_family": "http",
                "source_type": "access",
                "parser_name": "nginx_access",
                "src_ip": "84.247.182.240",
                "http_method": "GET",
                "url_path": f"/scan-{i}",
                "status_code": 404,
                "user_agent": "curl/8.5.0",
            }
        )

    cases = run_detections(events)
    incident_types = {case["incident_type"] for case in cases}
    assert "Web Enumeration Scan" in incident_types
