from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from parsers.base import ParseResult, ParserPlugin
from parsers.eb_log_parser import parse_eb_engine_line, parse_eb_hooks_line
from parsers.nginx_parser import parse_nginx_access_line, parse_nginx_error_line
from parsers.web_stdout_parser import parse_web_stdout_line


class NginxAccessParser:
    name = "nginx_access"
    _rx = re.compile(r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+\s+\S+\s+HTTP/')

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if self._rx.search(raw):
            return 0.95
        if "HTTP/" in raw and '"' in raw and " - - [" in raw:
            return 0.6
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        parsed = parse_nginx_access_line(raw)
        if not parsed:
            return ParseResult(False, self.name, 0.0, "http", {}, "nginx_access_parse_failed")
        fields: Dict[str, Any] = {
            "ts": parsed.get("timestamp"),
            "src_ip": parsed.get("client_ip"),
            "http_method": parsed.get("method"),
            "url_path": parsed.get("path"),
            "http_version": parsed.get("proto"),
            "status_code": parsed.get("status"),
            "bytes_sent": parsed.get("bytes"),
            "referer": parsed.get("referrer"),
            "user_agent": parsed.get("user_agent"),
            "host_header": parsed.get("host"),
            "message": raw,
            "attributes": {
                "remote_addr": parsed.get("remote_addr"),
                "real_ip": parsed.get("real_ip"),
            },
        }
        return ParseResult(True, self.name, 0.98, "http", fields)


class NginxErrorParser:
    name = "nginx_error"
    _rx = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+\[[^\]]+\]")

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if self._rx.search(raw):
            return 0.9
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        parsed = parse_nginx_error_line(raw)
        if not parsed:
            return ParseResult(False, self.name, 0.0, "http", {}, "nginx_error_parse_failed")
        fields: Dict[str, Any] = {
            "ts": parsed.get("timestamp"),
            "src_ip": parsed.get("client_ip"),
            "http_method": parsed.get("method"),
            "url_path": parsed.get("path"),
            "http_version": parsed.get("proto"),
            "severity": parsed.get("severity"),
            "message": parsed.get("message") or raw,
            "attributes": {
                "upstream": parsed.get("upstream"),
                "referrer": parsed.get("referrer"),
                "host": parsed.get("host"),
            },
        }
        return ParseResult(True, self.name, 0.95, "http", fields)


class WebStdoutParser:
    name = "web_stdout"
    _rx = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*\[[0-9]{4}-")

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if self._rx.search(raw):
            return 0.9
        if "reason=" in raw and " method=" in raw and " path=" in raw:
            return 0.7
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        parsed = parse_web_stdout_line(raw)
        if not parsed:
            return ParseResult(False, self.name, 0.0, "app", {}, "web_stdout_parse_failed")

        reason = parsed.get("reason")
        action = "blocked" if reason in {"secret_path", "bogus_stack_probe"} else None
        fields: Dict[str, Any] = {
            "ts": parsed.get("timestamp"),
            "src_ip": parsed.get("client_ip"),
            "http_method": parsed.get("method"),
            "url_path": parsed.get("path"),
            "user_agent": parsed.get("user_agent"),
            "message": parsed.get("message") or raw,
            "severity": parsed.get("severity"),
            "action": action,
            "outcome": action,
            "category": reason,
            "attributes": {
                "service": parsed.get("service"),
                "module": parsed.get("module"),
                "sample": parsed.get("sample"),
                "reason": reason,
            },
        }
        return ParseResult(True, self.name, 0.94, "app", fields)


class EbEngineParser:
    name = "eb_engine"

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if raw.startswith("20") and "[" in raw and "Running command:" in raw:
            return 0.75
        if "/" in raw[:10] and "[" in raw:
            return 0.45
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        parsed = parse_eb_engine_line(raw)
        if not parsed:
            return ParseResult(False, self.name, 0.0, "platform", {}, "eb_engine_parse_failed")
        fields: Dict[str, Any] = {
            "ts": parsed.get("timestamp"),
            "message": parsed.get("message") or raw,
            "severity": parsed.get("severity"),
            "event_kind": parsed.get("event_type"),
            "attributes": {
                "command": parsed.get("command"),
                "instruction": parsed.get("instruction"),
                "engine_command": parsed.get("engine_command"),
            },
        }
        return ParseResult(True, self.name, 0.8, "platform", fields)


class EbHooksParser:
    name = "eb_hooks"

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if raw.startswith("20") and "[" in raw:
            return 0.7
        if raw.strip():
            return 0.2
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        parsed = parse_eb_hooks_line(raw)
        if not parsed:
            return ParseResult(False, self.name, 0.0, "platform", {}, "eb_hooks_parse_failed")
        fields: Dict[str, Any] = {
            "ts": parsed.get("timestamp"),
            "message": parsed.get("message") or raw,
            "severity": parsed.get("severity"),
            "event_kind": parsed.get("event_type"),
            "attributes": {
                "command": parsed.get("command"),
            },
        }
        return ParseResult(True, self.name, 0.75, "platform", fields)


class GenericJsonParser:
    name = "generic_json"

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        line = raw.strip()
        if not line.startswith("{") or not line.endswith("}"):
            return 0.0
        try:
            json.loads(line)
        except json.JSONDecodeError:
            return 0.0
        return 0.9

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return ParseResult(False, self.name, 0.0, "app", {}, "generic_json_parse_failed")

        fields: Dict[str, Any] = {
            "ts": payload.get("timestamp") or payload.get("ts") or payload.get("time"),
            "src_ip": payload.get("src_ip") or payload.get("client_ip") or payload.get("sourceAddress"),
            "http_method": payload.get("method") or payload.get("verb"),
            "url_path": payload.get("path") or payload.get("url") or payload.get("request_uri"),
            "status_code": payload.get("status") or payload.get("http_status") or payload.get("sc_status"),
            "user_agent": payload.get("user_agent") or payload.get("ua"),
            "message": payload.get("message") or raw,
            "severity": payload.get("severity") or payload.get("level"),
            "action": payload.get("action"),
            "outcome": payload.get("outcome"),
            "category": payload.get("category") or payload.get("reason"),
            "attributes": payload,
        }
        return ParseResult(True, self.name, 0.9, "app", fields)


class SyslogGenericParser:
    name = "syslog_generic"
    _rx = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+")

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        if self._rx.search(raw):
            return 0.65
        return 0.0

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        fields: Dict[str, Any] = {
            "message": raw,
            "attributes": {},
        }
        return ParseResult(True, self.name, 0.6, "system", fields)


class FallbackRawParser:
    name = "fallback_raw"

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        return 0.01

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        return ParseResult(
            success=False,
            parser_name=self.name,
            confidence=0.01,
            event_family=None,
            fields={"message": raw, "attributes": {}},
            error="no_parser_matched",
        )


def build_default_parsers() -> List[ParserPlugin]:
    return [
        NginxAccessParser(),
        NginxErrorParser(),
        WebStdoutParser(),
        EbEngineParser(),
        EbHooksParser(),
        GenericJsonParser(),
        SyslogGenericParser(),
        FallbackRawParser(),
    ]
