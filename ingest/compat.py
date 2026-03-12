from __future__ import annotations

from typing import Any, Dict


SECTION_MAP: Dict[str, Dict[str, Any]] = {
    "/var/log/nginx/access.log": {
        "parser_hint": "nginx_access",
        "source": {
            "vendor": "nginx",
            "product": "nginx",
            "service": "web",
            "type": "access",
            "format": "combined",
        },
    },
    "/var/log/nginx/error.log": {
        "parser_hint": "nginx_error",
        "source": {
            "vendor": "nginx",
            "product": "nginx",
            "service": "web",
            "type": "error",
            "format": "nginx_error",
        },
    },
    "/var/log/web.stdout.log": {
        "parser_hint": "web_stdout",
        "source": {
            "vendor": "app",
            "product": "web",
            "service": "web_stdout",
            "type": "application",
            "format": "syslog_app",
        },
    },
    "/var/log/eb-engine.log": {
        "parser_hint": "eb_engine",
        "source": {
            "vendor": "aws",
            "product": "elastic_beanstalk",
            "service": "eb_engine",
            "type": "platform",
            "format": "eb_engine",
        },
    },
    "/var/log/eb-hooks.log": {
        "parser_hint": "eb_hooks",
        "source": {
            "vendor": "aws",
            "product": "elastic_beanstalk",
            "service": "eb_hooks",
            "type": "platform",
            "format": "eb_hooks",
        },
    },
}


def source_context_from_section(section: str) -> Dict[str, Any]:
    mapped = SECTION_MAP.get(section)
    if not mapped:
        return {
            "parser_hint": None,
            "source": {
                "vendor": "unknown",
                "product": "unknown",
                "service": "unknown",
                "type": "unknown",
                "format": "raw",
            },
        }
    return {
        "parser_hint": mapped.get("parser_hint"),
        "source": dict(mapped.get("source") or {}),
    }
