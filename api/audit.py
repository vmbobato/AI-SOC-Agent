from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from utils.timezone import APP_TIMEZONE_NAME, now_local_iso


def _audit_path() -> Path:
    from os import getenv

    return Path(getenv("SOC_AUDIT_LOG_PATH", "logs/api_audit.log"))


def write_audit_event(
    *,
    endpoint: str,
    method: str,
    status: str,
    status_code: int,
    client_ip: Optional[str] = None,
    forwarded_for: Optional[str] = None,
    tenant_id: Optional[str] = None,
    run_id: Optional[str] = None,
    detail: Optional[Any] = None,
) -> None:
    payload = {
        "timestamp": now_local_iso(),
        "timezone": APP_TIMEZONE_NAME,
        "endpoint": endpoint,
        "method": method,
        "status": status,
        "status_code": status_code,
        "client_ip": client_ip,
        "forwarded_for": forwarded_for,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "detail": detail,
    }

    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
