from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, Request


_STORE_LOCK = Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def auth_enabled() -> bool:
    from os import getenv

    return getenv("SOC_API_AUTH_ENABLED", "false").strip().lower() in {"1", "true", "yes"}


def _store_path() -> Path:
    from os import getenv

    return Path(getenv("SOC_API_KEYS_PATH", "data/api_keys.json"))


def _admin_token() -> str:
    from os import getenv

    return getenv("SOC_ADMIN_TOKEN", "")


@dataclass(slots=True)
class AuthContext:
    tenant_id: str
    key_id: str


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _load_store() -> Dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return {"keys": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"keys": []}
    keys = payload.get("keys")
    if not isinstance(keys, list):
        return {"keys": []}
    return {"keys": keys}


def _write_store(payload: Dict[str, Any]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def _extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing_bearer_token")
    token = auth_header.split(" ", maxsplit=1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing_bearer_token")
    return token


def authenticate_request(request: Request) -> Optional[AuthContext]:
    if not auth_enabled():
        return None

    token = _extract_bearer_token(request)
    token_hash = _hash_key(token)

    with _STORE_LOCK:
        store = _load_store()
        for key in store["keys"]:
            if not isinstance(key, dict):
                continue
            if not bool(key.get("active", True)):
                continue
            if key.get("key_hash") != token_hash:
                continue

            tenant_id = key.get("tenant_id")
            key_id = key.get("key_id")
            if not isinstance(tenant_id, str) or not tenant_id:
                break
            if not isinstance(key_id, str) or not key_id:
                break

            key["last_used_utc"] = _now()
            _write_store(store)
            return AuthContext(tenant_id=tenant_id, key_id=key_id)

    raise HTTPException(status_code=401, detail="invalid_api_key")


def validate_admin_request(request: Request) -> None:
    expected = _admin_token()
    if not expected:
        raise HTTPException(status_code=403, detail="admin_token_not_configured")
    provided = request.headers.get("x-admin-token", "").strip()
    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=403, detail="invalid_admin_token")


def create_api_key(tenant_id: str, label: str = "") -> Dict[str, str]:
    with _STORE_LOCK:
        store = _load_store()
        for key in store.get("keys", []):
            if not isinstance(key, dict):
                continue
            existing_tenant = key.get("tenant_id")
            if (
                isinstance(existing_tenant, str)
                and existing_tenant.lower() == tenant_id.lower()
                and bool(key.get("active", True))
            ):
                raise ValueError("tenant_active_key_already_exists")

        raw_key = f"soc_{secrets.token_urlsafe(32)}"
        key_id = f"key_{secrets.token_hex(8)}"
        record = {
            "key_id": key_id,
            "tenant_id": tenant_id,
            "label": label,
            "key_hash": _hash_key(raw_key),
            "active": True,
            "created_utc": _now(),
            "last_used_utc": None,
        }

        keys = [k for k in store.get("keys", []) if isinstance(k, dict)]
        keys.append(record)
        store["keys"] = keys
        _write_store(store)

    return {"key_id": key_id, "tenant_id": tenant_id, "api_key": raw_key}


def revoke_api_key(key_id: str) -> bool:
    updated = False
    with _STORE_LOCK:
        store = _load_store()
        for key in store.get("keys", []):
            if not isinstance(key, dict):
                continue
            if key.get("key_id") == key_id:
                key["active"] = False
                key["revoked_utc"] = _now()
                updated = True
                break
        if updated:
            _write_store(store)
    return updated


def list_api_keys(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    store = _load_store()
    keys: List[Dict[str, Any]] = []
    for key in store.get("keys", []):
        if not isinstance(key, dict):
            continue
        if tenant_id and key.get("tenant_id") != tenant_id:
            continue
        keys.append(
            {
                "key_id": key.get("key_id"),
                "tenant_id": key.get("tenant_id"),
                "label": key.get("label"),
                "active": key.get("active", True),
                "created_utc": key.get("created_utc"),
                "last_used_utc": key.get("last_used_utc"),
                "revoked_utc": key.get("revoked_utc"),
            }
        )
    return keys
