from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Optional

from config.settings import PipelineConfig
from pipeline.orchestrator import run_pipeline
from utils.timezone import APP_TIMEZONE_NAME, local_tag_precise, now_local_iso


_EXECUTOR = ThreadPoolExecutor(max_workers=2)
TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def new_run_id() -> str:
    return local_tag_precise()


def _status_path(run_id: str, out_dir: str) -> Path:
    return Path(out_dir) / f"run_status_{run_id}.json"


def write_run_status(
    run_id: str,
    *,
    out_dir: str,
    status: str,
    filepath: str,
    tenant_id: str = "default",
    error: Optional[str] = None,
) -> None:
    payload: Dict[str, Any] = {
        "run_id": run_id,
        "status": status,
        "filepath": filepath,
        "tenant_id": tenant_id,
        "updated_at": now_local_iso(),
        "timezone": APP_TIMEZONE_NAME,
    }
    if error:
        payload["error"] = error

    target = _status_path(run_id, out_dir=out_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_target = target.with_suffix(".tmp")
    tmp_target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_target.replace(target)


def load_run_status(run_id: str, out_dir: str) -> Optional[Dict[str, Any]]:
    target = _status_path(run_id, out_dir=out_dir)
    if not target.exists():
        return None
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def normalize_tenant_id(value: str) -> str:
    tenant_id = (value.strip() or "default").lower()
    if not TENANT_ID_PATTERN.fullmatch(tenant_id):
        raise ValueError("invalid_tenant_id")
    return tenant_id


def persist_uploaded_log(
    run_id: str,
    tenant_id: str,
    original_filename: str,
    content: bytes,
    uploads_dir: str = "uploads",
) -> Path:
    safe_name = Path(original_filename or "uploaded.log").name
    upload_root = Path(uploads_dir) / tenant_id
    upload_root.mkdir(parents=True, exist_ok=True)
    path = upload_root / f"{run_id}_{safe_name}"
    path.write_bytes(content)
    return path


def _execute_job(filepath: str, config: PipelineConfig, run_id: str, tenant_id: str) -> None:
    write_run_status(
        run_id,
        out_dir=config.out_dir,
        status="running",
        filepath=filepath,
        tenant_id=tenant_id,
    )
    try:
        run_pipeline(filepath, config=config, run_id=run_id, tenant_id=tenant_id)
        write_run_status(
            run_id,
            out_dir=config.out_dir,
            status="completed",
            filepath=filepath,
            tenant_id=tenant_id,
        )
    except Exception as exc:  # noqa: BLE001
        write_run_status(
            run_id,
            out_dir=config.out_dir,
            status="failed",
            filepath=filepath,
            tenant_id=tenant_id,
            error=str(exc),
        )


def submit_pipeline_job(
    filepath: str,
    config: Optional[PipelineConfig] = None,
    run_id: Optional[str] = None,
    tenant_id: str = "default",
) -> str:
    cfg = config or PipelineConfig.from_env()
    resolved_run_id = run_id or new_run_id()
    write_run_status(
        resolved_run_id,
        out_dir=cfg.out_dir,
        status="queued",
        filepath=filepath,
        tenant_id=tenant_id,
    )
    _EXECUTOR.submit(_execute_job, filepath, cfg, resolved_run_id, tenant_id)
    return resolved_run_id
