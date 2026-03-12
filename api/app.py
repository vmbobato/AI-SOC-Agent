from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.audit import write_audit_event
from api.auth import (
    AuthContext,
    auth_enabled,
    authenticate_request,
    create_api_key,
    list_api_keys,
    revoke_api_key,
    validate_admin_request,
)
from config.settings import PipelineConfig
from ingest.intake_models import IntakeRequest
from pipeline.jobs import (
    load_run_status,
    new_run_id,
    normalize_tenant_id,
    persist_uploaded_log,
    submit_pipeline_job,
)
from pipeline.orchestrator import (
    load_alerts_for_run,
    load_artifact_path_for_run,
    load_campaigns_for_run,
    load_cases_for_run,
    load_run_metadata,
    run_pipeline,
    run_pipeline_from_intake,
)


DOWNLOADABLE_ARTIFACTS = {
    "incident_report",
    "cases",
    "campaigns",
    "alerts",
    "llm_summary",
    "metadata",
}


class SubmitLogPayload(BaseModel):
    tenant_id: str = "default"
    filename: str = "uploaded.log"
    log_content: str


class IntakeRunPayload(IntakeRequest):
    pass


class CreateApiKeyPayload(BaseModel):
    tenant_id: str
    label: str = ""


class RevokeApiKeyPayload(BaseModel):
    key_id: str


def _run_pipeline(filepath: str, tenant_id: str) -> dict:
    result = run_pipeline(filepath, config=PipelineConfig.from_env(), tenant_id=tenant_id)
    return result.to_dict()


def _build_run_links(request: Request, run_id: str) -> Dict[str, str]:
    base = str(request.base_url).rstrip("/")
    return {
        "status": f"{base}/pipeline/runs/{run_id}",
        "cases": f"{base}/pipeline/runs/{run_id}/cases",
        "campaigns": f"{base}/pipeline/runs/{run_id}/campaigns",
        "alerts": f"{base}/pipeline/runs/{run_id}/alerts",
    }


def _build_download_links(request: Request, metadata: Dict[str, Any]) -> Dict[str, str]:
    run_id = metadata.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return {}

    artifacts = metadata.get("artifacts") or {}
    if not isinstance(artifacts, dict):
        return {}

    base = str(request.base_url).rstrip("/")
    links: Dict[str, str] = {}
    for artifact_name in artifacts:
        if artifact_name in DOWNLOADABLE_ARTIFACTS:
            links[artifact_name] = f"{base}/pipeline/runs/{run_id}/downloads/{artifact_name}"
    return links


def _resolve_auth(request: Request) -> Optional[AuthContext]:
    return authenticate_request(request)


def _resolve_tenant_id(request: Request, provided_tenant_id: Optional[str] = None) -> str:
    auth_ctx = _resolve_auth(request)

    if auth_ctx:
        if provided_tenant_id is not None:
            try:
                normalized = normalize_tenant_id(provided_tenant_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if normalized != auth_ctx.tenant_id:
                raise HTTPException(status_code=403, detail="tenant_access_denied")
        return auth_ctx.tenant_id

    if provided_tenant_id is None:
        return "default"
    try:
        return normalize_tenant_id(provided_tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _enforce_tenant_access(metadata_or_status: Dict[str, Any], request: Request) -> None:
    auth_ctx = _resolve_auth(request)
    if not auth_ctx:
        return

    tenant_id = metadata_or_status.get("tenant_id")
    if not isinstance(tenant_id, str) or tenant_id != auth_ctx.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_access_denied")


def _require_completed_metadata(run_id: str, out_dir: str, request: Request) -> Dict[str, Any]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if metadata:
        _enforce_tenant_access(metadata, request)
        return metadata

    status_payload = load_run_status(run_id, out_dir=out_dir)
    if status_payload:
        _enforce_tenant_access(status_payload, request)
        raise HTTPException(status_code=409, detail=status_payload)

    raise HTTPException(status_code=404, detail="run_not_found")


def _audit(
    request: Request,
    *,
    status: str,
    status_code: int,
    tenant_id: Optional[str] = None,
    run_id: Optional[str] = None,
    detail: Optional[Any] = None,
) -> None:
    client_ip = request.client.host if request.client else None
    forwarded_for = request.headers.get("x-forwarded-for")
    write_audit_event(
        endpoint=request.url.path,
        method=request.method,
        status=status,
        status_code=status_code,
        client_ip=client_ip,
        forwarded_for=forwarded_for,
        tenant_id=tenant_id,
        run_id=run_id,
        detail=detail,
    )


def create_app() -> FastAPI:
    """Build and return the FastAPI application instance."""
    app = FastAPI(title="AI SOC Analyst API", version="0.4.0")

    @app.get("/health")
    def health(request: Request) -> dict[str, str]:
        _audit(request, status="success", status_code=200)
        return {"status": "ok"}

    @app.post("/auth/keys/create")
    def create_key(payload: CreateApiKeyPayload, request: Request) -> dict:
        validate_admin_request(request)
        try:
            tenant_id = normalize_tenant_id(payload.tenant_id)
        except ValueError as exc:
            _audit(request, status="bad_request", status_code=400, detail=str(exc))
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            created = create_api_key(tenant_id=tenant_id, label=payload.label)
        except ValueError as exc:
            _audit(request, status="conflict", status_code=409, tenant_id=tenant_id, detail=str(exc))
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        _audit(request, status="success", status_code=200, tenant_id=tenant_id, detail={"key_id": created["key_id"]})
        return created

    @app.get("/auth/keys")
    def get_keys(request: Request, tenant_id: Optional[str] = None) -> dict:
        validate_admin_request(request)
        if tenant_id:
            try:
                normalized_tenant = normalize_tenant_id(tenant_id)
            except ValueError as exc:
                _audit(request, status="bad_request", status_code=400, detail=str(exc))
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            normalized_tenant = None
        keys = list_api_keys(tenant_id=normalized_tenant)
        _audit(request, status="success", status_code=200, tenant_id=normalized_tenant)
        return {"keys": keys}

    @app.post("/auth/keys/revoke")
    def revoke_key(payload: RevokeApiKeyPayload, request: Request) -> dict:
        validate_admin_request(request)
        revoked = revoke_api_key(payload.key_id)
        if not revoked:
            _audit(request, status="not_found", status_code=404, detail={"key_id": payload.key_id})
            raise HTTPException(status_code=404, detail="key_not_found")
        _audit(request, status="success", status_code=200, detail={"key_id": payload.key_id})
        return {"status": "revoked", "key_id": payload.key_id}

    @app.post("/pipeline/run")
    def run_pipeline_for_file(filepath: str, request: Request, tenant_id: Optional[str] = None) -> dict:
        resolved_tenant = _resolve_tenant_id(request, tenant_id)
        payload = _run_pipeline(filepath, tenant_id=resolved_tenant)
        run_id = payload.get("run_id")
        if isinstance(run_id, str):
            payload["links"] = _build_run_links(request, run_id)
            payload["download_links"] = {
                name: f"{str(request.base_url).rstrip('/')}/pipeline/runs/{run_id}/downloads/{name}"
                for name in (payload.get("artifacts") or {}).keys()
                if name in DOWNLOADABLE_ARTIFACTS
            }
        _audit(request, status="success", status_code=200, tenant_id=resolved_tenant, run_id=run_id if isinstance(run_id, str) else None)
        return payload

    @app.post("/pipeline/submit")
    def submit_pipeline_job_from_upload(payload: SubmitLogPayload, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        resolved_tenant = _resolve_tenant_id(request, payload.tenant_id)

        content = payload.log_content.encode("utf-8")
        if not content:
            _audit(request, status="bad_request", status_code=400, tenant_id=resolved_tenant, detail="empty_upload")
            raise HTTPException(status_code=400, detail="empty_upload")

        run_id = new_run_id()
        saved_path = persist_uploaded_log(
            run_id,
            resolved_tenant,
            payload.filename,
            content,
            uploads_dir=cfg.uploads_dir,
        )

        submit_pipeline_job(
            filepath=str(saved_path),
            config=cfg,
            run_id=run_id,
            tenant_id=resolved_tenant,
        )

        response = {
            "run_id": run_id,
            "status": "queued",
            "filepath": str(saved_path),
            "tenant_id": resolved_tenant,
            "links": _build_run_links(request, run_id),
        }
        _audit(request, status="queued", status_code=200, tenant_id=resolved_tenant, run_id=run_id)
        return response

    @app.post("/pipeline/intake")
    def run_pipeline_from_intake_payload(payload: IntakeRunPayload, request: Request) -> dict:
        resolved_tenant = _resolve_tenant_id(request, payload.tenant_id)
        result = run_pipeline_from_intake(
            intake_request=payload,
            config=PipelineConfig.from_env(),
            tenant_id=resolved_tenant,
        )
        response = result.to_dict()
        response["links"] = _build_run_links(request, result.run_id)
        response["download_links"] = {
            name: f"{str(request.base_url).rstrip('/')}/pipeline/runs/{result.run_id}/downloads/{name}"
            for name in (response.get("artifacts") or {}).keys()
            if name in DOWNLOADABLE_ARTIFACTS
        }
        _audit(request, status="success", status_code=200, tenant_id=resolved_tenant, run_id=result.run_id)
        return response

    @app.get("/pipeline/runs/{run_id}")
    def get_run_metadata(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        metadata = load_run_metadata(run_id, out_dir=cfg.out_dir)
        if metadata:
            _enforce_tenant_access(metadata, request)
            payload = dict(metadata)
            payload["links"] = _build_run_links(request, run_id)
            payload["download_links"] = _build_download_links(request, payload)
            _audit(request, status="success", status_code=200, tenant_id=payload.get("tenant_id"), run_id=run_id)
            return payload

        status_payload = load_run_status(run_id, out_dir=cfg.out_dir)
        if status_payload:
            _enforce_tenant_access(status_payload, request)
            payload = dict(status_payload)
            payload["links"] = _build_run_links(request, run_id)
            _audit(request, status=str(payload.get("status") or "unknown"), status_code=200, tenant_id=payload.get("tenant_id"), run_id=run_id)
            return payload

        _audit(request, status="not_found", status_code=404, run_id=run_id)
        raise HTTPException(status_code=404, detail="run_not_found")

    @app.get("/pipeline/runs/{run_id}/cases")
    def get_run_cases(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        metadata = _require_completed_metadata(run_id, out_dir=cfg.out_dir, request=request)
        tenant_value = metadata.get("tenant_id")
        tenant_for_audit = tenant_value if isinstance(tenant_value, str) else None
        response = {
            "run_id": run_id,
            "tenant_id": tenant_for_audit,
            "cases": load_cases_for_run(run_id, out_dir=cfg.out_dir),
            "links": _build_run_links(request, run_id),
        }
        _audit(request, status="success", status_code=200, tenant_id=tenant_for_audit, run_id=run_id)
        return response

    @app.get("/pipeline/runs/{run_id}/campaigns")
    def get_run_campaigns(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        metadata = _require_completed_metadata(run_id, out_dir=cfg.out_dir, request=request)
        tenant_value = metadata.get("tenant_id")
        tenant_for_audit = tenant_value if isinstance(tenant_value, str) else None
        response = {
            "run_id": run_id,
            "tenant_id": tenant_for_audit,
            "campaigns": load_campaigns_for_run(run_id, out_dir=cfg.out_dir),
            "links": _build_run_links(request, run_id),
        }
        _audit(request, status="success", status_code=200, tenant_id=tenant_for_audit, run_id=run_id)
        return response

    @app.get("/pipeline/runs/{run_id}/alerts")
    def get_run_alerts(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        metadata = _require_completed_metadata(run_id, out_dir=cfg.out_dir, request=request)
        tenant_value = metadata.get("tenant_id")
        tenant_for_audit = tenant_value if isinstance(tenant_value, str) else None
        response = {
            "run_id": run_id,
            "tenant_id": tenant_for_audit,
            "alerts": load_alerts_for_run(run_id, out_dir=cfg.out_dir),
            "links": _build_run_links(request, run_id),
        }
        _audit(request, status="success", status_code=200, tenant_id=tenant_for_audit, run_id=run_id)
        return response

    @app.get("/pipeline/runs/{run_id}/downloads/{artifact_name}")
    def download_artifact(run_id: str, artifact_name: str, request: Request, inline: bool = Query(False)) -> FileResponse:
        if artifact_name not in DOWNLOADABLE_ARTIFACTS:
            _audit(request, status="not_found", status_code=404, run_id=run_id, detail="artifact_not_found")
            raise HTTPException(status_code=404, detail="artifact_not_found")

        cfg = PipelineConfig.from_env()
        metadata = _require_completed_metadata(run_id, out_dir=cfg.out_dir, request=request)
        artifact_path = load_artifact_path_for_run(run_id, artifact_name=artifact_name, out_dir=cfg.out_dir)
        if not artifact_path:
            _audit(request, status="not_found", status_code=404, tenant_id=metadata.get("tenant_id"), run_id=run_id, detail="artifact_not_found")
            raise HTTPException(status_code=404, detail="artifact_not_found")

        file_path = Path(artifact_path)
        if not file_path.exists() or not file_path.is_file():
            _audit(request, status="not_found", status_code=404, tenant_id=metadata.get("tenant_id"), run_id=run_id, detail="artifact_not_found")
            raise HTTPException(status_code=404, detail="artifact_not_found")

        media_type = "application/octet-stream"
        if file_path.suffix == ".json":
            media_type = "application/json"
        elif file_path.suffix == ".md":
            media_type = "text/markdown"

        _audit(request, status="success", status_code=200, tenant_id=metadata.get("tenant_id"), run_id=run_id, detail={"artifact": artifact_name})
        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            filename=file_path.name,
            content_disposition_type="inline" if inline else "attachment",
        )

    @app.get("/auth/status")
    def auth_status(request: Request) -> dict:
        payload = {"auth_enabled": auth_enabled()}
        _audit(request, status="success", status_code=200)
        return payload

    return app


app = create_app()
