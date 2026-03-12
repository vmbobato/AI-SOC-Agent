from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from config.settings import PipelineConfig
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


def _run_pipeline(filepath: str) -> dict:
    result = run_pipeline(filepath, config=PipelineConfig.from_env())
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


def _require_completed_metadata(run_id: str, out_dir: str) -> Dict[str, Any]:
    metadata = load_run_metadata(run_id, out_dir=out_dir)
    if metadata:
        return metadata

    status_payload = load_run_status(run_id, out_dir=out_dir)
    if status_payload:
        raise HTTPException(status_code=409, detail=status_payload)

    raise HTTPException(status_code=404, detail="run_not_found")


def create_app() -> FastAPI:
    """Build and return the FastAPI application instance."""
    app = FastAPI(title="AI SOC Analyst API", version="0.3.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/pipeline/run")
    def run_pipeline_for_file(filepath: str, request: Request) -> dict:
        payload = _run_pipeline(filepath)
        run_id = payload.get("run_id")
        if isinstance(run_id, str):
            payload["links"] = _build_run_links(request, run_id)
            payload["download_links"] = {
                name: f"{str(request.base_url).rstrip('/')}/pipeline/runs/{run_id}/downloads/{name}"
                for name in (payload.get("artifacts") or {}).keys()
                if name in DOWNLOADABLE_ARTIFACTS
            }
        return payload

    @app.post("/pipeline/submit")
    def submit_pipeline_job_from_upload(payload: SubmitLogPayload, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        try:
            normalized_tenant = normalize_tenant_id(payload.tenant_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        content = payload.log_content.encode("utf-8")
        if not content:
            raise HTTPException(status_code=400, detail="empty_upload")

        run_id = new_run_id()
        saved_path = persist_uploaded_log(
            run_id,
            normalized_tenant,
            payload.filename,
            content,
            uploads_dir=cfg.uploads_dir,
        )

        # Queue a job against the saved uploaded file using the same run_id.
        submit_pipeline_job(filepath=str(saved_path), config=cfg, run_id=run_id)

        response = {
            "run_id": run_id,
            "status": "queued",
            "filepath": str(saved_path),
            "links": _build_run_links(request, run_id),
        }
        return response

    @app.get("/pipeline/runs/{run_id}")
    def get_run_metadata(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        metadata = load_run_metadata(run_id, out_dir=cfg.out_dir)
        if metadata:
            payload = dict(metadata)
            payload["links"] = _build_run_links(request, run_id)
            payload["download_links"] = _build_download_links(request, payload)
            return payload

        status_payload = load_run_status(run_id, out_dir=cfg.out_dir)
        if status_payload:
            payload = dict(status_payload)
            payload["links"] = _build_run_links(request, run_id)
            return payload

        raise HTTPException(status_code=404, detail="run_not_found")

    @app.get("/pipeline/runs/{run_id}/cases")
    def get_run_cases(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        _require_completed_metadata(run_id, out_dir=cfg.out_dir)
        return {"run_id": run_id, "cases": load_cases_for_run(run_id, out_dir=cfg.out_dir), "links": _build_run_links(request, run_id)}

    @app.get("/pipeline/runs/{run_id}/campaigns")
    def get_run_campaigns(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        _require_completed_metadata(run_id, out_dir=cfg.out_dir)
        return {
            "run_id": run_id,
            "campaigns": load_campaigns_for_run(run_id, out_dir=cfg.out_dir),
            "links": _build_run_links(request, run_id),
        }

    @app.get("/pipeline/runs/{run_id}/alerts")
    def get_run_alerts(run_id: str, request: Request) -> dict:
        cfg = PipelineConfig.from_env()
        _require_completed_metadata(run_id, out_dir=cfg.out_dir)
        return {"run_id": run_id, "alerts": load_alerts_for_run(run_id, out_dir=cfg.out_dir), "links": _build_run_links(request, run_id)}

    @app.get("/pipeline/runs/{run_id}/downloads/{artifact_name}")
    def download_artifact(run_id: str, artifact_name: str, inline: bool = Query(False)) -> FileResponse:
        if artifact_name not in DOWNLOADABLE_ARTIFACTS:
            raise HTTPException(status_code=404, detail="artifact_not_found")

        cfg = PipelineConfig.from_env()
        artifact_path = load_artifact_path_for_run(run_id, artifact_name=artifact_name, out_dir=cfg.out_dir)
        if not artifact_path:
            raise HTTPException(status_code=404, detail="artifact_not_found")

        file_path = Path(artifact_path)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="artifact_not_found")

        media_type = "application/octet-stream"
        if file_path.suffix == ".json":
            media_type = "application/json"
        elif file_path.suffix == ".md":
            media_type = "text/markdown"

        return FileResponse(
            path=str(file_path),
            media_type=media_type,
            filename=file_path.name,
            content_disposition_type="inline" if inline else "attachment",
        )

    return app


app = create_app()
