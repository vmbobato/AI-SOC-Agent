from __future__ import annotations

from fastapi import FastAPI, HTTPException

from config.settings import PipelineConfig
from pipeline.orchestrator import (
    load_alerts_for_run,
    load_campaigns_for_run,
    load_cases_for_run,
    load_run_metadata,
    run_pipeline,
)


def _run_pipeline(filepath: str) -> dict:
    result = run_pipeline(filepath, config=PipelineConfig.from_env())
    return result.to_dict()


def create_app() -> FastAPI:
    """Build and return the FastAPI application instance."""
    app = FastAPI(title="AI SOC Analyst API", version="0.2.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/pipeline/run")
    def run_pipeline_for_file(filepath: str) -> dict:
        return _run_pipeline(filepath)

    @app.get("/pipeline/runs/{run_id}")
    def get_run_metadata(run_id: str) -> dict:
        metadata = load_run_metadata(run_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="run_not_found")
        return metadata

    @app.get("/pipeline/runs/{run_id}/cases")
    def get_run_cases(run_id: str) -> dict:
        metadata = load_run_metadata(run_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="run_not_found")
        return {"run_id": run_id, "cases": load_cases_for_run(run_id)}

    @app.get("/pipeline/runs/{run_id}/campaigns")
    def get_run_campaigns(run_id: str) -> dict:
        metadata = load_run_metadata(run_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="run_not_found")
        return {"run_id": run_id, "campaigns": load_campaigns_for_run(run_id)}

    @app.get("/pipeline/runs/{run_id}/alerts")
    def get_run_alerts(run_id: str) -> dict:
        metadata = load_run_metadata(run_id)
        if not metadata:
            raise HTTPException(status_code=404, detail="run_not_found")
        return {"run_id": run_id, "alerts": load_alerts_for_run(run_id)}

    return app


app = create_app()
