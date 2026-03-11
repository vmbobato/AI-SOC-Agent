from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI


def _run_pipeline(filepath: str) -> None:
    from main import run as run_pipeline
    run_pipeline(filepath)


def create_app() -> FastAPI:
    """Build and return the FastAPI application instance."""
    app = FastAPI(title="AI SOC Analyst API", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/pipeline/run")
    def run_pipeline_for_file(filepath: str) -> dict[str, str]:
        # Thin wrapper: preserve existing behavior by delegating to current pipeline entrypoint.
        _run_pipeline(filepath)
        exists = Path(filepath).exists()
        return {
            "status": "completed" if exists else "file_not_found",
            "filepath": filepath,
        }

    return app


app = create_app()
