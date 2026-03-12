from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from unittest.mock import patch

from starlette.requests import Request

from api.app import SubmitLogPayload, create_app


def _request(path: str = "/") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        }
    )


class ApiAppTests(unittest.TestCase):
    @patch("api.app._run_pipeline")
    def test_pipeline_run_delegates_to_existing_entrypoint(self, mock_run_pipeline) -> None:
        mock_run_pipeline.return_value = {
            "run_id": "run-1",
            "status": "completed",
            "artifacts": {"cases": "reports/cases_test.json"},
        }
        app = create_app()
        run_route = next(route for route in app.routes if getattr(route, "path", "") == "/pipeline/run")
        run_route = cast(Any, run_route)

        response_payload = run_route.endpoint(filepath="data/sample.log", request=_request("/pipeline/run"))

        self.assertEqual(response_payload["run_id"], "run-1")
        self.assertIn("links", response_payload)
        self.assertIn("download_links", response_payload)
        mock_run_pipeline.assert_called_once_with("data/sample.log")

    def test_health_returns_ok(self) -> None:
        app = create_app()
        health_route = next(route for route in app.routes if getattr(route, "path", "") == "/health")
        health_route = cast(Any, health_route)
        response_payload = health_route.endpoint()
        self.assertEqual(response_payload, {"status": "ok"})

    def test_pipeline_run_returns_download_link_payload(self) -> None:
        fixture_path = Path("tests/fixtures/sample_pipeline.log").resolve()
        self.assertTrue(fixture_path.exists())

        with TemporaryDirectory() as tmp_dir:
            with patch.dict(
                os.environ,
                {
                    "SOC_REPORTS_DIR": tmp_dir,
                    "SOC_UPLOADS_DIR": f"{tmp_dir}/uploads",
                    "SOC_LLM_ENABLED": "false",
                },
                clear=False,
            ):
                app = create_app()
                run_route = next(
                    route for route in app.routes if getattr(route, "path", "") == "/pipeline/run"
                )
                run_route = cast(Any, run_route)
                response_payload = run_route.endpoint(
                    filepath=str(fixture_path), request=_request("/pipeline/run")
                )

                self.assertEqual(response_payload["status"], "completed")
                self.assertIn("download_links", response_payload)
                self.assertIn("cases", response_payload["download_links"])

                run_id = response_payload["run_id"]
                download_route = next(
                    route
                    for route in app.routes
                    if getattr(route, "path", "") == "/pipeline/runs/{run_id}/downloads/{artifact_name}"
                )
                download_route = cast(Any, download_route)
                file_response = download_route.endpoint(run_id=run_id, artifact_name="cases", inline=False)
                self.assertTrue(Path(file_response.path).exists())
                self.assertIn("attachment", file_response.headers.get("content-disposition", ""))

    def test_pipeline_submit_upload_async_and_download(self) -> None:
        fixture_path = Path("tests/fixtures/sample_pipeline.log").resolve()
        self.assertTrue(fixture_path.exists())

        with TemporaryDirectory() as tmp_dir:
            with patch.dict(
                os.environ,
                {
                    "SOC_REPORTS_DIR": tmp_dir,
                    "SOC_UPLOADS_DIR": f"{tmp_dir}/uploads",
                    "SOC_LLM_ENABLED": "false",
                },
                clear=False,
            ):
                app = create_app()
                submit_route = next(
                    route for route in app.routes if getattr(route, "path", "") == "/pipeline/submit"
                )
                submit_route = cast(Any, submit_route)
                status_route = next(
                    route
                    for route in app.routes
                    if getattr(route, "path", "") == "/pipeline/runs/{run_id}"
                )
                status_route = cast(Any, status_route)
                download_route = next(
                    route
                    for route in app.routes
                    if getattr(route, "path", "") == "/pipeline/runs/{run_id}/downloads/{artifact_name}"
                )
                download_route = cast(Any, download_route)

                submit_payload = submit_route.endpoint(
                    payload=SubmitLogPayload(
                        tenant_id="acme",
                        filename="sample_pipeline.log",
                        log_content=fixture_path.read_text(encoding="utf-8"),
                    ),
                    request=_request("/pipeline/submit"),
                )

                self.assertEqual(submit_payload["status"], "queued")
                run_id = submit_payload["run_id"]

                latest_status = {}
                for _ in range(60):
                    latest_status = status_route.endpoint(run_id=run_id, request=_request(f"/pipeline/runs/{run_id}"))
                    if latest_status.get("status") == "completed":
                        break
                    time.sleep(0.1)

                self.assertEqual(latest_status.get("status"), "completed")
                self.assertIn("download_links", latest_status)
                self.assertIn("cases", latest_status["download_links"])

                file_response = download_route.endpoint(run_id=run_id, artifact_name="cases", inline=False)
                self.assertTrue(Path(file_response.path).exists())
                self.assertIn("attachment", file_response.headers.get("content-disposition", ""))


if __name__ == "__main__":
    unittest.main()
