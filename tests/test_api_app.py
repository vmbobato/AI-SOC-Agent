from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import HTTPException
from typing import Any, cast

from api.app import create_app


class ApiAppTests(unittest.TestCase):
    @patch("api.app._run_pipeline")
    def test_pipeline_run_delegates_to_existing_entrypoint(self, mock_run_pipeline) -> None:
        mock_run_pipeline.return_value = {"run_id": "run-1", "status": "completed"}
        app = create_app()
        run_route = next(route for route in app.routes if getattr(route, "path", "") == "/pipeline/run")
        run_route = cast(Any, run_route)
        response_payload = run_route.endpoint(filepath="data/sample.log")
        self.assertEqual(response_payload["run_id"], "run-1")
        mock_run_pipeline.assert_called_once_with("data/sample.log")

    def test_health_returns_ok(self) -> None:
        app = create_app()
        health_route = next(route for route in app.routes if getattr(route, "path", "") == "/health")
        health_route = cast(Any, health_route)
        response_payload = health_route.endpoint()
        self.assertEqual(response_payload, {"status": "ok"})

    @patch("api.app.load_run_metadata")
    def test_get_run_metadata_not_found(self, mock_load_metadata) -> None:
        mock_load_metadata.return_value = None
        app = create_app()
        route = next(route for route in app.routes if getattr(route, "path", "") == "/pipeline/runs/{run_id}")
        route = cast(Any, route)
        with self.assertRaises(HTTPException):
            route.endpoint(run_id="missing")


if __name__ == "__main__":
    unittest.main()
