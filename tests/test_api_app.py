from __future__ import annotations

import unittest
from unittest.mock import patch

from api.app import create_app


class ApiAppTests(unittest.TestCase):
    @patch("api.app._run_pipeline")
    def test_pipeline_run_delegates_to_existing_entrypoint(self, mock_run_pipeline) -> None:
        app = create_app()
        run_route = next(route for route in app.routes if route.path == "/pipeline/run")
        response_payload = run_route.endpoint(filepath="data/sample.log")
        self.assertEqual(response_payload["filepath"], "data/sample.log")
        mock_run_pipeline.assert_called_once_with("data/sample.log")

    def test_health_returns_ok(self) -> None:
        app = create_app()
        health_route = next(route for route in app.routes if route.path == "/health")
        response_payload = health_route.endpoint()
        self.assertEqual(response_payload, {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
