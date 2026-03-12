from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from api.app import CreateApiKeyPayload, create_app


def _request(
    path: str,
    *,
    method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "root_path": "",
            "query_string": b"",
            "headers": headers or [],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        }
    )


def _auth_headers(token: str) -> list[tuple[bytes, bytes]]:
    return [(b"authorization", f"Bearer {token}".encode("utf-8"))]


def _admin_headers(token: str) -> list[tuple[bytes, bytes]]:
    return [(b"x-admin-token", token.encode("utf-8"))]


class ApiAuthTests(unittest.TestCase):
    def test_per_tenant_api_key_enforces_tenant_isolation(self) -> None:
        fixture_path = Path("tests/fixtures/sample_pipeline.log").resolve()
        self.assertTrue(fixture_path.exists())

        with TemporaryDirectory() as tmp_dir:
            env = {
                "SOC_API_AUTH_ENABLED": "true",
                "SOC_ADMIN_TOKEN": "admin-secret",
                "SOC_API_KEYS_PATH": f"{tmp_dir}/api_keys.json",
                "SOC_AUDIT_LOG_PATH": f"{tmp_dir}/logs/api_audit.log",
                "SOC_REPORTS_DIR": f"{tmp_dir}/reports",
                "SOC_UPLOADS_DIR": f"{tmp_dir}/uploads",
                "SOC_LLM_ENABLED": "false",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                create_key_route = next(route for route in app.routes if getattr(route, "path", "") == "/auth/keys/create")
                run_route = next(route for route in app.routes if getattr(route, "path", "") == "/pipeline/run")
                metadata_route = next(route for route in app.routes if getattr(route, "path", "") == "/pipeline/runs/{run_id}")

                create_key_route = cast(Any, create_key_route)
                run_route = cast(Any, run_route)
                metadata_route = cast(Any, metadata_route)

                acme_key_payload = create_key_route.endpoint(
                    payload=CreateApiKeyPayload(tenant_id="acme", label="acme-key"),
                    request=_request("/auth/keys/create", method="POST", headers=_admin_headers("admin-secret")),
                )
                bravo_key_payload = create_key_route.endpoint(
                    payload=CreateApiKeyPayload(tenant_id="bravo", label="bravo-key"),
                    request=_request("/auth/keys/create", method="POST", headers=_admin_headers("admin-secret")),
                )

                acme_key = acme_key_payload["api_key"]
                bravo_key = bravo_key_payload["api_key"]

                run_payload = run_route.endpoint(
                    filepath=str(fixture_path),
                    request=_request("/pipeline/run", method="POST", headers=_auth_headers(acme_key)),
                    tenant_id=None,
                )
                run_id = run_payload["run_id"]
                self.assertEqual(run_payload["tenant_id"], "acme")

                own_tenant_view = metadata_route.endpoint(
                    run_id=run_id,
                    request=_request(f"/pipeline/runs/{run_id}", headers=_auth_headers(acme_key)),
                )
                self.assertEqual(own_tenant_view["tenant_id"], "acme")

                with self.assertRaises(HTTPException):
                    metadata_route.endpoint(
                        run_id=run_id,
                        request=_request(f"/pipeline/runs/{run_id}", headers=_auth_headers(bravo_key)),
                    )

                audit_path = Path(env["SOC_AUDIT_LOG_PATH"])
                self.assertTrue(audit_path.exists())
                audit_text = audit_path.read_text(encoding="utf-8")
                self.assertIn("/pipeline/run", audit_text)

    def test_duplicate_active_key_for_same_tenant_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            env = {
                "SOC_API_AUTH_ENABLED": "true",
                "SOC_ADMIN_TOKEN": "admin-secret",
                "SOC_API_KEYS_PATH": f"{tmp_dir}/api_keys.json",
            }
            with patch.dict(os.environ, env, clear=False):
                app = create_app()
                create_key_route = next(route for route in app.routes if getattr(route, "path", "") == "/auth/keys/create")
                create_key_route = cast(Any, create_key_route)

                first = create_key_route.endpoint(
                    payload=CreateApiKeyPayload(tenant_id="Acme", label="first"),
                    request=_request("/auth/keys/create", method="POST", headers=_admin_headers("admin-secret")),
                )
                self.assertIn("api_key", first)

                with self.assertRaises(HTTPException) as ctx:
                    create_key_route.endpoint(
                        payload=CreateApiKeyPayload(tenant_id="acme", label="second"),
                        request=_request("/auth/keys/create", method="POST", headers=_admin_headers("admin-secret")),
                    )
                self.assertEqual(ctx.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
