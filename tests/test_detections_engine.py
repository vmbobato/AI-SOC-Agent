from __future__ import annotations

import unittest
from typing import Any

from detections.engine import merge_cases, run_detections, suppress_redundant_dos_cases


def _access_event(
    *,
    timestamp: str,
    client_ip: str,
    path: str,
    status: int,
    method: str = "GET",
    user_agent: str = "ua-test",
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "source": "nginx_access",
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "status": status,
        "user_agent": user_agent,
    }


def _app_event(
    *,
    timestamp: str,
    client_ip: str,
    path: str,
    reason: str,
    user_agent: str = "ua-test",
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "source": "web_stdout",
        "client_ip": client_ip,
        "path": path,
        "reason": reason,
        "user_agent": user_agent,
    }


class DetectionEngineTests(unittest.TestCase):
    def test_detects_web_enumeration_scan(self) -> None:
        events = [
            _access_event(
                timestamp=f"2026-03-05T01:00:{i:02d}+00:00",
                client_ip="203.0.113.10",
                path=f"/scan-{i}",
                status=404,
            )
            for i in range(40)
        ]

        cases = run_detections(events)
        incident_types = {case["incident_type"] for case in cases}

        self.assertIn("Web Enumeration Scan", incident_types)

    def test_detects_sensitive_file_probe(self) -> None:
        paths = ["/.env", "/.git/config", "/phpinfo", "/vendor/phpunit/eval-stdin.php", "/adminer"]
        events = [
            _access_event(
                timestamp=f"2026-03-05T01:02:{i:02d}+00:00",
                client_ip="203.0.113.20",
                path=path,
                status=404,
            )
            for i, path in enumerate(paths)
        ]

        cases = run_detections(events)
        incident_types = {case["incident_type"] for case in cases}

        self.assertIn("Sensitive File / Exploit Probe", incident_types)

    def test_detects_bruteforce_attempt(self) -> None:
        events = [
            _access_event(
                timestamp=f"2026-03-05T01:04:{i:02d}+00:00",
                client_ip="203.0.113.30",
                path="/login",
                method="POST",
                status=401,
            )
            for i in range(20)
        ]

        cases = run_detections(events)
        incident_types = {case["incident_type"] for case in cases}

        self.assertIn("Brute Force Attempt", incident_types)

    def test_detects_dos_burst(self) -> None:
        events = [
            _access_event(
                timestamp=f"2026-03-05T01:{i // 120:02d}:{i % 60:02d}+00:00",
                client_ip="203.0.113.40",
                path="/",
                status=200,
            )
            for i in range(240)
        ]

        cases = run_detections(events)
        incident_types = {case["incident_type"] for case in cases}

        self.assertIn("Traffic Burst / Possible DoS", incident_types)

    def test_detects_blocked_app_layer_probe(self) -> None:
        events = [
            _app_event(
                timestamp=f"2026-03-05T01:06:{i:02d}+00:00",
                client_ip="203.0.113.50",
                path="/secret",
                reason="secret_path",
            )
            for i in range(5)
        ]

        cases = run_detections(events)
        incident_types = {case["incident_type"] for case in cases}

        self.assertIn("Blocked App-Layer Probe", incident_types)

    def test_merge_cases_combines_adjacent_same_type_and_ip(self) -> None:
        base_case = {
            "incident_type": "Web Enumeration Scan",
            "source_ips": ["203.0.113.60"],
            "severity": "Low",
            "confidence": 0.6,
        }
        case_a = {
            **base_case,
            "timestamp_start": "2026-03-05T01:00:00+00:00",
            "timestamp_end": "2026-03-05T01:02:00+00:00",
            "evidence": {
                "requests": 50,
                "unique_paths": 45,
                "unique_ratio": 0.9,
                "404_ratio": 0.9,
                "top_paths": {"/a": 30},
                "status_counts": {404: 50},
            },
        }
        case_b = {
            **base_case,
            "timestamp_start": "2026-03-05T01:02:00+00:00",
            "timestamp_end": "2026-03-05T01:04:00+00:00",
            "severity": "Medium",
            "confidence": 0.8,
            "evidence": {
                "requests": 30,
                "unique_paths": 20,
                "unique_ratio": 0.67,
                "404_ratio": 0.85,
                "top_paths": {"/b": 10},
                "status_counts": {404: 30},
            },
        }

        merged = merge_cases([case_a, case_b], gap_minutes=0)

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["timestamp_end"], "2026-03-05T01:04:00+00:00")
        self.assertEqual(merged[0]["evidence"]["requests"], 80)
        self.assertEqual(merged[0]["severity"], "Medium")
        self.assertEqual(merged[0]["confidence"], 0.8)

    def test_suppress_redundant_dos_when_overlapping_scan(self) -> None:
        scan_case = {
            "incident_type": "Web Enumeration Scan",
            "source_ips": ["203.0.113.70"],
            "timestamp_start": "2026-03-05T01:00:00+00:00",
            "timestamp_end": "2026-03-05T01:02:00+00:00",
            "evidence": {},
        }
        dos_case = {
            "incident_type": "Traffic Burst / Possible DoS",
            "source_ips": ["203.0.113.70"],
            "timestamp_start": "2026-03-05T01:01:00+00:00",
            "timestamp_end": "2026-03-05T01:03:00+00:00",
            "evidence": {},
        }

        result = suppress_redundant_dos_cases([scan_case, dos_case])
        incident_types = [case["incident_type"] for case in result]

        self.assertEqual(incident_types, ["Web Enumeration Scan"])


if __name__ == "__main__":
    unittest.main()
