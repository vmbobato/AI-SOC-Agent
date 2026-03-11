from __future__ import annotations

import unittest

from alert_pipeline.alerts import build_alerts


class AlertPipelineTests(unittest.TestCase):
    def test_build_alerts_deduplicates_same_case_fingerprint(self) -> None:
        cases = [
            {
                "case_id": "case-0001",
                "incident_type": "Web Enumeration Scan",
                "timestamp_start": "2026-03-05T01:00:00+00:00",
                "timestamp_end": "2026-03-05T01:02:00+00:00",
                "source_ips": ["203.0.113.10"],
                "severity": "High",
                "confidence": 0.9,
                "evidence": {"requests": 100},
                "recommended_actions": ["Block IP"],
            },
            {
                "case_id": "case-0002",
                "incident_type": "Web Enumeration Scan",
                "timestamp_start": "2026-03-05T01:00:00+00:00",
                "timestamp_end": "2026-03-05T01:02:00+00:00",
                "source_ips": ["203.0.113.10"],
                "severity": "High",
                "confidence": 0.9,
                "evidence": {"requests": 100},
                "recommended_actions": ["Block IP"],
            },
        ]

        alerts = build_alerts(cases, run_id="run-1")

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["linked_case_ids"], ["case-0001", "case-0002"])
        self.assertEqual(alerts[0]["category"], "reconnaissance")


if __name__ == "__main__":
    unittest.main()
