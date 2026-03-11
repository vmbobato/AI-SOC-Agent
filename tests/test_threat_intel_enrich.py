from __future__ import annotations

import unittest
from unittest.mock import patch

from threat_intel.enrich import enrich_cases_with_threat_intel


class ThreatIntelEnrichmentTests(unittest.TestCase):
    @patch.dict("os.environ", {}, clear=True)
    def test_public_ip_without_keys_is_marked_skipped_no_api_keys(self) -> None:
        cases = [
            {
                "incident_type": "Web Enumeration Scan",
                "source_ips": ["8.8.8.8"],
                "evidence": {},
            }
        ]

        enriched = enrich_cases_with_threat_intel(cases)
        intel = enriched[0]["threat_intel"]["8.8.8.8"]

        self.assertEqual(intel["intel_status"], "skipped_no_api_keys")
        self.assertEqual(intel["source"], [])

    @patch.dict("os.environ", {}, clear=True)
    def test_private_ip_is_not_enriched(self) -> None:
        cases = [
            {
                "incident_type": "Web Enumeration Scan",
                "source_ips": ["10.0.0.7"],
                "evidence": {},
            }
        ]

        enriched = enrich_cases_with_threat_intel(cases)
        intel = enriched[0]["threat_intel"]["10.0.0.7"]

        self.assertEqual(intel["intel_status"], "skipped_private_ip")
        self.assertEqual(intel["source"], [])


if __name__ == "__main__":
    unittest.main()
