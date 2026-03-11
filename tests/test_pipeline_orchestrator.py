from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from config.settings import DetectionConfig, LLMConfig, PipelineConfig
from pipeline.orchestrator import (
    load_alerts_for_run,
    load_campaigns_for_run,
    load_cases_for_run,
    load_run_metadata,
    run_pipeline,
)


class PipelineOrchestratorTests(unittest.TestCase):
    def test_run_pipeline_generates_cases_campaigns_alerts_and_metadata(self) -> None:
        fixture = Path("tests/fixtures/sample_pipeline.log")
        self.assertTrue(fixture.exists())

        with TemporaryDirectory() as tmp_dir:
            config = PipelineConfig(
                out_dir=tmp_dir,
                detection=DetectionConfig(
                    scan_unique_paths_threshold=3,
                    scan_404_ratio_threshold=0.6,
                    brute_force_threshold=3,
                    dos_rpm_threshold=1000,
                    window_minutes=2,
                    correlation_window_minutes=60,
                ),
                llm=LLMConfig(enabled=False),
            )

            result = run_pipeline(str(fixture), config=config)

            self.assertEqual(result.status, "completed")
            self.assertGreater(result.counts["events"], 0)
            self.assertGreater(result.counts["cases"], 0)
            self.assertGreater(result.counts["campaigns"], 0)
            self.assertGreater(result.counts["alerts"], 0)

            metadata = load_run_metadata(result.run_id, out_dir=tmp_dir)
            self.assertIsNotNone(metadata)
            metadata = cast(dict, metadata)
            self.assertEqual(metadata["run_id"], result.run_id)

            cases = load_cases_for_run(result.run_id, out_dir=tmp_dir)
            campaigns = load_campaigns_for_run(result.run_id, out_dir=tmp_dir)
            alerts = load_alerts_for_run(result.run_id, out_dir=tmp_dir)

            self.assertGreater(len(cases), 0)
            self.assertGreater(len(campaigns), 0)
            self.assertGreater(len(alerts), 0)

            incident_types = {case["incident_type"] for case in cases}
            self.assertIn("Web Enumeration Scan", incident_types)
            self.assertIn("Brute Force Attempt", incident_types)
            self.assertIn("Blocked App-Layer Probe", incident_types)

            for artifact in result.artifacts.values():
                self.assertTrue(Path(artifact).exists())

    def test_file_not_found_writes_metadata(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            config = PipelineConfig(out_dir=tmp_dir, llm=LLMConfig(enabled=False))
            result = run_pipeline("tests/fixtures/does_not_exist.log", config=config)

            self.assertEqual(result.status, "file_not_found")
            self.assertIn("metadata", result.artifacts)
            metadata_path = Path(result.artifacts["metadata"])
            self.assertTrue(metadata_path.exists())

            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "file_not_found")


if __name__ == "__main__":
    unittest.main()
