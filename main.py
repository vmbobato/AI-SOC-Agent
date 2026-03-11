from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from config.settings import PipelineConfig
from pipeline.orchestrator import run_pipeline


CURRENT_STATE: Dict[str, Any] = {
    "last_file_read_path": None,
    "last_file_read_hash": None,
    "last_file_read_time": None,
    "last_run_id": None,
}


def run(filepath: str) -> Dict[str, Any]:
    config = PipelineConfig.from_env()
    result = run_pipeline(filepath, config=config)

    if result.status != "completed":
        print(f"Pipeline status: {result.status}")
        return result.to_dict()

    print(f"Run ID: {result.run_id}")
    print(f"Parsed events: {result.counts.get('events', 0)}")
    print(f"Detected cases: {result.counts.get('cases', 0)}")
    print(f"Correlated campaigns: {result.counts.get('campaigns', 0)}")
    print(f"Generated alerts: {result.counts.get('alerts', 0)}")

    for name, path in result.artifacts.items():
        print(f"{name}: {path}")

    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"- {error}")

    CURRENT_STATE["last_file_read_path"] = filepath
    CURRENT_STATE["last_file_read_hash"] = result.input_sha256
    CURRENT_STATE["last_file_read_time"] = datetime.now(timezone.utc).isoformat()
    CURRENT_STATE["last_run_id"] = result.run_id

    return result.to_dict()


def _save_state() -> None:
    saved_state_dir = Path("saved_states")
    saved_state_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M_Saved-State")
    state_path = saved_state_dir / f"{timestamp}.json"
    state_path.write_text(json.dumps(CURRENT_STATE, indent=2), encoding="utf-8")


if __name__ == "__main__":
    running = True
    default_path = "data/last_100_log_3-5-2026/example_2.log"

    while running:
        try:
            cmd = input("\n[SOC AGENT] $ ").strip()
            if cmd == "run":
                run(default_path)
            elif cmd.startswith("run "):
                custom_path = cmd.split(" ", maxsplit=1)[1].strip()
                run(custom_path)
            elif cmd == "exit":
                running = False
        except KeyboardInterrupt:
            running = False

    _save_state()
    print("\nClosing Agent...\nBye!\n")
