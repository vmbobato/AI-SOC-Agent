from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(slots=True)
class DetectionConfig:
    scan_unique_paths_threshold: int = 40
    scan_404_ratio_threshold: float = 0.85
    brute_force_threshold: int = 20
    dos_rpm_threshold: int = 120
    window_minutes: int = 2
    correlation_window_minutes: int = 60


@dataclass(slots=True)
class LLMConfig:
    enabled: bool = True
    provider: str = "openai"  # openai | ollama
    model: str = "gpt-4.1"  # llama3
    timeout_seconds: int = 500


@dataclass(slots=True)
class PipelineConfig:
    out_dir: str = "reports"
    uploads_dir: str = "uploads"
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        enabled = os.getenv("SOC_LLM_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
        return cls(
            out_dir=os.getenv("SOC_REPORTS_DIR", "reports"),
            uploads_dir=os.getenv("SOC_UPLOADS_DIR", "uploads"),
            detection=DetectionConfig(
                scan_unique_paths_threshold=int(os.getenv("SOC_SCAN_UNIQUE_PATHS_THRESHOLD", "40")),
                scan_404_ratio_threshold=float(os.getenv("SOC_SCAN_404_RATIO_THRESHOLD", "0.85")),
                brute_force_threshold=int(os.getenv("SOC_BRUTE_FORCE_THRESHOLD", "20")),
                dos_rpm_threshold=int(os.getenv("SOC_DOS_RPM_THRESHOLD", "120")),
                window_minutes=int(os.getenv("SOC_WINDOW_MINUTES", "2")),
                correlation_window_minutes=int(os.getenv("SOC_CORRELATION_WINDOW_MINUTES", "60")),
            ),
            llm=LLMConfig(
                enabled=enabled,
                provider=os.getenv("SOC_LLM_PROVIDER", "openai").strip().lower(),
                model=os.getenv("SOC_LLM_MODEL", "gpt-4.1").strip(),
                timeout_seconds=int(os.getenv("SOC_LLM_TIMEOUT_SECONDS", "500")),
            ),
        )
