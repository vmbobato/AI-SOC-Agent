from __future__ import annotations

from dataclasses import dataclass
import os
from typing import List


@dataclass(frozen=True)
class LogSourceConfig:
    source_name: str
    log_group_name: str
    filter_pattern: str | None = None


@dataclass(frozen=True)
class AwsPipelineConfig:
    region: str
    window_minutes: int
    s3_bucket: str
    s3_prefix: str
    ses_sender: str
    ses_recipients: List[str]
    openai_api_key: str
    openai_model: str
    log_sources: List[LogSourceConfig]

    @staticmethod
    def _required(name: str) -> str:
        value = os.getenv(name, "").strip()
        if not value:
            raise ValueError(f"Missing required env var: {name}")
        return value

    @staticmethod
    def _optional_int(name: str, default: int) -> int:
        raw = os.getenv(name, "").strip()
        if not raw:
            return default
        return int(raw)

    @classmethod
    def from_env(cls) -> "AwsPipelineConfig":
        recipients_raw = cls._required("SES_RECIPIENTS")
        recipients = [item.strip() for item in recipients_raw.split(",") if item.strip()]
        if not recipients:
            raise ValueError("SES_RECIPIENTS must contain at least one email")

        log_sources = [
            LogSourceConfig(
                source_name="nginx_access",
                log_group_name=cls._required("LOG_GROUP_NGINX_ACCESS"),
                filter_pattern=os.getenv("FILTER_NGINX_ACCESS", "").strip() or None,
            ),
            LogSourceConfig(
                source_name="nginx_error",
                log_group_name=cls._required("LOG_GROUP_NGINX_ERROR"),
                filter_pattern=os.getenv("FILTER_NGINX_ERROR", "").strip() or None,
            ),
            LogSourceConfig(
                source_name="web_stdout",
                log_group_name=cls._required("LOG_GROUP_WEB_STDOUT"),
                filter_pattern=os.getenv("FILTER_WEB_STDOUT", "").strip() or None,
            ),
        ]

        return cls(
            region=os.getenv("AWS_REGION", "us-east-1"),
            window_minutes=cls._optional_int("WINDOW_MINUTES", 60),
            s3_bucket=cls._required("REPORTS_BUCKET"),
            s3_prefix=os.getenv("REPORTS_PREFIX", "soc-reports").strip("/"),
            ses_sender=cls._required("SES_SENDER"),
            ses_recipients=recipients,
            openai_api_key=cls._required("OPENAI_API_KEY"),
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            log_sources=log_sources,
        )
