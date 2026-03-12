from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo


APP_TIMEZONE_NAME = "America/Chicago"
APP_TIMEZONE = ZoneInfo(APP_TIMEZONE_NAME)


def now_local() -> datetime:
    return datetime.now(APP_TIMEZONE)


def now_local_iso() -> str:
    return now_local().isoformat()


def local_tag() -> str:
    return now_local().strftime("%Y%m%d_%H%M%S_ct")


def local_tag_precise() -> str:
    return now_local().strftime("%Y%m%d_%H%M%S_%f_ct")


def parse_iso_datetime(value: str) -> Optional[datetime]:
    raw = value.strip()
    if not raw:
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def iso_to_local(value: str) -> str:
    parsed = parse_iso_datetime(value)
    if not parsed:
        return value
    return parsed.astimezone(APP_TIMEZONE).isoformat()
