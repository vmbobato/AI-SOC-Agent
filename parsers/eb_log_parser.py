import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone

EB_ENGINE_PATTERN = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[(?P<level>[A-Z]+)\]\s+'
    r'(?P<message>.*)$'
)

def parse_eb_engine_line(line: str) -> Optional[Dict[str, Any]]:
    m = EB_ENGINE_PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()
    dt = datetime.strptime(g["ts"], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)

    return {
        "timestamp": dt.isoformat(),
        "source": "eb_engine",
        "severity": g["level"].lower(),
        "message": g["message"],
        "raw_line": line,
    }


EB_HOOKS_PATTERN = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[(?P<level>[A-Z]+)\]\s+'
    r'(?P<message>.*)$'
)

def parse_eb_hooks_line(line: str) -> Optional[Dict[str, Any]]:
    m = EB_HOOKS_PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()
    dt = datetime.strptime(g["ts"], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)

    return {
        "timestamp": dt.isoformat(),
        "source": "eb_hooks",
        "severity": g["level"].lower(),
        "message": g["message"],
        "raw_line": line,
    }