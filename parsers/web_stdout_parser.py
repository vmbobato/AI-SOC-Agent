import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone

WEB_STDOUT_PATTERNS = [
    re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+'
        r'(?P<message>.*)$'
    ),
    re.compile(
        r'^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+\-]\d{4})\]\s+'
        r'\[(?P<pid>\d+)\]\s+'
        r'\[(?P<level>[A-Z]+)\]\s+'
        r'(?P<message>.*)$'
    ),
]

def parse_web_stdout_line(line: str) -> Optional[Dict[str, Any]]:
    for pattern in WEB_STDOUT_PATTERNS:
        m = pattern.match(line)
        if not m:
            continue

        g = m.groupdict()

        dt = None
        if "," in g["ts"]:
            dt = datetime.strptime(g["ts"], "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)
        else:
            dt = datetime.strptime(g["ts"], "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)

        return {
            "timestamp": dt.isoformat(),
            "source": "web_stdout",
            "severity": g["level"].lower(),
            "pid": int(g["pid"]) if g.get("pid") else None,
            "message": g["message"],
            "raw_line": line,
        }

    return None

def parse_web_stdout_line_fallback(line: str) -> Dict[str, Any]:
    return {
        "timestamp": None,
        "source": "web_stdout",
        "severity": "info",
        "message": line.strip(),
        "raw_line": line,
    }