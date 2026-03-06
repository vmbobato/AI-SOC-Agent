import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone

SYSLOG_APP_PATTERN = re.compile(
    r'^(?P<syslog_ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<service>[a-zA-Z0-9_.-]+)\[(?P<pid>\d+)\]:\s+'
    r'\[(?P<app_ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\]\s+'
    r'(?P<level>[A-Z]+)\s+in\s+(?P<module>[a-zA-Z0-9_.-]+):\s+'
    r'(?P<message>.*)$'
)

KV_TAIL_PATTERN = re.compile(
    r'^(?P<summary>.*?)'
    r'(?:\s+method=(?P<method>[A-Z]+))?'
    r'(?:\s+path=(?P<path>\S+))?'
    r'(?:\s+ip=(?P<client_ip>\S+))?'
    r'(?:\s+ua=(?P<user_agent>.*?))?'
    r'(?:\s+reason=(?P<reason>\S+))?'
    r'(?:\s+sample=(?P<sample>\S+))?$'
)

def parse_web_stdout_line(line: str) -> Optional[Dict[str, Any]]:
    m = SYSLOG_APP_PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()

    dt = datetime.strptime(g["app_ts"], "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)

    msg = g["message"].strip()
    km = KV_TAIL_PATTERN.match(msg)

    summary = msg
    method = path = client_ip = user_agent = reason = sample = None

    if km:
        kd = km.groupdict()
        summary = (kd.get("summary") or "").strip()
        method = kd.get("method")
        path = kd.get("path")
        client_ip = kd.get("client_ip")
        user_agent = kd.get("user_agent")
        reason = kd.get("reason")
        sample = kd.get("sample")

        if user_agent:
            user_agent = user_agent.strip()

    return {
        "timestamp": dt.isoformat(),
        "source": "web_stdout",
        "severity": g["level"].lower(),
        "host": g["host"],
        "service": g["service"],
        "pid": int(g["pid"]),
        "module": g["module"],
        "message": summary,
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "reason": reason,
        "sample": sample,
        "raw_line": line,
    }