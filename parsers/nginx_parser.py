import re
from typing import Optional, Dict, Any
from datetime import datetime, timezone


PATTERN = re.compile(
    r'^(?P<remote_addr>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"'
    r'(?:\s+"(?P<real_ip>[^"]+)")?$'
)

def parse_nginx_access_line(line: str) -> Optional[Dict[str, Any]]:
    m = PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()

    # Nginx timestamp format: 04/Mar/2026:01:01:03 +0000
    dt = datetime.strptime(g["ts"], "%d/%b/%Y:%H:%M:%S %z")
    dt_utc = dt.astimezone(timezone.utc)

    status = int(g["status"])
    bytes_sent = int(g["bytes"]) if (g["bytes"] or "").isdigit() else 0

    remote_addr = g["remote_addr"]
    real_ip = g.get("real_ip")
    client_ip = real_ip or remote_addr

    return {
        "timestamp": dt_utc.isoformat(),
        "source": "nginx_access",
        "client_ip": client_ip,
        "remote_addr": remote_addr,
        "real_ip": real_ip,
        "method": g["method"],
        "path": g["path"],
        "proto": g["proto"],
        "status": status,
        "bytes": bytes_sent,
        "referrer": g["referrer"],
        "user_agent": g["ua"],
        "raw_line": line,
    }
    


NGINX_ERROR_PATTERN = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>[^\]]+)\]\s+'
    r'(?P<pid>\d+)#(?P<tid>\d+):\s+'
    r'(?:\*(?P<conn>\d+)\s+)?'
    r'(?P<message>.*)$'
)

CLIENT_RE = re.compile(r'client:\s*(?P<client_ip>[^,]+)')
REQUEST_RE = re.compile(r'request:\s*"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"')
UPSTREAM_RE = re.compile(r'upstream:\s*"(?P<upstream>[^"]+)"')
HOST_RE = re.compile(r'host:\s*"(?P<host>[^"]+)"')
REFERRER_RE = re.compile(r'referrer:\s*"(?P<referrer>[^"]+)"')

def parse_nginx_error_line(line: str) -> Optional[Dict[str, Any]]:
    m = NGINX_ERROR_PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()
    dt = datetime.strptime(g["ts"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    message = g["message"].strip()

    client_ip = None
    method = None
    path = None
    proto = None
    upstream = None
    host = None
    referrer = None

    cm = CLIENT_RE.search(message)
    if cm:
        client_ip = cm.group("client_ip").strip()

    rm = REQUEST_RE.search(message)
    if rm:
        method = rm.group("method")
        path = rm.group("path")
        proto = rm.group("proto")

    um = UPSTREAM_RE.search(message)
    if um:
        upstream = um.group("upstream")

    hm = HOST_RE.search(message)
    if hm:
        host = hm.group("host")

    refm = REFERRER_RE.search(message)
    if refm:
        referrer = refm.group("referrer")

    return {
        "timestamp": dt.isoformat(),
        "source": "nginx_error",
        "severity": g["level"].lower(),
        "pid": int(g["pid"]),
        "tid": int(g["tid"]),
        "connection_id": int(g["conn"]) if g["conn"] else None,
        "message": message,
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "proto": proto,
        "upstream": upstream,
        "host": host,
        "referrer": referrer,
        "raw_line": line,
    }