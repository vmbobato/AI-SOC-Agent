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
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>[^\]]+)\] '
    r'(?P<pid>\d+)#(?P<tid>\d+): '
    r'(?:\*(?P<conn>\d+) )?'
    r'(?P<message>.*)$'
)

CLIENT_PATTERN = re.compile(r'client: (?P<client_ip>[^,]+)')
REQUEST_PATTERN = re.compile(r'request: "(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)"')
HOST_PATTERN = re.compile(r'host: "(?P<host>[^"]+)"')

def parse_nginx_error_line(line: str) -> Optional[Dict[str, Any]]:
    m = NGINX_ERROR_PATTERN.match(line)
    if not m:
        return None

    g = m.groupdict()

    dt = datetime.strptime(g["ts"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)

    message = g["message"]
    client_match = CLIENT_PATTERN.search(message)
    request_match = REQUEST_PATTERN.search(message)
    host_match = HOST_PATTERN.search(message)

    client_ip = client_match.group("client_ip").strip() if client_match else None

    method = request_match.group("method") if request_match else None
    path = request_match.group("path") if request_match else None
    proto = request_match.group("proto") if request_match else None
    host = host_match.group("host") if host_match else None

    return {
        "timestamp": dt.isoformat(),
        "source": "nginx_error",
        "severity": g["level"].lower(),
        "client_ip": client_ip,
        "pid": int(g["pid"]),
        "tid": int(g["tid"]),
        "connection_id": int(g["conn"]) if g["conn"] else None,
        "method": method,
        "path": path,
        "proto": proto,
        "host": host,
        "message": message,
        "raw_line": line,
    }