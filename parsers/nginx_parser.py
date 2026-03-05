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