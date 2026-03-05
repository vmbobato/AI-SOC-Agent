from pathlib import Path
from ingest.log_reader import iter_log_lines
from parsers.nginx_parser import parse_nginx_access_line

events = []
for line in iter_log_lines(Path("data/log-2_4_26/nginx/access.log")):
    e = parse_nginx_access_line(line)
    if e:
        events.append(e)

# Filter ONLY your attacker IP
attacker = [e for e in events if e["client_ip"] == "84.247.182.240"]

print("events total:", len(events))
print("attacker events:", len(attacker))

paths = set(e["path"] for e in attacker)
ratio_404 = sum(1 for e in attacker if e["status"] == 404) / max(1, len(attacker))

print("attacker unique paths:", len(paths))
print("attacker 404 ratio:", ratio_404)