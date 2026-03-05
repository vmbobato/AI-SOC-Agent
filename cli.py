from pathlib import Path
from reports.report_writer import write_markdown_report, write_json_cases
from ingest.log_reader import iter_log_lines
from parsers.nginx_parser import parse_nginx_access_line
from detections.engine import run_detections

def main():
    # 1) Point this at your access.log
    log_path = Path("data/log-2_4_26/nginx/access.log")

    if not log_path.exists():
        print(f"Log not found: {log_path}")
        return

    # 2) Read + parse into events
    events = []
    for line in iter_log_lines(log_path):
        evt = parse_nginx_access_line(line)
        if evt:
            events.append(evt)

    print(f"Parsed events: {len(events)}")

    # 3) Run detections
    cases = run_detections(
        events,
        scan_unique_paths_threshold=40,
        scan_404_ratio_threshold=0.85,
        brute_force_threshold=20,
        dos_rpm_threshold=120,
        window_minutes=2,
    )
    report_path = write_markdown_report(cases, out_dir="reports")
    json_path = write_json_cases(cases, out_dir="reports")
    print(f"\nReport saved to: {report_path}")
    print(f"Cases saved to:  {json_path}")
    print(f"Detected cases: {len(cases)}")
    for i, c in enumerate(cases[:5], 1):
        print(f"\nCase {i}: {c['incident_type']}")
        print(f"  IPs: {c['source_ips']}")
        print(f"  Window: {c['timestamp_start']} -> {c['timestamp_end']}")
        print(f"  Severity: {c.get('severity')}  Confidence: {c.get('confidence')}")
        print(f"  Evidence keys: {list((c.get('evidence') or {}).keys())}")

if __name__ == "__main__":
    main()