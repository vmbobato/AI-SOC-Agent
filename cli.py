import hashlib, json, time
from pathlib import Path
from datetime import datetime
from collections import Counter
from reports.report_writer import write_markdown_report, write_json_cases
from ingest.log_reader import iter_log_lines
from parsers.nginx_parser import parse_nginx_access_line, parse_nginx_error_line
from parsers.eb_log_parser import parse_eb_engine_line, parse_eb_hooks_line
from parsers.web_stdout_parser import parse_web_stdout_line
from detections.engine import run_detections
from llm.incident_analyzer import analyze_cases_with_ollama
from reports.llm_report_writer import write_llm_summary


PARSERS = {
    "/var/log/nginx/access.log": parse_nginx_access_line,
    "/var/log/nginx/error.log": parse_nginx_error_line,
    "/var/log/web.stdout.log": parse_web_stdout_line,
    "/var/log/eb-engine.log": parse_eb_engine_line,
    "/var/log/eb-hooks.log": parse_eb_hooks_line,
}

CURRENT_STATE = {
    "last_file_read_path" : None,
    "last_file_read_hash" : None,
    "last_file_read_time" : None,
    "next_parser" : None
}

def parse_generic_line(line: str, source: str) -> dict:
    return {
        "timestamp": None,
        "source": source,
        "severity": "unknown",
        "message": line.strip(),
        "raw_line": line,
    }


def run(filepath):
    global LOG_PATHS, CURRENT_STATE
    # 1) Point this at your log file
    log_path = Path(filepath)

    if not log_path.exists():
        print(f"Log not found: {log_path}")
        return

    # 2) Read + parse into events
    events = []
    parsed_ok = Counter()
    parsed_fail = Counter()

    for line in iter_log_lines(log_path):
        evt = None
        line = line.rstrip("\n")
        if not line or line.startswith("----"):
            continue
        if line in PARSERS:
            CURRENT_STATE["next_parser"] = line
            continue
        parser = PARSERS.get(CURRENT_STATE["next_parser"])
        evt = parser(line) if parser else None
        if evt:
            parsed_ok[CURRENT_STATE["next_parser"]] += 1
            events.append(evt)
        else:
            parsed_fail[CURRENT_STATE["next_parser"]] += 1
            if CURRENT_STATE["next_parser"]:
                evt = parse_generic_line(line, CURRENT_STATE["next_parser"])
                events.append(evt)

    print("Parsed OK:", parsed_ok)
    print("Parsed FAIL:", parsed_fail)

    print(f"Parsed events: {len(events)}")

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
    if cases:
        try:
            start = time.time()
            llm_summary = analyze_cases_with_ollama(cases, model="llama3", timeout=1000)
            llm_summary_path = write_llm_summary(llm_summary, out_dir="reports")
            print(f"\nLLM summary saved to: {llm_summary_path}")
            end = time.time()
            print(f"\nLLM took {end - start:.2f} seconds to give an asnwer. ")
        except Exception as e:
            print(f"\nLLM analysis failed: {e}")

if __name__ == "__main__":
    running = True
    while running:
        try:
            cmd = input("\n[SOC AGENT] $ ")
            if cmd == "run":
                path = "data/last_100_log_3-5-2026/example_2.log"
                CURRENT_STATE["last_file_read_time"] = datetime.now().strftime("%Y/%m/%d -- %H:%M:%S")
                run(path)
                with open(path, "rb") as file:
                    digest = hashlib.file_digest(file, "sha256").hexdigest()
                    CURRENT_STATE['last_file_read_hash'] = digest
                CURRENT_STATE["last_file_read_path"] = path
            if cmd == "exit":
                running = False
        except KeyboardInterrupt as e:
            running = False
            
    with open(f"saved_states/{datetime.now().strftime("%Y-%m-%d_%H-%M_Saved-State")}.json", "w") as f:
        json.dump(CURRENT_STATE, f, indent=4)
    print("\nClosing Agent...\nBye!\n")