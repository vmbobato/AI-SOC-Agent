import re
import json
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
    message = g["message"].strip()

    event = {
        "timestamp": dt.isoformat(),
        "source": "eb_engine",
        "severity": g["level"].lower(),
        "message": message,
        "raw_line": line,
    }

    if message.startswith("Running command: "):
        event["event_type"] = "command"
        event["command"] = message.removeprefix("Running command: ").strip()

    elif message.startswith("Executing instruction: "):
        event["event_type"] = "instruction"
        event["instruction"] = message.removeprefix("Executing instruction: ").strip()

    elif message.startswith("Engine command: "):
        event["event_type"] = "engine_command"
        event["engine_command"] = message.removeprefix("Engine command: ").strip()

    elif message.startswith("CommandService Response: "):
        event["event_type"] = "command_service_response"
        payload = message.removeprefix("CommandService Response: ").strip()
        try:
            event["response_json"] = json.loads(payload)
        except json.JSONDecodeError:
            event["response_json"] = None
            event["response_raw"] = payload

    else:
        event["event_type"] = "log"

    return event

EB_HOOKS_PATTERN = re.compile(
    r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[(?P<level>[A-Z]+)\]\s+'
    r'(?P<message>.*)$'
)

def parse_eb_hooks_line(line: str) -> Optional[Dict[str, Any]]:
    m = EB_HOOKS_PATTERN.match(line)
    if m:
        g = m.groupdict()
        dt = datetime.strptime(g["ts"], "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
        message = g["message"].strip()

        event = {
            "timestamp": dt.isoformat(),
            "source": "eb_hooks",
            "severity": g["level"].lower(),
            "message": message,
            "raw_line": line,
        }

        if message.startswith("Running command: "):
            event["event_type"] = "command"
            event["command"] = message.removeprefix("Running command: ").strip()
        else:
            event["event_type"] = "log"

        return event

    # Fallback for multiline command output lines with no timestamp prefix
    stripped = line.strip()
    if stripped:
        return {
            "timestamp": None,
            "source": "eb_hooks",
            "severity": "info",
            "event_type": "output",
            "message": stripped,
            "raw_line": line,
        }

    return None