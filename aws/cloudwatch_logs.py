from __future__ import annotations

from typing import List, Set


def fetch_log_messages(
    logs_client,
    log_group_name: str,
    start_time_ms: int,
    end_time_ms: int,
    filter_pattern: str | None = None,
    max_events: int = 20000,
) -> List[str]:
    """Fetch CloudWatch log messages for a time range from one log group."""
    params = {
        "logGroupName": log_group_name,
        "startTime": start_time_ms,
        "endTime": end_time_ms,
        "interleaved": True,
    }
    if filter_pattern:
        params["filterPattern"] = filter_pattern

    messages: List[str] = []
    seen_event_ids: Set[str] = set()

    paginator = logs_client.get_paginator("filter_log_events")
    for page in paginator.paginate(**params):
        for event in page.get("events", []):
            event_id = event.get("eventId")
            if event_id and event_id in seen_event_ids:
                continue
            if event_id:
                seen_event_ids.add(event_id)

            message = (event.get("message") or "").rstrip("\n")
            if message:
                messages.append(message)

            if len(messages) >= max_events:
                return messages

    return messages
