from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib import request, error

from llm.incident_analyzer import build_soc_prompt


OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


def summarize_cases_with_openai(
    cases: List[Dict[str, Any]],
    api_key: str,
    model: str,
    timeout_seconds: int = 90,
) -> str:
    if not cases:
        return "## AI SOC Analyst Summary\n\nNo incidents to analyze."

    prompt = build_soc_prompt(cases)
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a concise SOC analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        OPENAI_CHAT_COMPLETIONS_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API error: {exc.code} {details}") from exc

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("OpenAI API returned no choices")

    message = choices[0].get("message") or {}
    content = message.get("content")
    if not content:
        raise RuntimeError("OpenAI API returned empty content")

    return content.strip()
