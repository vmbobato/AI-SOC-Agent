from __future__ import annotations

import json
from typing import Any, Dict

from aws.pipeline import run_pipeline


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    result = run_pipeline(event=event, context=context)
    return {
        "statusCode": 200,
        "body": json.dumps(result),
    }
