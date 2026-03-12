from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol


@dataclass(slots=True)
class ParseResult:
    success: bool
    parser_name: str
    confidence: float
    event_family: Optional[str]
    fields: Dict[str, Any]
    error: Optional[str] = None


class ParserPlugin(Protocol):
    name: str

    def matches(self, raw: str, context: Optional[dict] = None) -> float:
        ...

    def parse(self, raw: str, context: Optional[dict] = None) -> ParseResult:
        ...
