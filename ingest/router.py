from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from parsers.base import ParseResult, ParserPlugin
from parsers.plugins import FallbackRawParser, build_default_parsers


DEFAULT_MATCH_THRESHOLD = 0.25


@dataclass(slots=True)
class RoutedParse:
    result: ParseResult
    tried_parsers: List[str]


class ParserRouter:
    def __init__(self, parsers: Optional[List[ParserPlugin]] = None, match_threshold: float = DEFAULT_MATCH_THRESHOLD):
        self.parsers = parsers or build_default_parsers()
        self.match_threshold = match_threshold
        self._by_name: Dict[str, ParserPlugin] = {p.name: p for p in self.parsers}
        self.fallback = self._by_name.get("fallback_raw")
        if not self.fallback:
            self.fallback = FallbackRawParser()
            self.parsers.append(self.fallback)
            self._by_name[self.fallback.name] = self.fallback

    def route(self, raw: str, parser_hint: Optional[str] = None, context: Optional[dict] = None) -> RoutedParse:
        tried: List[str] = []

        if parser_hint:
            hinted = self._by_name.get(parser_hint)
            if hinted:
                tried.append(hinted.name)
                hinted_result = hinted.parse(raw, context=context)
                if hinted_result.success:
                    return RoutedParse(result=hinted_result, tried_parsers=tried)

        scored: List[tuple[float, ParserPlugin]] = []
        for parser in self.parsers:
            if parser.name == "fallback_raw":
                continue
            if parser_hint and parser.name == parser_hint:
                continue
            score = parser.matches(raw, context=context)
            if score >= self.match_threshold:
                scored.append((score, parser))

        scored.sort(key=lambda item: item[0], reverse=True)

        for score, parser in scored:
            tried.append(parser.name)
            result = parser.parse(raw, context=context)
            if result.success:
                result.confidence = max(result.confidence, float(score))
                return RoutedParse(result=result, tried_parsers=tried)

        fallback = self.fallback or FallbackRawParser()
        tried.append(fallback.name)
        return RoutedParse(result=fallback.parse(raw, context=context), tried_parsers=tried)


def build_router() -> ParserRouter:
    return ParserRouter()
