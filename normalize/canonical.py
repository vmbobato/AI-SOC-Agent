from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass(slots=True)
class CanonicalEvent:
    ts: Optional[str]
    tenant_id: str
    event_family: Optional[str] = None
    event_kind: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    environment: Optional[str] = None
    host: Optional[str] = None
    source_type: Optional[str] = None
    parser_name: Optional[str] = None
    parser_confidence: float = 0.0
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    http_method: Optional[str] = None
    url_path: Optional[str] = None
    url_query: Optional[str] = None
    http_version: Optional[str] = None
    host_header: Optional[str] = None
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    status_code: Optional[int] = None
    bytes_sent: Optional[int] = None
    request_time_ms: Optional[float] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    message: Optional[str] = None
    raw_message: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    parse_error: Optional[str] = None
    parser_version: str = "1.0"
    is_4xx: bool = False
    is_5xx: bool = False
    is_sensitive_path: bool = False
    is_probe_like: bool = False
    path_depth: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
