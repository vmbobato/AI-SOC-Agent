from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class EventRecord:
    timestamp: Optional[str]
    source: str
    raw: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["EventRecord"]:
        source = data.get("source")
        if not isinstance(source, str) or not source.strip():
            return None
        timestamp = data.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, str):
            timestamp = str(timestamp)
        return cls(timestamp=timestamp, source=source, raw=dict(data))

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)


@dataclass(slots=True)
class CaseRecord:
    incident_type: str
    timestamp_start: str
    timestamp_end: str
    source_ips: List[str]
    raw: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["CaseRecord"]:
        incident_type = data.get("incident_type")
        start = data.get("timestamp_start")
        end = data.get("timestamp_end")
        source_ips = data.get("source_ips")
        if not isinstance(incident_type, str) or not incident_type:
            return None
        if not isinstance(start, str) or not start:
            return None
        if not isinstance(end, str) or not end:
            return None
        if not isinstance(source_ips, list):
            return None
        normalized_ips = [ip for ip in source_ips if isinstance(ip, str) and ip]
        return cls(
            incident_type=incident_type,
            timestamp_start=start,
            timestamp_end=end,
            source_ips=normalized_ips,
            raw=dict(data),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)


@dataclass(slots=True)
class CampaignRecord:
    campaign_id: str
    source_ip: str
    first_seen: str
    last_seen: str
    raw: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["CampaignRecord"]:
        campaign_id = data.get("campaign_id")
        source_ip = data.get("source_ip")
        first_seen = data.get("first_seen")
        last_seen = data.get("last_seen")
        if not all(isinstance(v, str) and v for v in [campaign_id, source_ip, first_seen, last_seen]):
            return None
        assert isinstance(campaign_id, str)
        assert isinstance(source_ip, str)
        assert isinstance(first_seen, str)
        assert isinstance(last_seen, str)
        return cls(
            campaign_id=campaign_id,
            source_ip=source_ip,
            first_seen=first_seen,
            last_seen=last_seen,
            raw=dict(data),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)


@dataclass(slots=True)
class AlertRecord:
    alert_id: str
    run_id: str
    title: str
    severity: str
    confidence: float
    source_ips: List[str]
    timestamp_start: str
    timestamp_end: str
    category: str
    recommended_actions: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    linked_case_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "run_id": self.run_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ips": self.source_ips,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "category": self.category,
            "recommended_actions": self.recommended_actions,
            "evidence": self.evidence,
            "linked_case_ids": self.linked_case_ids,
        }


@dataclass(slots=True)
class PipelineRunResult:
    run_id: str
    status: str
    filepath: str
    input_sha256: str
    counts: Dict[str, int]
    parse_stats: Dict[str, Dict[str, int]]
    artifacts: Dict[str, str]
    timings_ms: Dict[str, int]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "filepath": self.filepath,
            "input_sha256": self.input_sha256,
            "counts": self.counts,
            "parse_stats": self.parse_stats,
            "artifacts": self.artifacts,
            "timings_ms": self.timings_ms,
            "errors": self.errors,
        }
