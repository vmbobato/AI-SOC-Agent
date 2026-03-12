from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class IntakeSourceMetadata(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    type: Optional[str] = None
    format: Optional[str] = None
    host: Optional[str] = None
    environment: Optional[str] = None


class IntakeRawEvent(BaseModel):
    message: str = Field(min_length=1)
    timestamp: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class IntakeRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=64)
    parser_hint: Optional[str] = None
    source: IntakeSourceMetadata = Field(default_factory=IntakeSourceMetadata)
    events: List[IntakeRawEvent] = Field(default_factory=list)
    log_content: Optional[str] = None

    @field_validator("tenant_id")
    @classmethod
    def normalize_tenant_id(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_intake_content(self) -> "IntakeRequest":
        has_events = len(self.events) > 0
        has_log_content = bool((self.log_content or "").strip())
        if not has_events and not has_log_content:
            raise ValueError("Either events or log_content must be provided")
        return self

    def iter_events(self) -> List[IntakeRawEvent]:
        if self.events:
            return self.events

        lines = [line.strip() for line in (self.log_content or "").splitlines() if line.strip()]
        return [IntakeRawEvent(message=line) for line in lines]
