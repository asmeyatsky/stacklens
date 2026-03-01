from __future__ import annotations

from pydantic import BaseModel, Field


class ScanSummary(BaseModel, frozen=True):
    """Cross-layer summary of key findings."""

    hosting: str = "Unknown"
    tech_stack: list[str] = Field(default_factory=list)
    security_posture: str = "Unknown"
    key_findings: list[str] = Field(default_factory=list)
    architecture: list[str] = Field(default_factory=list)
    integrations: list[str] = Field(default_factory=list)
    api_stack: list[str] = Field(default_factory=list)
    data_storage: list[str] = Field(default_factory=list)
    maturity_rating: str = "unknown"
