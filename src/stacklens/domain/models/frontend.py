from __future__ import annotations

from pydantic import BaseModel, Field


class TechDetection(BaseModel, frozen=True):
    """A single detected technology signal."""

    category: str
    name: str
    evidence: str


class ScriptDependency(BaseModel, frozen=True):
    """A script dependency extracted from CDN URLs."""

    name: str
    version: str = ""
    cdn: str = ""


class FrontendResult(BaseModel, frozen=True):
    """Aggregated frontend / client-side analysis."""

    detections: list[TechDetection] = Field(default_factory=list)
    meta_generator: str | None = None
    rendering: str = "unknown"
    script_dependencies: list[ScriptDependency] = Field(default_factory=list)
    structured_data_types: list[str] = Field(default_factory=list)
    preconnect_domains: list[str] = Field(default_factory=list)
