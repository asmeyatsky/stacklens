from __future__ import annotations

from pydantic import BaseModel, Field


class TechDetection(BaseModel, frozen=True):
    """A single detected technology signal."""

    category: str  # e.g. "js_framework", "css_framework", "analytics", "third_party"
    name: str  # e.g. "React", "Tailwind", "GA4"
    evidence: str  # What triggered the detection (e.g. "__NEXT_DATA__ script tag")


class FrontendResult(BaseModel, frozen=True):
    """Aggregated frontend / client-side analysis."""

    detections: list[TechDetection] = Field(default_factory=list)
    meta_generator: str | None = None  # <meta name="generator"> content
    rendering: str = "unknown"  # "spa", "ssr", "static", "unknown"
