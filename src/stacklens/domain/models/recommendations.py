from __future__ import annotations

from pydantic import BaseModel


class Recommendation(BaseModel, frozen=True):
    category: str  # "performance" | "security" | "best-practices" | "infrastructure"
    severity: str  # "critical" | "warning" | "info"
    title: str
    description: str
    impact: str
    action: str


class Recommendations(BaseModel, frozen=True):
    items: list[Recommendation] = []
