from __future__ import annotations

from pydantic import BaseModel


class MetricScore(BaseModel, frozen=True):
    name: str  # "LCP", "FCP", "CLS", "TBT", "TTFB"
    value: float | None
    score: int  # 0-100 for this metric
    rating: str  # "good" | "needs-improvement" | "poor" | "unknown"
    display: str  # "2500ms", "0.08", etc.


class PerformanceScore(BaseModel, frozen=True):
    overall_score: int = 0  # 0-100 weighted
    grade: str = "F"  # A/B/C/D/F
    metrics: list[MetricScore] = []
    resource_breakdown: dict[str, int] = {}  # bytes by resource type
    third_party_ratio: float = 0.0  # 0-1
    total_requests: int = 0
    total_transfer_bytes: int = 0
    render_blocking_count: int = 0
    page_weight_bytes: int = 0
