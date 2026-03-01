from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from stacklens.domain.models.meta import ScanMeta
from stacklens.domain.models.performance import PerformanceScore
from stacklens.domain.models.summary import ScanSummary
from stacklens.domain.models.target import AnalysisTarget


class AnalysisReport(BaseModel, frozen=True):
    """Aggregate root: immutable report built up layer-by-layer."""

    target: AnalysisTarget
    meta: ScanMeta = Field(default_factory=ScanMeta)
    layers: dict[str, Any] = Field(default_factory=dict)
    summary: ScanSummary | None = None
    performance_score: PerformanceScore | None = None

    def with_layer_result(self, layer_name: str, result: Any) -> AnalysisReport:
        new_layers = {**self.layers, layer_name: result}
        return self.model_copy(update={"layers": new_layers})

    def with_summary(self, summary: ScanSummary) -> AnalysisReport:
        return self.model_copy(update={"summary": summary})

    def with_performance_score(self, score: PerformanceScore) -> AnalysisReport:
        return self.model_copy(update={"performance_score": score})

    def finalize(self) -> AnalysisReport:
        completed_meta = self.meta.complete(list(self.layers.keys()))
        return self.model_copy(update={"meta": completed_meta})
