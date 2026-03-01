from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from stacklens.domain.models.report import AnalysisReport


@runtime_checkable
class ReportWriterPort(Protocol):
    async def write(self, report: AnalysisReport, path: Path) -> Path: ...
