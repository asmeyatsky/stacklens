from __future__ import annotations

import json
from pathlib import Path

from stacklens.domain.models.report import AnalysisReport


class JsonReportWriter:
    async def write(self, report: AnalysisReport, path: Path) -> Path:
        data = report.model_dump(mode="json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, default=str))
        return path
