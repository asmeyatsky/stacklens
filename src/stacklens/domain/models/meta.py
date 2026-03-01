from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ScanMeta(BaseModel, frozen=True):
    """Metadata about a single analysis run."""

    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    layers: list[str] = Field(default_factory=list)
    version: str = "0.1.0"

    def complete(self, layers: list[str]) -> ScanMeta:
        return self.model_copy(
            update={
                "completed_at": datetime.now(timezone.utc),
                "layers": layers,
            }
        )
