from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from stacklens.domain.models.target import AnalysisTarget


@runtime_checkable
class AnalyserPort(Protocol):
    """Core extensibility point: every analysis layer implements this."""

    @property
    def name(self) -> str: ...

    @property
    def depends_on(self) -> list[str]: ...

    async def analyse(self, target: AnalysisTarget) -> Any: ...
