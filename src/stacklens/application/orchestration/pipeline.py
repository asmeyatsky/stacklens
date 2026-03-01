from __future__ import annotations

import asyncio
from typing import Any

from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.analyser import AnalyserPort


class AnalysisPipeline:
    """DAG orchestrator: resolves dependencies, runs independent layers concurrently."""

    def __init__(
        self,
        analysers: list[AnalyserPort],
        *,
        concurrency: int = 5,
        timeout: float = 30.0,
    ) -> None:
        self._analysers = {a.name: a for a in analysers}
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = timeout

    async def run(
        self,
        target: AnalysisTarget,
        layers: list[str],
    ) -> AnalysisReport:
        report = AnalysisReport(target=target)
        resolved_order = self._resolve_dag(layers)

        results: dict[str, Any] = {}
        for batch in resolved_order:
            tasks = [self._run_one(name, target) for name in batch]
            batch_results = await asyncio.gather(*tasks)
            for name, result in zip(batch, batch_results):
                results[name] = result

        for name, result in results.items():
            report = report.with_layer_result(name, result)

        return report.finalize()

    async def _run_one(self, name: str, target: AnalysisTarget) -> Any:
        analyser = self._analysers.get(name)
        if not analyser:
            return {"error": f"Unknown analyser: {name}"}
        async with self._semaphore:
            try:
                timeout = getattr(analyser, "timeout", self._timeout)
                return await asyncio.wait_for(
                    analyser.analyse(target), timeout=timeout
                )
            except asyncio.TimeoutError:
                timeout = getattr(analyser, "timeout", self._timeout)
                return {"error": f"Analyser '{name}' timed out after {timeout}s"}
            except Exception as exc:
                return {"error": f"Analyser '{name}' failed: {exc}"}

    def _resolve_dag(self, layers: list[str]) -> list[list[str]]:
        """Simple topological sort into batches of independent layers."""
        remaining = set(layers) & set(self._analysers.keys())
        completed: set[str] = set()
        batches: list[list[str]] = []

        while remaining:
            batch = []
            for name in list(remaining):
                analyser = self._analysers[name]
                deps = set(analyser.depends_on) & set(layers)
                if deps <= completed:
                    batch.append(name)
            if not batch:
                batch = list(remaining)
            for name in batch:
                remaining.discard(name)
            completed.update(batch)
            batches.append(sorted(batch))

        return batches
