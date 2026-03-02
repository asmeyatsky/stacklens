from __future__ import annotations

from pathlib import Path

from stacklens.application.dtos.analysis_config import AnalysisConfig
from stacklens.application.orchestration.pipeline import AnalysisPipeline
from stacklens.application.services.summary_builder import build_summary
from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.report_writer import ReportWriterPort
from stacklens.domain.services.ethics import EthicsPolicy
from stacklens.domain.services.performance_scoring import score_performance
from stacklens.domain.services.recommendation_builder import build_recommendations


class RunAnalysisCommand:
    """Use case: run a full analysis and write reports."""

    def __init__(
        self,
        pipeline: AnalysisPipeline,
        writers: dict[str, ReportWriterPort],
        ethics: EthicsPolicy,
    ) -> None:
        self._pipeline = pipeline
        self._writers = writers
        self._ethics = ethics

    async def execute(self, config: AnalysisConfig) -> AnalysisReport:
        target = AnalysisTarget.from_url(config.target_url)

        await self._ethics.check_robots_txt(
            f"{target.scheme}://{target.hostname}",
            strict=config.ethical_strict,
        )

        report = await self._pipeline.run(target, config.layers)

        # Build cross-layer summary
        summary = build_summary(report)
        report = report.with_summary(summary)

        # Compute performance score if browser layer is present
        browser_data = report.layers.get("browser")
        if isinstance(browser_data, BrowserResult):
            perf_score = score_performance(browser_data)
            report = report.with_performance_score(perf_score)

        # Build recommendations from all available data
        recs = build_recommendations(report)
        report = report.with_recommendations(recs)

        config.output_dir.mkdir(parents=True, exist_ok=True)
        for fmt in config.output_formats:
            writer = self._writers.get(fmt)
            if writer:
                filename = f"stacklens_{report.meta.scan_id}.{fmt}"
                await writer.write(report, Path(config.output_dir / filename))

        return report
