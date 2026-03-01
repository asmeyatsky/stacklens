from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.services.performance_scoring import score_performance
from stacklens.infrastructure.writers.html_writer import HtmlReportWriter
from stacklens.presentation.cli.app import app

console = Console()


@app.command()
def report(
    json_path: Path = typer.Argument(..., help="Path to a StackLens JSON report file"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output HTML file path (defaults to same directory with .html extension)",
    ),
) -> None:
    """Convert an existing StackLens JSON report to a self-contained HTML file."""
    if not json_path.exists():
        console.print(f"[red]File not found: {json_path}[/red]")
        raise typer.Exit(code=1)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    analysis_report = AnalysisReport.model_validate(data)

    # Compute performance score from browser data if present and not already scored
    if analysis_report.performance_score is None:
        browser_data = analysis_report.layers.get("browser")
        if isinstance(browser_data, dict):
            try:
                browser_result = BrowserResult.model_validate(browser_data)
                perf_score = score_performance(browser_result)
                analysis_report = analysis_report.with_performance_score(perf_score)
            except Exception:
                pass

    html_path = output or json_path.with_suffix(".html")
    asyncio.run(_write_html(analysis_report, html_path))

    console.print(f"[green]HTML report saved to {html_path}[/green]")


async def _write_html(report: AnalysisReport, path: Path) -> None:
    writer = HtmlReportWriter()
    await writer.write(report, path)
