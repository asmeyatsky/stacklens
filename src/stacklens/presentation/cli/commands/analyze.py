from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from stacklens.application.dtos.analysis_config import AnalysisConfig
from stacklens.infrastructure.config.container import Container
from stacklens.presentation.cli.app import app

console = Console()

VALID_LAYERS = ["dns", "tls", "headers", "frontend", "backend"]


@app.command()
def analyze(
    url: str = typer.Argument(..., help="URL to analyse"),
    layers: Optional[str] = typer.Option(
        None,
        "--layers",
        "-l",
        help="Comma-separated layers to run (dns,tls,headers,frontend,backend)",
    ),
    output_dir: Path = typer.Option(
        Path("stacklens_output"),
        "--output-dir",
        "-o",
        help="Output directory for reports",
    ),
    no_ai: bool = typer.Option(True, "--no-ai/--ai", help="Disable AI analysis"),
    ethical_strict: bool = typer.Option(
        False,
        "--ethical-strict",
        help="Abort if robots.txt disallows scanning",
    ),
) -> None:
    """Analyse a public-facing URL across DNS, TLS, HTTP headers, frontend, and backend layers."""
    selected_layers = _parse_layers(layers)

    config = AnalysisConfig(
        target_url=url,
        layers=selected_layers,
        output_dir=output_dir,
        no_ai=no_ai,
        ethical_strict=ethical_strict,
    )

    asyncio.run(_run(config))


async def _run(config: AnalysisConfig) -> None:
    container = Container()
    try:
        command = container.run_analysis_command(config.layers)

        with console.status("[bold green]Analysing...") as _:
            report = await command.execute(config)

        _print_summary(report)
        console.print(
            f"\n[green]Report saved to {config.output_dir}/[/green]"
        )
    finally:
        await container.close()


def _print_summary(report) -> None:  # noqa: ANN001
    console.print(f"\n[bold]StackLens Analysis: {report.target.hostname}[/bold]")
    console.print(f"Scan ID: {report.meta.scan_id}")
    console.print(f"Layers: {', '.join(report.meta.layers)}\n")

    for layer_name, result in report.layers.items():
        if isinstance(result, dict) and "error" in result:
            console.print(f"[red]{layer_name}: {result['error']}[/red]")
            continue

        table = Table(title=layer_name.upper(), show_header=True)
        if layer_name == "dns":
            table.add_column("Type")
            table.add_column("Value")
            for rec in result.records:
                table.add_row(rec.record_type, rec.value)
            if result.cdn_detected:
                table.add_row("CDN", result.cdn_detected)
        elif layer_name == "tls":
            table.add_column("Property")
            table.add_column("Value")
            table.add_row("Protocol", result.protocol)
            table.add_row("Cipher", result.cipher)
            if result.certificate:
                table.add_row("Subject", result.certificate.subject)
                table.add_row("Issuer", result.certificate.issuer)
            if result.days_until_expiry is not None:
                table.add_row("Days Until Expiry", str(result.days_until_expiry))
        elif layer_name == "headers":
            table.add_column("Header")
            table.add_column("Status")
            table.add_column("Value")
            for h in result.security_headers:
                status = "[green]present[/green]" if h.present else "[red]missing[/red]"
                table.add_row(h.name, status, h.value or "")
            table.add_row("Score", "", f"{result.score:.0%}")
        elif layer_name == "frontend":
            table.add_column("Category")
            table.add_column("Technology")
            table.add_column("Evidence")
            for d in result.detections:
                table.add_row(d.category, d.name, d.evidence)
            if result.meta_generator:
                table.add_row("generator", result.meta_generator, "<meta> tag")
            table.add_row("rendering", result.rendering, "")
        elif layer_name == "backend":
            table.add_column("Property")
            table.add_column("Value")
            if result.server_framework:
                table.add_row("Framework", ", ".join(result.server_framework))
            if result.cms:
                table.add_row("CMS", ", ".join(result.cms))
            if result.cloud_provider:
                table.add_row("Cloud", ", ".join(result.cloud_provider))
            if result.waf:
                table.add_row("WAF", ", ".join(result.waf))
            for probe in result.endpoint_probes:
                if probe.accessible:
                    table.add_row(
                        f"Endpoint {probe.path}",
                        f"[green]{probe.status_code}[/green]",
                    )

        console.print(table)


def _parse_layers(layers_str: str | None) -> list[str]:
    if not layers_str:
        return list(VALID_LAYERS)
    selected = [l.strip().lower() for l in layers_str.split(",")]
    invalid = [l for l in selected if l not in VALID_LAYERS]
    if invalid:
        raise typer.BadParameter(
            f"Invalid layers: {', '.join(invalid)}. Valid: {', '.join(VALID_LAYERS)}"
        )
    return selected
