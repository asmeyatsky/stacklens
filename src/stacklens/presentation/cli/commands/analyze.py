from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from stacklens.application.dtos.analysis_config import AnalysisConfig
from stacklens.infrastructure.config.container import Container
from stacklens.presentation.cli.app import app

console = Console()

VALID_LAYERS = ["dns", "tls", "headers", "frontend", "backend", "browser"]
DEFAULT_LAYERS = ["dns", "tls", "headers", "frontend", "backend"]


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
    deep: bool = typer.Option(
        False,
        "--deep",
        help="Enable deep browser analysis (requires Playwright)",
    ),
    ethical_strict: bool = typer.Option(
        False,
        "--ethical-strict",
        help="Abort if robots.txt disallows scanning",
    ),
) -> None:
    """Analyse a public-facing URL across DNS, TLS, HTTP headers, frontend, and backend layers."""
    selected_layers = _parse_layers(layers, deep=deep)

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

    # Summary panel at top
    if report.summary:
        summary_lines: list[str] = []
        if report.summary.hosting != "Unknown":
            summary_lines.append(f"[bold]Hosting:[/bold] {report.summary.hosting}")
        if report.summary.tech_stack:
            summary_lines.append(f"[bold]Stack:[/bold] {', '.join(report.summary.tech_stack)}")
        if report.summary.architecture:
            summary_lines.append(f"[bold]Architecture:[/bold] {', '.join(report.summary.architecture)}")
        if report.summary.api_stack:
            summary_lines.append(f"[bold]API Stack:[/bold] {', '.join(report.summary.api_stack)}")
        if report.summary.data_storage:
            summary_lines.append(f"[bold]Data/Storage:[/bold] {', '.join(report.summary.data_storage)}")
        if report.summary.security_posture != "Unknown":
            summary_lines.append(f"[bold]Security:[/bold] {report.summary.security_posture}")
        if report.summary.integrations:
            summary_lines.append(
                f"[bold]Integrations:[/bold] {len(report.summary.integrations)} services"
            )
        if report.summary.maturity_rating != "unknown":
            summary_lines.append(f"[bold]Maturity:[/bold] {report.summary.maturity_rating}")
        if report.summary.key_findings:
            summary_lines.append("")
            for finding in report.summary.key_findings:
                summary_lines.append(f"  - {finding}")

        if summary_lines:
            console.print(
                Panel(
                    "\n".join(summary_lines),
                    title="Summary",
                    border_style="cyan",
                )
            )
            console.print()

    for layer_name, result in report.layers.items():
        if isinstance(result, dict) and "error" in result:
            console.print(f"[red]{layer_name}: {result['error']}[/red]")
            continue

        if layer_name == "dns":
            _print_dns(result)
        elif layer_name == "tls":
            _print_tls(result)
        elif layer_name == "headers":
            _print_headers(result)
        elif layer_name == "frontend":
            _print_frontend(result)
        elif layer_name == "backend":
            _print_backend(result)
        elif layer_name == "browser":
            _print_browser(result)

    # Consolidated integrations table
    if report.summary and report.summary.integrations:
        _print_integrations(report.summary.integrations)


def _print_dns(result) -> None:  # noqa: ANN001
    table = Table(title="DNS", show_header=True)
    table.add_column("Property")
    table.add_column("Value")

    if result.hosting_provider:
        table.add_row("DNS Provider", result.hosting_provider)
    if result.cdn_detected:
        table.add_row("CDN", result.cdn_detected)
    if result.email_provider:
        table.add_row("Email Provider", result.email_provider)
    if result.spf_includes:
        table.add_row("SPF Services", ", ".join(result.spf_includes))
    if result.dns_services:
        table.add_row("Verified Services", ", ".join(result.dns_services))
    if result.dmarc_policy:
        table.add_row("DMARC Policy", result.dmarc_policy)
    if result.caa_issuers:
        table.add_row("CAA Issuers", ", ".join(result.caa_issuers))
    if result.ptr_records:
        table.add_row("PTR Records", ", ".join(result.ptr_records))
    if result.resolved_ips:
        table.add_row("Resolved IPs", ", ".join(result.resolved_ips))

    for rec in result.records:
        table.add_row(f"[dim]{rec.record_type}[/dim]", f"[dim]{rec.value}[/dim]")

    console.print(table)


def _print_tls(result) -> None:  # noqa: ANN001
    table = Table(title="TLS", show_header=True)
    table.add_column("Property")
    table.add_column("Value")
    table.add_row("Protocol", result.protocol)
    table.add_row("Cipher", result.cipher)
    if result.cipher_strength != "unknown":
        table.add_row("Cipher Strength", result.cipher_strength)
    if result.key_type:
        table.add_row("Key Type", result.key_type)
    if result.certificate:
        table.add_row("Subject", result.certificate.subject)
        table.add_row("Issuer", result.certificate.issuer)
    if result.is_wildcard:
        table.add_row("Wildcard", "Yes")
    if result.is_ev:
        table.add_row("EV Certificate", "Yes")
    if result.days_until_expiry is not None:
        table.add_row("Days Until Expiry", str(result.days_until_expiry))
    console.print(table)


def _print_headers(result) -> None:  # noqa: ANN001
    table = Table(title="HEADERS", show_header=True)
    table.add_column("Header")
    table.add_column("Status")
    table.add_column("Value")
    for h in result.security_headers:
        status = "[green]present[/green]" if h.present else "[red]missing[/red]"
        table.add_row(h.name, status, h.value or "")
    table.add_row("Score", "", f"{result.score:.0%}")

    if result.cors:
        for key, val in result.cors.items():
            table.add_row(f"[cyan]CORS {key}[/cyan]", "[green]present[/green]", val)

    if result.caching:
        for key, val in result.caching.items():
            table.add_row(f"[cyan]{key}[/cyan]", "[green]present[/green]", val)

    if result.cookie_insights:
        for insight in result.cookie_insights:
            table.add_row("[cyan]Cookie[/cyan]", "", insight)

    console.print(table)


def _print_frontend(result) -> None:  # noqa: ANN001
    table = Table(title="FRONTEND", show_header=True)
    table.add_column("Category")
    table.add_column("Technology")
    table.add_column("Evidence")
    for d in result.detections:
        table.add_row(d.category, d.name, d.evidence)
    if result.meta_generator:
        table.add_row("generator", result.meta_generator, "<meta> tag")
    table.add_row("rendering", result.rendering, "")

    if result.script_dependencies:
        for dep in result.script_dependencies:
            version_info = f"v{dep.version}" if dep.version else ""
            cdn_info = f" ({dep.cdn})" if dep.cdn else ""
            table.add_row("dependency", dep.name, f"{version_info}{cdn_info}")

    if result.structured_data_types:
        table.add_row("structured_data", ", ".join(result.structured_data_types), "JSON-LD")

    if result.preconnect_domains:
        table.add_row("preconnect", ", ".join(result.preconnect_domains), "dns-prefetch/preconnect")

    console.print(table)


def _print_backend(result) -> None:  # noqa: ANN001
    table = Table(title="BACKEND", show_header=True)
    table.add_column("Property")
    table.add_column("Value")

    if result.server_software:
        table.add_row("Server Software", result.server_software)
    if result.proxy_gateway:
        table.add_row("Proxy/Gateway", ", ".join(result.proxy_gateway))
    if result.tracing:
        table.add_row("Tracing", ", ".join(result.tracing))
    if result.server_framework:
        table.add_row("Framework", ", ".join(result.server_framework))
    if result.cms:
        table.add_row("CMS", ", ".join(result.cms))
    if result.cloud_provider:
        table.add_row("Cloud", ", ".join(result.cloud_provider))
    if result.waf:
        table.add_row("WAF", ", ".join(result.waf))
    if result.api_signals:
        table.add_row("API Signals", ", ".join(result.api_signals))
    if result.database_hints:
        table.add_row("Database Hints", ", ".join(result.database_hints))
    if result.architecture:
        table.add_row("Architecture", ", ".join(result.architecture))
    if result.caching:
        for c in result.caching:
            table.add_row("Caching", c)
    if result.auth_providers:
        table.add_row("Auth Providers", ", ".join(result.auth_providers))
    if result.cookie_insights:
        for ci in result.cookie_insights:
            table.add_row("Cookie Insight", ci)
    if result.elapsed_ms > 0:
        table.add_row("Response Time", f"{result.elapsed_ms:.0f}ms")
    if result.infra_hints:
        for hint in result.infra_hints:
            table.add_row("Infra Hint", hint)

    accessible = [p for p in result.endpoint_probes if p.accessible]
    if accessible:
        for probe in accessible:
            table.add_row(
                f"Endpoint {probe.path}",
                f"[green]{probe.status_code}[/green]",
            )

    console.print(table)


def _print_integrations(integrations: list[str]) -> None:
    table = Table(title="INTEGRATIONS", show_header=True)
    table.add_column("#", justify="right")
    table.add_column("Service")
    for i, svc in enumerate(integrations, 1):
        table.add_row(str(i), svc)
    console.print(table)


def _parse_layers(layers_str: str | None, *, deep: bool = False) -> list[str]:
    if not layers_str:
        selected = list(DEFAULT_LAYERS)
    else:
        selected = [l.strip().lower() for l in layers_str.split(",")]
        invalid = [l for l in selected if l not in VALID_LAYERS]
        if invalid:
            raise typer.BadParameter(
                f"Invalid layers: {', '.join(invalid)}. Valid: {', '.join(VALID_LAYERS)}"
            )
    if deep and "browser" not in selected:
        selected.append("browser")
    return selected


def _format_bytes(n: int | float) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _print_browser(result: object) -> None:  # noqa: ANN001
    # Network summary
    net = Table(title="BROWSER / Network", show_header=True)
    net.add_column("Property")
    net.add_column("Value")
    net.add_row("Total Requests", str(result.network.total_requests))
    net.add_row("Transfer Size", _format_bytes(result.network.total_transfer_bytes))
    net.add_row("1st Party Requests", str(result.network.first_party_requests))
    net.add_row("3rd Party Requests", str(result.network.third_party_requests))
    if result.network.third_party_domains:
        net.add_row("3rd Party Domains", ", ".join(result.network.third_party_domains[:15]))
    if result.network.graphql_queries:
        net.add_row("GraphQL Queries", str(len(result.network.graphql_queries)))
    if result.network.streaming_endpoints:
        net.add_row("SSE Endpoints", str(len(result.network.streaming_endpoints)))
    if result.network.protocols_used:
        net.add_row("Protocols", ", ".join(result.network.protocols_used))
    if result.network.requests_by_type:
        breakdown = ", ".join(
            f"{k}: {v}" for k, v in sorted(result.network.requests_by_type.items(), key=lambda x: -x[1])
        )
        net.add_row("By Type", breakdown)
    console.print(net)

    # Performance
    perf = result.performance
    if any([perf.ttfb_ms, perf.fcp_ms, perf.lcp_ms, perf.load_event_ms]):
        ptbl = Table(title="BROWSER / Performance", show_header=True)
        ptbl.add_column("Metric")
        ptbl.add_column("Value")
        if perf.ttfb_ms is not None:
            ptbl.add_row("TTFB", f"{perf.ttfb_ms:.0f}ms")
        if perf.fcp_ms is not None:
            ptbl.add_row("FCP", f"{perf.fcp_ms:.0f}ms")
        if perf.lcp_ms is not None:
            color = "[red]" if perf.lcp_ms > 4000 else "[green]"
            ptbl.add_row("LCP", f"{color}{perf.lcp_ms:.0f}ms[/{color[1:]}")
        if perf.cls is not None:
            color = "[red]" if perf.cls > 0.25 else "[green]"
            ptbl.add_row("CLS", f"{color}{perf.cls:.3f}[/{color[1:]}")
        if perf.dom_interactive_ms is not None:
            ptbl.add_row("DOM Interactive", f"{perf.dom_interactive_ms:.0f}ms")
        if perf.dom_complete_ms is not None:
            ptbl.add_row("DOM Complete", f"{perf.dom_complete_ms:.0f}ms")
        if perf.load_event_ms is not None:
            ptbl.add_row("Load Event", f"{perf.load_event_ms:.0f}ms")
        if perf.total_page_weight_bytes:
            ptbl.add_row("Page Weight", _format_bytes(perf.total_page_weight_bytes))
        console.print(ptbl)

    # Runtime / Framework
    fw = result.framework_data
    if any([fw.next_data, fw.nuxt_data, fw.remix_context, fw.global_objects, fw.service_worker_active]):
        rtbl = Table(title="BROWSER / Runtime", show_header=True)
        rtbl.add_column("Property")
        rtbl.add_column("Value")
        if fw.next_data:
            rtbl.add_row("Next.js", "[green]detected[/green]")
        if fw.nuxt_data:
            rtbl.add_row("Nuxt", "[green]detected[/green]")
        if fw.remix_context:
            rtbl.add_row("Remix", "[green]detected[/green]")
        if fw.service_worker_active:
            rtbl.add_row("Service Worker", "[green]active[/green]")
        if fw.global_objects:
            rtbl.add_row("Global Objects", ", ".join(fw.global_objects))
        if fw.browser_features:
            rtbl.add_row("Browser Features", ", ".join(fw.browser_features))
        console.print(rtbl)

    # Storage
    st = result.storage
    if st.cookie_count or st.local_storage_keys or st.session_storage_keys:
        stbl = Table(title="BROWSER / Storage", show_header=True)
        stbl.add_column("Property")
        stbl.add_column("Value")
        stbl.add_row("Cookies", str(st.cookie_count))
        if st.local_storage_keys:
            stbl.add_row("localStorage Keys", str(len(st.local_storage_keys)))
        if st.session_storage_keys:
            stbl.add_row("sessionStorage Keys", str(len(st.session_storage_keys)))
        console.print(stbl)

    # WebSockets
    if result.websockets:
        wstbl = Table(title="BROWSER / WebSockets", show_header=True)
        wstbl.add_column("URL")
        wstbl.add_column("Sent")
        wstbl.add_column("Received")
        for ws in result.websockets:
            wstbl.add_row(ws.url, str(ws.frames_sent), str(ws.frames_received))
        console.print(wstbl)

    # Console
    c = result.console
    if c.error_count or c.warning_count or c.uncaught_exceptions:
        ctbl = Table(title="BROWSER / Console", show_header=True)
        ctbl.add_column("Property")
        ctbl.add_column("Value")
        ctbl.add_row("Errors", str(c.error_count))
        ctbl.add_row("Warnings", str(c.warning_count))
        if c.uncaught_exceptions:
            ctbl.add_row("Uncaught Exceptions", str(len(c.uncaught_exceptions)))
        for err in c.errors[:5]:
            ctbl.add_row("[dim]Error[/dim]", f"[dim]{err[:120]}[/dim]")
        console.print(ctbl)

    # DOM
    d = result.dom
    if d.total_elements:
        dtbl = Table(title="BROWSER / DOM", show_header=True)
        dtbl.add_column("Property")
        dtbl.add_column("Value")
        dtbl.add_row("Total Elements", str(d.total_elements))
        if d.iframe_sources:
            dtbl.add_row("Iframes", str(len(d.iframe_sources)))
        if d.has_shadow_dom:
            dtbl.add_row("Shadow DOM", "[green]detected[/green]")
        if d.lazy_image_count:
            dtbl.add_row("Lazy Images", str(d.lazy_image_count))
        dtbl.add_row("Rendered HTML", _format_bytes(d.rendered_html_length))
        console.print(dtbl)

    # Meta
    if result.page_title:
        console.print(f"  Page Title: {result.page_title}")
    if result.final_url:
        console.print(f"  Final URL: {result.final_url}")
    if result.elapsed_ms:
        console.print(f"  Browser elapsed: {result.elapsed_ms:.0f}ms")
