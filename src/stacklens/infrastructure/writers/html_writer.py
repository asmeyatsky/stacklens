from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from stacklens.domain.models.report import AnalysisReport


class _Ns:
    """Wraps a dict so its keys are accessible as attributes (recursively)."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._d = data

    def __getattr__(self, name: str) -> Any:
        try:
            val = self._d[name]
        except KeyError:
            return None
        if isinstance(val, dict):
            return _Ns(val)
        if isinstance(val, list) and val and isinstance(val[0], dict):
            return [_Ns(v) for v in val]
        return val

    def items(self) -> Any:
        return self._d.items()

    def __iter__(self) -> Any:
        return iter(self._d)

    def __bool__(self) -> bool:
        return bool(self._d)


def _wrap(obj: Any) -> Any:
    """Ensure *obj* supports attribute access (model or dict)."""
    return _Ns(obj) if isinstance(obj, dict) else obj


def _esc(value: object) -> str:
    return html.escape(str(value))


def _format_bytes(n: int | float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


_CSS = """\
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;line-height:1.6;padding:2rem}
a{color:#58a6ff;text-decoration:none}
.container{max-width:960px;margin:0 auto}
header{border-bottom:1px solid #21262d;padding-bottom:1rem;margin-bottom:2rem}
header h1{font-size:1.5rem;color:#f0f6fc}
header .meta{color:#8b949e;font-size:.85rem;margin-top:.25rem}
.card{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:1.25rem;margin-bottom:1.5rem}
.card h2{font-size:1.1rem;color:#f0f6fc;margin-bottom:.75rem;border-bottom:1px solid #21262d;padding-bottom:.5rem}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}
.badge-good{background:#1b4332;color:#2dd4bf}
.badge-warn{background:#4a3728;color:#f59e0b}
.badge-bad{background:#4c1d1d;color:#f87171}
table{width:100%;border-collapse:collapse;margin-top:.5rem}
th{text-align:left;color:#8b949e;font-size:.8rem;text-transform:uppercase;padding:.4rem .5rem;border-bottom:1px solid #21262d}
td{padding:.4rem .5rem;border-bottom:1px solid #161b22;font-size:.9rem}
.status-present{color:#2dd4bf}
.status-missing{color:#f87171}
.finding{padding:.25rem 0;color:#8b949e;font-size:.9rem}
.kv{display:grid;grid-template-columns:160px 1fr;gap:.3rem .75rem}
.kv dt{color:#8b949e;font-size:.85rem}
.kv dd{font-size:.9rem}
.sub-section{margin-top:1rem}
.sub-section h3{font-size:.95rem;color:#8b949e;margin-bottom:.4rem}
.score-circle{display:inline-flex;align-items:center;justify-content:center;width:100px;height:100px;position:relative}
.score-circle svg{position:absolute;top:0;left:0}
.score-circle .score-text{font-size:1.4rem;font-weight:700;z-index:1}
.score-circle .grade-text{font-size:.75rem;color:#8b949e}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.75rem;margin-top:1rem}
.metric-card{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:.75rem;text-align:center}
.metric-card .metric-name{font-size:.75rem;color:#8b949e;text-transform:uppercase;margin-bottom:.25rem}
.metric-card .metric-value{font-size:1.1rem;font-weight:600}
.metric-card .metric-bar{height:4px;border-radius:2px;margin-top:.5rem}
.bar-chart{margin-top:.75rem}
.bar-row{display:flex;align-items:center;margin-bottom:.4rem;font-size:.85rem}
.bar-row .bar-label{width:80px;color:#8b949e}
.bar-row .bar-track{flex:1;height:12px;background:#21262d;border-radius:3px;margin:0 .5rem;overflow:hidden}
.bar-row .bar-fill{height:100%;background:#58a6ff;border-radius:3px}
.bar-row .bar-size{width:70px;text-align:right;color:#c9d1d9}
.perf-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}
.rec-grid{display:flex;flex-direction:column;gap:.75rem;margin-top:.75rem}
.rec-item{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:1rem;border-left:4px solid #8b949e}
.rec-item.rec-critical{border-left-color:#f87171}
.rec-item.rec-warning{border-left-color:#f59e0b}
.rec-item.rec-info{border-left-color:#2dd4bf}
.rec-severity{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.7rem;font-weight:600;text-transform:uppercase;margin-right:.5rem}
.rec-severity-critical{background:#4c1d1d;color:#f87171}
.rec-severity-warning{background:#4a3728;color:#f59e0b}
.rec-severity-info{background:#1b4332;color:#2dd4bf}
.rec-category{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.7rem;font-weight:500;background:#21262d;color:#8b949e;margin-right:.5rem}
.rec-title{font-weight:600;color:#f0f6fc;margin-bottom:.25rem}
.rec-desc{color:#8b949e;font-size:.85rem;margin-bottom:.25rem}
.rec-impact{color:#8b949e;font-size:.85rem;font-style:italic;margin-bottom:.5rem}
.rec-action{background:#161b22;border:1px solid #21262d;border-radius:4px;padding:.5rem .75rem;font-size:.85rem;color:#c9d1d9}
"""


class HtmlReportWriter:
    async def write(self, report: AnalysisReport, path: Path) -> Path:
        html_str = self._render(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_str, encoding="utf-8")
        return path

    def _render(self, report: AnalysisReport) -> str:
        parts: list[str] = []
        parts.append(self._header(report))

        if report.summary:
            parts.append(self._summary_card(report))

        if report.performance_score:
            parts.append(self._performance_section(report.performance_score))

        if report.recommendations and report.recommendations.items:
            parts.append(self._recommendations_section(report.recommendations))

        layers = report.layers
        section_map = {
            "dns": self._dns_section,
            "tls": self._tls_section,
            "headers": self._headers_section,
            "frontend": self._frontend_section,
            "backend": self._backend_section,
            "browser": self._browser_section,
        }
        for name, renderer in section_map.items():
            if name not in layers:
                continue
            raw = layers[name]
            if isinstance(raw, dict) and "error" in raw:
                parts.append(self._error_card(name.title(), raw["error"]))
            else:
                parts.append(renderer(_wrap(raw)))

        if report.summary and report.summary.integrations:
            parts.append(self._integrations_section(report.summary.integrations))

        body = "\n".join(parts)
        return (
            "<!DOCTYPE html>\n"
            f"<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>StackLens — {_esc(report.target.hostname)}</title>"
            f"<style>{_CSS}</style></head>"
            f"<body><div class=\"container\">{body}</div></body></html>"
        )

    # ── header ──────────────────────────────────────────────────

    def _header(self, report: AnalysisReport) -> str:
        meta = report.meta
        layers = ", ".join(meta.layers) if meta.layers else "—"
        return (
            f"<header>"
            f"<h1>StackLens Report — {_esc(report.target.hostname)}</h1>"
            f"<div class=\"meta\">"
            f"Scan ID: {_esc(meta.scan_id)} · "
            f"Timestamp: {_esc(meta.started_at)} · "
            f"Layers: {_esc(layers)} · "
            f"v{_esc(meta.version)}"
            f"</div></header>"
        )

    # ── summary card ────────────────────────────────────────────

    def _summary_card(self, report: object) -> str:
        s = getattr(report, "summary", None) or report
        rows: list[str] = []
        if s.hosting != "Unknown":
            rows.append(f"<dt>Hosting</dt><dd>{_esc(s.hosting)}</dd>")
        if s.tech_stack:
            rows.append(f"<dt>Stack</dt><dd>{_esc(', '.join(s.tech_stack))}</dd>")
        if s.architecture:
            rows.append(f"<dt>Architecture</dt><dd>{_esc(', '.join(s.architecture))}</dd>")
        if s.api_stack:
            rows.append(f"<dt>API Stack</dt><dd>{_esc(', '.join(s.api_stack))}</dd>")
        if s.data_storage:
            rows.append(f"<dt>Data/Storage</dt><dd>{_esc(', '.join(s.data_storage))}</dd>")
        if s.security_posture != "Unknown":
            badge = self._security_badge(s.security_posture)
            rows.append(f"<dt>Security</dt><dd>{badge}</dd>")
        if s.maturity_rating != "unknown":
            rows.append(f"<dt>Maturity</dt><dd><span class=\"badge badge-good\">{_esc(s.maturity_rating)}</span></dd>")

        # Performance badge
        ps = getattr(report, "performance_score", None)
        if ps:
            grade_colors = {"A": "#2dd4bf", "B": "#2dd4bf", "C": "#f59e0b", "D": "#f87171", "F": "#f87171"}
            color = grade_colors.get(ps.grade, "#c9d1d9")
            rows.append(
                f"<dt>Performance</dt><dd>"
                f"<span class=\"perf-badge\" style=\"background:{color}20;color:{color}\">"
                f"{ps.overall_score}/100 ({ps.grade})</span></dd>"
            )

        findings = ""
        if s.key_findings:
            items = "".join(f"<div class=\"finding\">• {_esc(f)}</div>" for f in s.key_findings)
            findings = f"<div class=\"sub-section\"><h3>Key Findings</h3>{items}</div>"

        return (
            f"<div class=\"card\"><h2>Summary</h2>"
            f"<dl class=\"kv\">{''.join(rows)}</dl>"
            f"{findings}</div>"
        )

    def _security_badge(self, posture: str) -> str:
        low = posture.lower()
        if "good" in low or "strong" in low:
            cls = "badge-good"
        elif "moderate" in low or "mixed" in low:
            cls = "badge-warn"
        else:
            cls = "badge-bad"
        return f"<span class=\"badge {cls}\">{_esc(posture)}</span>"

    # ── Performance ─────────────────────────────────────────────

    def _performance_section(self, ps: object) -> str:
        grade_colors = {"A": "#2dd4bf", "B": "#2dd4bf", "C": "#f59e0b", "D": "#f87171", "F": "#f87171"}
        color = grade_colors.get(ps.grade, "#c9d1d9")

        # SVG score circle
        radius = 40
        circumference = 2 * 3.14159 * radius
        offset = circumference * (1 - ps.overall_score / 100)
        circle_svg = (
            f'<div class="score-circle">'
            f'<svg width="100" height="100" viewBox="0 0 100 100">'
            f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="#21262d" stroke-width="6"/>'
            f'<circle cx="50" cy="50" r="{radius}" fill="none" stroke="{color}" stroke-width="6" '
            f'stroke-dasharray="{circumference:.1f}" stroke-dashoffset="{offset:.1f}" '
            f'stroke-linecap="round" transform="rotate(-90 50 50)"/>'
            f'</svg>'
            f'<div style="text-align:center">'
            f'<div class="score-text" style="color:{color}">{ps.overall_score}</div>'
            f'<div class="grade-text">{ps.grade}</div>'
            f'</div></div>'
        )

        # Metric cards
        rating_colors = {"good": "#2dd4bf", "needs-improvement": "#f59e0b", "poor": "#f87171"}
        cards = ""
        for m in ps.metrics:
            if m.rating == "unknown":
                continue
            mc = rating_colors.get(m.rating, "#8b949e")
            cards += (
                f'<div class="metric-card">'
                f'<div class="metric-name">{_esc(m.name)}</div>'
                f'<div class="metric-value" style="color:{mc}">{_esc(m.display)}</div>'
                f'<div class="metric-bar" style="background:{mc}"></div>'
                f'</div>'
            )
        metric_grid = f'<div class="metric-grid">{cards}</div>' if cards else ""

        # Resource breakdown bar chart
        breakdown_html = ""
        if ps.resource_breakdown:
            max_bytes = max(ps.resource_breakdown.values()) if ps.resource_breakdown else 1
            bars = ""
            for rtype, rbytes in sorted(ps.resource_breakdown.items(), key=lambda x: -x[1]):
                pct = (rbytes / max_bytes * 100) if max_bytes > 0 else 0
                bars += (
                    f'<div class="bar-row">'
                    f'<span class="bar-label">{_esc(rtype)}</span>'
                    f'<span class="bar-track"><span class="bar-fill" style="width:{pct:.0f}%"></span></span>'
                    f'<span class="bar-size">{_format_bytes(rbytes)}</span>'
                    f'</div>'
                )
            breakdown_html = f'<div class="sub-section"><h3>Resource Breakdown</h3><div class="bar-chart">{bars}</div></div>'

        # Network stats row
        stats: list[str] = []
        stats.append(f"Requests: {ps.total_requests}")
        if ps.third_party_ratio > 0:
            stats.append(f"3rd party: {ps.third_party_ratio:.0%}")
        if ps.total_transfer_bytes:
            stats.append(f"Transfer: {_format_bytes(ps.total_transfer_bytes)}")
        if ps.render_blocking_count:
            stats.append(f"Render-blocking: {ps.render_blocking_count}")
        stats_html = f'<div style="color:#8b949e;font-size:.85rem;margin-top:.75rem">{" · ".join(stats)}</div>' if stats else ""

        return (
            f'<div class="card"><h2>Performance</h2>'
            f'{circle_svg}{metric_grid}{breakdown_html}{stats_html}</div>'
        )

    # ── Recommendations ──────────────────────────────────────────

    def _recommendations_section(self, recs: object) -> str:
        items_html = ""
        for rec in recs.items:
            sev_cls = f"rec-{rec.severity}"
            badge_cls = f"rec-severity-{rec.severity}"
            items_html += (
                f'<div class="rec-item {sev_cls}">'
                f'<div style="margin-bottom:.5rem">'
                f'<span class="rec-severity {badge_cls}">{_esc(rec.severity)}</span>'
                f'<span class="rec-category">{_esc(rec.category)}</span>'
                f'</div>'
                f'<div class="rec-title">{_esc(rec.title)}</div>'
                f'<div class="rec-desc">{_esc(rec.description)}</div>'
                f'<div class="rec-impact">{_esc(rec.impact)}</div>'
                f'<div class="rec-action">{_esc(rec.action)}</div>'
                f'</div>'
            )

        return (
            f'<div class="card"><h2>Recommendations</h2>'
            f'<div class="rec-grid">{items_html}</div></div>'
        )

    # ── DNS ─────────────────────────────────────────────────────

    def _dns_section(self, r: object) -> str:
        rows = self._kv_rows([
            ("DNS Provider", getattr(r, "hosting_provider", None)),
            ("CDN", getattr(r, "cdn_detected", None)),
            ("Email Provider", getattr(r, "email_provider", None)),
            ("SPF Services", ", ".join(r.spf_includes) if getattr(r, "spf_includes", None) else None),
            ("DNS Services", ", ".join(r.dns_services) if getattr(r, "dns_services", None) else None),
            ("DMARC Policy", getattr(r, "dmarc_policy", None)),
            ("CAA Issuers", ", ".join(r.caa_issuers) if getattr(r, "caa_issuers", None) else None),
            ("PTR Records", ", ".join(r.ptr_records) if getattr(r, "ptr_records", None) else None),
            ("Resolved IPs", ", ".join(r.resolved_ips) if getattr(r, "resolved_ips", None) else None),
        ])

        records_html = ""
        if getattr(r, "records", None):
            rec_rows = "".join(
                f"<tr><td style=\"color:#8b949e\">{_esc(rec.record_type)}</td>"
                f"<td style=\"color:#8b949e\">{_esc(rec.value)}</td></tr>"
                for rec in r.records
            )
            records_html = (
                f"<table><tr><th>Type</th><th>Value</th></tr>"
                f"{rec_rows}</table>"
            )

        return (
            f"<div class=\"card\"><h2>DNS</h2>"
            f"<dl class=\"kv\">{rows}</dl>"
            f"{records_html}</div>"
        )

    # ── TLS ─────────────────────────────────────────────────────

    def _tls_section(self, r: object) -> str:
        cert_rows: list[tuple[str, str | None]] = []
        if getattr(r, "certificate", None):
            cert_rows.append(("Subject", r.certificate.subject))
            cert_rows.append(("Issuer", r.certificate.issuer))
        rows = self._kv_rows([
            ("Protocol", getattr(r, "protocol", None)),
            ("Cipher", getattr(r, "cipher", None)),
            ("Cipher Strength", getattr(r, "cipher_strength", None) if getattr(r, "cipher_strength", "unknown") != "unknown" else None),
            ("Key Type", getattr(r, "key_type", None)),
            *cert_rows,
            ("Wildcard", "Yes" if getattr(r, "is_wildcard", False) else None),
            ("EV Certificate", "Yes" if getattr(r, "is_ev", False) else None),
            ("Days Until Expiry", str(r.days_until_expiry) if getattr(r, "days_until_expiry", None) is not None else None),
        ])
        return f"<div class=\"card\"><h2>TLS</h2><dl class=\"kv\">{rows}</dl></div>"

    # ── Headers ─────────────────────────────────────────────────

    def _headers_section(self, r: object) -> str:
        header_rows = ""
        for h in r.security_headers:
            cls = "status-present" if h.present else "status-missing"
            label = "present" if h.present else "missing"
            header_rows += (
                f"<tr><td>{_esc(h.name)}</td>"
                f"<td class=\"{cls}\">{label}</td>"
                f"<td>{_esc(h.value or '')}</td></tr>"
            )
        header_rows += f"<tr><td><strong>Score</strong></td><td></td><td><strong>{r.score:.0%}</strong></td></tr>"

        cors_rows = ""
        if getattr(r, "cors", None):
            for key, val in r.cors.items():
                cors_rows += f"<tr><td>CORS {_esc(key)}</td><td class=\"status-present\">present</td><td>{_esc(val)}</td></tr>"

        cache_rows = ""
        if getattr(r, "caching", None):
            for key, val in r.caching.items():
                cache_rows += f"<tr><td>{_esc(key)}</td><td class=\"status-present\">present</td><td>{_esc(val)}</td></tr>"

        cookie_rows = ""
        if getattr(r, "cookie_insights", None):
            for insight in r.cookie_insights:
                cookie_rows += f"<tr><td>Cookie</td><td></td><td>{_esc(insight)}</td></tr>"

        return (
            f"<div class=\"card\"><h2>Headers</h2>"
            f"<table><tr><th>Header</th><th>Status</th><th>Value</th></tr>"
            f"{header_rows}{cors_rows}{cache_rows}{cookie_rows}</table></div>"
        )

    # ── Frontend ────────────────────────────────────────────────

    def _frontend_section(self, r: object) -> str:
        det_rows = ""
        for d in r.detections:
            det_rows += f"<tr><td>{_esc(d.category)}</td><td>{_esc(d.name)}</td><td>{_esc(d.evidence)}</td></tr>"
        if getattr(r, "meta_generator", None):
            det_rows += f"<tr><td>generator</td><td>{_esc(r.meta_generator)}</td><td>&lt;meta&gt; tag</td></tr>"
        det_rows += f"<tr><td>rendering</td><td>{_esc(r.rendering)}</td><td></td></tr>"

        if getattr(r, "script_dependencies", None):
            for dep in r.script_dependencies:
                ver = f"v{dep.version}" if dep.version else ""
                cdn = f" ({dep.cdn})" if dep.cdn else ""
                det_rows += f"<tr><td>dependency</td><td>{_esc(dep.name)}</td><td>{_esc(f'{ver}{cdn}')}</td></tr>"

        if getattr(r, "structured_data_types", None):
            det_rows += f"<tr><td>structured_data</td><td>{_esc(', '.join(r.structured_data_types))}</td><td>JSON-LD</td></tr>"
        if getattr(r, "preconnect_domains", None):
            det_rows += f"<tr><td>preconnect</td><td>{_esc(', '.join(r.preconnect_domains))}</td><td>dns-prefetch/preconnect</td></tr>"

        return (
            f"<div class=\"card\"><h2>Frontend</h2>"
            f"<table><tr><th>Category</th><th>Technology</th><th>Evidence</th></tr>"
            f"{det_rows}</table></div>"
        )

    # ── Backend ─────────────────────────────────────────────────

    def _backend_section(self, r: object) -> str:
        rows_data: list[tuple[str, str | None]] = [
            ("Server Software", getattr(r, "server_software", None)),
            ("Proxy/Gateway", ", ".join(r.proxy_gateway) if getattr(r, "proxy_gateway", None) else None),
            ("Tracing", ", ".join(r.tracing) if getattr(r, "tracing", None) else None),
            ("Framework", ", ".join(r.server_framework) if getattr(r, "server_framework", None) else None),
            ("CMS", ", ".join(r.cms) if getattr(r, "cms", None) else None),
            ("Cloud", ", ".join(r.cloud_provider) if getattr(r, "cloud_provider", None) else None),
            ("WAF", ", ".join(r.waf) if getattr(r, "waf", None) else None),
            ("API Signals", ", ".join(r.api_signals) if getattr(r, "api_signals", None) else None),
            ("Database Hints", ", ".join(r.database_hints) if getattr(r, "database_hints", None) else None),
            ("Architecture", ", ".join(r.architecture) if getattr(r, "architecture", None) else None),
            ("Auth Providers", ", ".join(r.auth_providers) if getattr(r, "auth_providers", None) else None),
        ]
        if getattr(r, "caching", None):
            for c in r.caching:
                rows_data.append(("Caching", c))
        if getattr(r, "cookie_insights", None):
            for ci in r.cookie_insights:
                rows_data.append(("Cookie Insight", ci))
        if getattr(r, "elapsed_ms", 0) > 0:
            rows_data.append(("Response Time", f"{r.elapsed_ms:.0f}ms"))
        if getattr(r, "infra_hints", None):
            for hint in r.infra_hints:
                rows_data.append(("Infra Hint", hint))

        kv = self._kv_rows(rows_data)

        probes_html = ""
        accessible = [p for p in getattr(r, "endpoint_probes", []) if p.accessible]
        if accessible:
            probe_rows = "".join(
                f"<tr><td>{_esc(p.path)}</td><td class=\"status-present\">{p.status_code}</td></tr>"
                for p in accessible
            )
            probes_html = (
                f"<div class=\"sub-section\"><h3>Accessible Endpoints</h3>"
                f"<table><tr><th>Path</th><th>Status</th></tr>{probe_rows}</table></div>"
            )

        return f"<div class=\"card\"><h2>Backend</h2><dl class=\"kv\">{kv}</dl>{probes_html}</div>"

    # ── Browser ─────────────────────────────────────────────────

    def _browser_section(self, r: object) -> str:
        parts: list[str] = []

        # Network
        net = getattr(r, "network", None)
        if net:
            rows: list[tuple[str, str | None]] = [
                ("Total Requests", str(net.total_requests)),
                ("Transfer Size", _format_bytes(net.total_transfer_bytes)),
                ("1st Party Requests", str(net.first_party_requests)),
                ("3rd Party Requests", str(net.third_party_requests)),
            ]
            if net.third_party_domains:
                rows.append(("3rd Party Domains", ", ".join(net.third_party_domains[:15])))
            if net.graphql_queries:
                rows.append(("GraphQL Queries", str(len(net.graphql_queries))))
            if net.streaming_endpoints:
                rows.append(("SSE Endpoints", str(len(net.streaming_endpoints))))
            if net.protocols_used:
                rows.append(("Protocols", ", ".join(net.protocols_used)))
            if net.requests_by_type:
                breakdown = ", ".join(
                    f"{k}: {v}" for k, v in sorted(net.requests_by_type.items(), key=lambda x: -x[1])
                )
                rows.append(("By Type", breakdown))
            parts.append(
                f"<div class=\"sub-section\"><h3>Network</h3>"
                f"<dl class=\"kv\">{self._kv_rows(rows)}</dl></div>"
            )

        # Performance
        perf = getattr(r, "performance", None)
        if perf and any([
            getattr(perf, "ttfb_ms", None),
            getattr(perf, "fcp_ms", None),
            getattr(perf, "lcp_ms", None),
            getattr(perf, "load_event_ms", None),
        ]):
            prows: list[tuple[str, str | None]] = []
            if perf.ttfb_ms is not None:
                prows.append(("TTFB", f"{perf.ttfb_ms:.0f}ms"))
            if perf.fcp_ms is not None:
                prows.append(("FCP", f"{perf.fcp_ms:.0f}ms"))
            if perf.lcp_ms is not None:
                cls = "status-missing" if perf.lcp_ms > 4000 else "status-present"
                prows.append(("LCP", f"<span class=\"{cls}\">{perf.lcp_ms:.0f}ms</span>"))
            if getattr(perf, "cls", None) is not None:
                cls = "status-missing" if perf.cls > 0.25 else "status-present"
                prows.append(("CLS", f"<span class=\"{cls}\">{perf.cls:.3f}</span>"))
            if getattr(perf, "dom_interactive_ms", None) is not None:
                prows.append(("DOM Interactive", f"{perf.dom_interactive_ms:.0f}ms"))
            if getattr(perf, "dom_complete_ms", None) is not None:
                prows.append(("DOM Complete", f"{perf.dom_complete_ms:.0f}ms"))
            if perf.load_event_ms is not None:
                prows.append(("Load Event", f"{perf.load_event_ms:.0f}ms"))
            if getattr(perf, "total_page_weight_bytes", None):
                prows.append(("Page Weight", _format_bytes(perf.total_page_weight_bytes)))
            parts.append(
                f"<div class=\"sub-section\"><h3>Performance</h3>"
                f"<dl class=\"kv\">{self._kv_rows(prows, escape_val=False)}</dl></div>"
            )

        # Runtime / Framework
        fw = getattr(r, "framework_data", None)
        if fw and any([
            getattr(fw, "next_data", None),
            getattr(fw, "nuxt_data", None),
            getattr(fw, "remix_context", None),
            getattr(fw, "global_objects", None),
            getattr(fw, "service_worker_active", None),
        ]):
            frows: list[tuple[str, str | None]] = []
            if fw.next_data:
                frows.append(("Next.js", "<span class=\"status-present\">detected</span>"))
            if fw.nuxt_data:
                frows.append(("Nuxt", "<span class=\"status-present\">detected</span>"))
            if fw.remix_context:
                frows.append(("Remix", "<span class=\"status-present\">detected</span>"))
            if getattr(fw, "service_worker_active", False):
                frows.append(("Service Worker", "<span class=\"status-present\">active</span>"))
            if fw.global_objects:
                frows.append(("Global Objects", _esc(", ".join(fw.global_objects))))
            if getattr(fw, "browser_features", None):
                frows.append(("Browser Features", _esc(", ".join(fw.browser_features))))
            parts.append(
                f"<div class=\"sub-section\"><h3>Runtime</h3>"
                f"<dl class=\"kv\">{self._kv_rows(frows, escape_val=False)}</dl></div>"
            )

        # Storage
        st = getattr(r, "storage", None)
        if st and (st.cookie_count or getattr(st, "local_storage_keys", None) or getattr(st, "session_storage_keys", None)):
            srows: list[tuple[str, str | None]] = [("Cookies", str(st.cookie_count))]
            if st.local_storage_keys:
                srows.append(("localStorage Keys", str(len(st.local_storage_keys))))
            if st.session_storage_keys:
                srows.append(("sessionStorage Keys", str(len(st.session_storage_keys))))
            parts.append(
                f"<div class=\"sub-section\"><h3>Storage</h3>"
                f"<dl class=\"kv\">{self._kv_rows(srows)}</dl></div>"
            )

        # WebSockets
        ws_list = getattr(r, "websockets", None)
        if ws_list:
            ws_rows = "".join(
                f"<tr><td>{_esc(ws.url)}</td><td>{ws.frames_sent}</td><td>{ws.frames_received}</td></tr>"
                for ws in ws_list
            )
            parts.append(
                f"<div class=\"sub-section\"><h3>WebSockets</h3>"
                f"<table><tr><th>URL</th><th>Sent</th><th>Received</th></tr>"
                f"{ws_rows}</table></div>"
            )

        # Console
        con = getattr(r, "console", None)
        if con and (con.error_count or con.warning_count or getattr(con, "uncaught_exceptions", None)):
            crows: list[tuple[str, str | None]] = [
                ("Errors", str(con.error_count)),
                ("Warnings", str(con.warning_count)),
            ]
            if con.uncaught_exceptions:
                crows.append(("Uncaught Exceptions", str(len(con.uncaught_exceptions))))
            noise = getattr(con, "noise_error_count", 0)
            if noise:
                crows.append(("Filtered tracking noise", str(noise)))
            err_html = ""
            for err in con.errors[:5]:
                err_html += f"<div class=\"finding\" style=\"color:#f87171\">• {_esc(err[:120])}</div>"
            parts.append(
                f"<div class=\"sub-section\"><h3>Console</h3>"
                f"<dl class=\"kv\">{self._kv_rows(crows)}</dl>{err_html}</div>"
            )

        # DOM
        dom = getattr(r, "dom", None)
        if dom and getattr(dom, "total_elements", 0):
            drows: list[tuple[str, str | None]] = [("Total Elements", str(dom.total_elements))]
            if getattr(dom, "iframe_sources", None):
                drows.append(("Iframes", str(len(dom.iframe_sources))))
            if getattr(dom, "has_shadow_dom", False):
                drows.append(("Shadow DOM", "<span class=\"status-present\">detected</span>"))
            if getattr(dom, "lazy_image_count", 0):
                drows.append(("Lazy Images", str(dom.lazy_image_count)))
            drows.append(("Rendered HTML", _format_bytes(getattr(dom, "rendered_html_length", 0))))
            parts.append(
                f"<div class=\"sub-section\"><h3>DOM</h3>"
                f"<dl class=\"kv\">{self._kv_rows(drows, escape_val=False)}</dl></div>"
            )

        # Page meta
        meta_parts: list[str] = []
        if getattr(r, "page_title", None):
            meta_parts.append(f"<dt>Page Title</dt><dd>{_esc(r.page_title)}</dd>")
        if getattr(r, "final_url", None):
            meta_parts.append(f"<dt>Final URL</dt><dd>{_esc(r.final_url)}</dd>")
        if getattr(r, "elapsed_ms", 0):
            meta_parts.append(f"<dt>Browser Elapsed</dt><dd>{r.elapsed_ms:.0f}ms</dd>")
        if meta_parts:
            parts.append(
                f"<div class=\"sub-section\"><h3>Page</h3>"
                f"<dl class=\"kv\">{''.join(meta_parts)}</dl></div>"
            )

        inner = "".join(parts)
        return f"<div class=\"card\"><h2>Browser</h2>{inner}</div>"

    # ── Integrations ────────────────────────────────────────────

    def _integrations_section(self, integrations: list[str]) -> str:
        rows = "".join(
            f"<tr><td style=\"text-align:right;color:#8b949e\">{i}</td><td>{_esc(svc)}</td></tr>"
            for i, svc in enumerate(integrations, 1)
        )
        return (
            f"<div class=\"card\"><h2>Integrations</h2>"
            f"<table><tr><th style=\"text-align:right\">#</th><th>Service</th></tr>"
            f"{rows}</table></div>"
        )

    # ── helpers ─────────────────────────────────────────────────

    def _error_card(self, title: str, error: str) -> str:
        return (
            f"<div class=\"card\"><h2>{_esc(title)}</h2>"
            f"<p class=\"status-missing\">{_esc(error)}</p></div>"
        )

    def _kv_rows(self, pairs: list[tuple[str, str | None]], *, escape_val: bool = True) -> str:
        out: list[str] = []
        for label, value in pairs:
            if value is None:
                continue
            val = _esc(value) if escape_val else value
            out.append(f"<dt>{_esc(label)}</dt><dd>{val}</dd>")
        return "".join(out)
