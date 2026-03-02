"""Tests for the recommendation builder service."""

from __future__ import annotations

from stacklens.domain.models.backend import BackendResult, EndpointProbe
from stacklens.domain.models.browser import (
    BrowserResult,
    ConsoleSnapshot,
    DomSnapshot,
    FrameworkData,
    PerformanceMetrics,
)
from stacklens.domain.models.dns import DnsResult
from stacklens.domain.models.frontend import FrontendResult
from stacklens.domain.models.headers import CookieAnalysis, HeadersResult, SecurityHeader
from stacklens.domain.models.performance import PerformanceScore
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.models.tls import TlsResult
from stacklens.domain.services.recommendation_builder import build_recommendations


def _report(**layers: object) -> AnalysisReport:
    return AnalysisReport(
        target=AnalysisTarget.from_url("https://example.com"),
        layers=layers,
    )


def _report_with_perf(perf_score: PerformanceScore, **layers: object) -> AnalysisReport:
    return AnalysisReport(
        target=AnalysisTarget.from_url("https://example.com"),
        layers=layers,
        performance_score=perf_score,
    )


# ── Empty report ───────────────────────────────────────────────


def test_empty_report_returns_empty_recommendations():
    report = _report()
    recs = build_recommendations(report)
    assert recs.items == []


# ── Performance rules ──────────────────────────────────────────


def test_poor_cls_produces_critical_recommendation():
    report = _report(browser=BrowserResult(
        performance=PerformanceMetrics(cls=0.35),
    ))
    recs = build_recommendations(report)
    titles = [r.title for r in recs.items]
    assert any("Layout Shift" in t for t in titles)
    cls_rec = next(r for r in recs.items if "Layout Shift" in r.title)
    assert cls_rec.severity == "critical"
    assert cls_rec.category == "performance"


def test_needs_improvement_cls_produces_warning():
    report = _report(browser=BrowserResult(
        performance=PerformanceMetrics(cls=0.15),
    ))
    recs = build_recommendations(report)
    cls_rec = next(r for r in recs.items if "Layout Shift" in r.title)
    assert cls_rec.severity == "warning"


def test_poor_lcp_produces_critical():
    report = _report(browser=BrowserResult(
        performance=PerformanceMetrics(lcp_ms=5000.0),
    ))
    recs = build_recommendations(report)
    lcp_rec = next(r for r in recs.items if "Contentful Paint" in r.title)
    assert lcp_rec.severity == "critical"


def test_poor_tbt_produces_critical():
    report = _report(browser=BrowserResult(
        performance=PerformanceMetrics(tbt_ms=800.0),
    ))
    recs = build_recommendations(report)
    tbt_rec = next(r for r in recs.items if "Blocking Time" in r.title)
    assert tbt_rec.severity == "critical"


def test_render_blocking_produces_warning():
    report = _report_with_perf(
        PerformanceScore(render_blocking_count=3),
        browser=BrowserResult(),
    )
    recs = build_recommendations(report)
    assert any("Render-Blocking" in r.title for r in recs.items)


def test_large_script_bundle_produces_warning():
    report = _report_with_perf(
        PerformanceScore(resource_breakdown={"script": 2_000_000}),
        browser=BrowserResult(),
    )
    recs = build_recommendations(report)
    assert any("JavaScript Payload" in r.title for r in recs.items)


def test_high_page_weight_produces_warning():
    report = _report_with_perf(
        PerformanceScore(page_weight_bytes=6_000_000),
        browser=BrowserResult(),
    )
    recs = build_recommendations(report)
    assert any("Page Weight" in r.title for r in recs.items)


def test_high_third_party_ratio_produces_warning():
    report = _report_with_perf(
        PerformanceScore(third_party_ratio=0.6),
        browser=BrowserResult(),
    )
    recs = build_recommendations(report)
    assert any("Third-Party" in r.title for r in recs.items)


def test_many_requests_produces_info():
    report = _report_with_perf(
        PerformanceScore(total_requests=150),
        browser=BrowserResult(),
    )
    recs = build_recommendations(report)
    req_rec = next(r for r in recs.items if "HTTP Requests" in r.title)
    assert req_rec.severity == "info"


# ── Security rules ─────────────────────────────────────────────


def test_low_header_score_produces_critical():
    report = _report(headers=HeadersResult(score=0.3))
    recs = build_recommendations(report)
    assert any("Security Headers" in r.title for r in recs.items)
    sec_rec = next(r for r in recs.items if "Security Headers" in r.title)
    assert sec_rec.severity == "critical"


def test_missing_csp_produces_warning():
    report = _report(headers=HeadersResult(
        score=0.7,
        security_headers=[
            SecurityHeader(name="Content-Security-Policy", present=False),
        ],
    ))
    recs = build_recommendations(report)
    assert any("Content-Security-Policy" in r.title for r in recs.items)


def test_missing_hsts_produces_warning():
    report = _report(headers=HeadersResult(
        score=0.7,
        security_headers=[
            SecurityHeader(name="Strict-Transport-Security", present=False),
        ],
    ))
    recs = build_recommendations(report)
    assert any("Strict-Transport-Security" in r.title for r in recs.items)


def test_expiring_tls_cert_produces_critical():
    report = _report(tls=TlsResult(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        days_until_expiry=10,
    ))
    recs = build_recommendations(report)
    cert_rec = next(r for r in recs.items if "Certificate" in r.title)
    assert cert_rec.severity == "critical"


def test_old_tls_protocol_produces_info():
    report = _report(tls=TlsResult(
        protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES256-GCM-SHA384",
    ))
    recs = build_recommendations(report)
    assert any("TLS 1.3" in r.title for r in recs.items)


def test_insecure_cookies_produces_warning():
    report = _report(headers=HeadersResult(
        score=0.8,
        cookies=[CookieAnalysis(name="session", secure=False, http_only=False)],
    ))
    recs = build_recommendations(report)
    assert any("Cookie" in r.title for r in recs.items)


# ── Best practices rules ──────────────────────────────────────


def test_console_errors_produces_warning():
    report = _report(browser=BrowserResult(
        console=ConsoleSnapshot(error_count=5, errors=["TypeError: x"]),
    ))
    recs = build_recommendations(report)
    assert any("JavaScript Errors" in r.title for r in recs.items)


def test_uncaught_exceptions_produces_warning():
    report = _report(browser=BrowserResult(
        console=ConsoleSnapshot(uncaught_exceptions=["ReferenceError: foo"]),
    ))
    recs = build_recommendations(report)
    assert any("Uncaught" in r.title for r in recs.items)


def test_csr_rendering_produces_info():
    report = _report(frontend=FrontendResult(rendering="CSR"))
    recs = build_recommendations(report)
    assert any("Server-Side Rendering" in r.title for r in recs.items)


def test_no_structured_data_produces_info():
    report = _report(frontend=FrontendResult())
    recs = build_recommendations(report)
    assert any("Structured Data" in r.title for r in recs.items)


# ── Infrastructure rules ──────────────────────────────────────


def test_no_cdn_produces_warning():
    report = _report(dns=DnsResult(cdn_detected=None))
    recs = build_recommendations(report)
    cdn_rec = next(r for r in recs.items if "CDN" in r.title)
    assert cdn_rec.severity == "warning"
    assert cdn_rec.category == "infrastructure"


def test_no_waf_produces_info():
    report = _report(backend=BackendResult(waf=[]))
    recs = build_recommendations(report)
    assert any("WAF" in r.title for r in recs.items)


def test_dmarc_none_produces_warning():
    report = _report(dns=DnsResult(dmarc_policy="none"))
    recs = build_recommendations(report)
    assert any("DMARC" in r.title for r in recs.items)


def test_exposed_debug_endpoints_produces_warning():
    report = _report(backend=BackendResult(
        endpoint_probes=[
            EndpointProbe(path="/swagger", status_code=200, accessible=True),
        ],
    ))
    recs = build_recommendations(report)
    assert any("Debug" in r.title for r in recs.items)


def test_database_hints_produces_warning():
    report = _report(backend=BackendResult(database_hints=["PostgreSQL"]))
    recs = build_recommendations(report)
    assert any("Database" in r.title for r in recs.items)


# ── Ordering & completeness ───────────────────────────────────


def test_severity_ordering_critical_before_warning_before_info():
    report = _report(
        dns=DnsResult(cdn_detected=None),  # warning
        tls=TlsResult(protocol="TLSv1.2", cipher="AES", days_until_expiry=5),  # critical + info
        frontend=FrontendResult(),  # info
    )
    recs = build_recommendations(report)
    severities = [r.severity for r in recs.items]
    # All criticals should come before warnings, which come before infos
    first_warning = next((i for i, s in enumerate(severities) if s == "warning"), len(severities))
    first_info = next((i for i, s in enumerate(severities) if s == "info"), len(severities))
    last_critical = max((i for i, s in enumerate(severities) if s == "critical"), default=-1)
    last_warning = max((i for i, s in enumerate(severities) if s == "warning"), default=-1)
    assert last_critical < first_warning or last_critical == -1
    assert last_warning < first_info or last_warning == -1


def test_all_recommendations_have_required_fields():
    """Every recommendation should have non-empty strings for all fields."""
    report = _report(
        browser=BrowserResult(
            performance=PerformanceMetrics(cls=0.5, lcp_ms=5000, tbt_ms=800),
            console=ConsoleSnapshot(error_count=3, errors=["err"]),
        ),
        headers=HeadersResult(score=0.3),
        dns=DnsResult(cdn_detected=None),
        backend=BackendResult(database_hints=["MySQL"]),
    )
    recs = build_recommendations(report)
    assert len(recs.items) > 0
    for rec in recs.items:
        assert rec.category, f"Empty category on: {rec.title}"
        assert rec.severity, f"Empty severity on: {rec.title}"
        assert rec.title, "Empty title"
        assert rec.description, f"Empty description on: {rec.title}"
        assert rec.impact, f"Empty impact on: {rec.title}"
        assert rec.action, f"Empty action on: {rec.title}"
