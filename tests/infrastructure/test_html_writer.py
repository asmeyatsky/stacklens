"""Tests for HtmlReportWriter."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from stacklens.domain.models.browser import (
    BrowserResult,
    ConsoleSnapshot,
    DomSnapshot,
    FrameworkData,
    NetworkSummary,
    PerformanceMetrics,
    StorageSummary,
    WebSocketConnection,
)
from stacklens.domain.models.performance import MetricScore, PerformanceScore
from stacklens.domain.models.report import AnalysisReport, ScanSummary
from stacklens.domain.models.target import AnalysisTarget
from stacklens.infrastructure.writers.html_writer import HtmlReportWriter


def _minimal_report() -> AnalysisReport:
    target = AnalysisTarget.from_url("https://example.com")
    report = AnalysisReport(target=target)
    return report.finalize()


def _full_report() -> AnalysisReport:
    """Build a report with all layers populated."""
    from stacklens.domain.models.dns import DnsRecord, DnsResult
    from stacklens.domain.models.tls import TlsCertificate, TlsResult
    from stacklens.domain.models.headers import HeadersResult, SecurityHeader
    from stacklens.domain.models.frontend import FrontendResult, TechDetection
    from stacklens.domain.models.backend import BackendResult, EndpointProbe

    target = AnalysisTarget.from_url("https://example.com")
    report = AnalysisReport(target=target)

    # DNS
    dns = DnsResult(
        records=[DnsRecord(record_type="A", name="example.com", value="93.184.216.34", ttl=300)],
        resolved_ips=["93.184.216.34"],
        hosting_provider="Edgecast",
        cdn_detected="Verizon",
    )
    report = report.with_layer_result("dns", dns)

    # TLS
    tls = TlsResult(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=TlsCertificate(
            subject="example.com",
            issuer="DigiCert",
            not_before="2024-01-01",
            not_after="2025-01-01",
            serial_number="ABC123",
        ),
        days_until_expiry=180,
    )
    report = report.with_layer_result("tls", tls)

    # Headers
    headers = HeadersResult(
        security_headers=[
            SecurityHeader(name="Strict-Transport-Security", present=True, value="max-age=31536000"),
            SecurityHeader(name="X-Frame-Options", present=False, value=None),
        ],
        score=0.75,
        cors={"allow-origin": "*"},
        caching={"Cache-Control": "public, max-age=3600"},
        cookie_insights=["Session cookie without Secure flag"],
    )
    report = report.with_layer_result("headers", headers)

    # Frontend
    frontend = FrontendResult(
        detections=[TechDetection(category="framework", name="React", evidence="react-root div")],
        rendering="CSR",
    )
    report = report.with_layer_result("frontend", frontend)

    # Backend
    backend = BackendResult(
        server_software="nginx/1.25",
        cloud_provider=["AWS"],
        elapsed_ms=42.0,
        endpoint_probes=[
            EndpointProbe(path="/robots.txt", status_code=200, accessible=True),
        ],
    )
    report = report.with_layer_result("backend", backend)

    # Browser
    browser = BrowserResult(
        network=NetworkSummary(
            total_requests=50,
            total_transfer_bytes=1_500_000,
            first_party_requests=30,
            third_party_requests=20,
            third_party_domains=["cdn.example.com"],
            requests_by_type={"script": 15, "image": 20},
            protocols_used=["h2"],
        ),
        performance=PerformanceMetrics(
            ttfb_ms=120.0,
            fcp_ms=800.0,
            lcp_ms=2500.0,
            load_event_ms=3000.0,
            total_page_weight_bytes=2_000_000,
        ),
        framework_data=FrameworkData(
            next_data=True,
            global_objects=["__NEXT_DATA__"],
        ),
        storage=StorageSummary(cookie_count=5),
        websockets=[WebSocketConnection(url="wss://ws.example.com", frames_sent=10, frames_received=20)],
        console=ConsoleSnapshot(error_count=2, warning_count=1, errors=["TypeError: null is not an object"]),
        dom=DomSnapshot(total_elements=500, rendered_html_length=45000, has_shadow_dom=True),
        page_title="Example Domain",
        final_url="https://example.com/",
        elapsed_ms=5000.0,
    )
    report = report.with_layer_result("browser", browser)

    summary = ScanSummary(
        hosting="AWS / Edgecast",
        tech_stack=["React", "Next.js"],
        security_posture="Good",
        key_findings=["Uses CDN", "Modern TLS"],
        architecture=["SPA", "JAMStack"],
        integrations=["Google Analytics", "Sentry"],
        maturity_rating="production",
    )
    report = report.with_summary(summary)
    return report.finalize()


@pytest.fixture
def tmp_html(tmp_path: Path) -> Path:
    return tmp_path / "report.html"


class TestMinimalReport:
    def test_produces_valid_html(self, tmp_html: Path) -> None:
        report = _minimal_report()
        result = asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = result.read_text()
        assert "<html" in content
        assert "example.com" in content
        assert report.meta.scan_id in content

    def test_no_layer_sections_for_empty_report(self, tmp_html: Path) -> None:
        report = _minimal_report()
        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        for heading in ["DNS", "TLS", "Headers", "Frontend", "Backend", "Browser"]:
            # The card h2 headings should not appear
            assert f"<h2>{heading}</h2>" not in content


class TestFullReport:
    @pytest.fixture(autouse=True)
    def _write(self, tmp_html: Path) -> None:
        self.report = _full_report()
        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(self.report, tmp_html)
        )
        self.html = tmp_html.read_text()

    def test_contains_all_section_headings(self) -> None:
        for heading in ["DNS", "TLS", "Headers", "Frontend", "Backend", "Browser", "Summary"]:
            assert f"<h2>{heading}</h2>" in self.html

    def test_dns_content(self) -> None:
        assert "Edgecast" in self.html
        assert "93.184.216.34" in self.html

    def test_tls_content(self) -> None:
        assert "TLSv1.3" in self.html
        assert "DigiCert" in self.html

    def test_headers_present_and_missing(self) -> None:
        assert "status-present" in self.html
        assert "status-missing" in self.html
        assert "75%" in self.html

    def test_frontend_detection(self) -> None:
        assert "React" in self.html
        assert "CSR" in self.html

    def test_backend_content(self) -> None:
        assert "nginx" in self.html
        assert "AWS" in self.html

    def test_browser_network(self) -> None:
        assert "Network" in self.html
        assert "50" in self.html  # total_requests

    def test_browser_performance(self) -> None:
        assert "Performance" in self.html
        assert "TTFB" in self.html

    def test_browser_runtime(self) -> None:
        assert "Runtime" in self.html
        assert "Next.js" in self.html

    def test_browser_storage(self) -> None:
        assert "Storage" in self.html
        assert "Cookies" in self.html

    def test_browser_websockets(self) -> None:
        assert "WebSockets" in self.html
        assert "wss://ws.example.com" in self.html

    def test_browser_console(self) -> None:
        assert "Console" in self.html
        assert "TypeError" in self.html

    def test_browser_dom(self) -> None:
        assert "DOM" in self.html
        assert "Shadow DOM" in self.html

    def test_integrations(self) -> None:
        assert "Integrations" in self.html
        assert "Google Analytics" in self.html
        assert "Sentry" in self.html

    def test_summary_card(self) -> None:
        assert "JAMStack" in self.html
        assert "production" in self.html
        assert "Uses CDN" in self.html


class TestMissingLayers:
    def test_only_dns_renders_dns_section(self, tmp_html: Path) -> None:
        from stacklens.domain.models.dns import DnsResult

        target = AnalysisTarget.from_url("https://test.io")
        report = AnalysisReport(target=target)
        dns = DnsResult(records=[], resolved_ips=["1.2.3.4"], hosting_provider="Cloudflare")
        report = report.with_layer_result("dns", dns).finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "<h2>DNS</h2>" in content
        assert "<h2>TLS</h2>" not in content
        assert "<h2>Browser</h2>" not in content

    def test_error_layer_renders_error(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://err.io")
        report = AnalysisReport(target=target)
        report = report.with_layer_result("dns", {"error": "Timeout"}).finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "Timeout" in content


class TestHtmlEscaping:
    def test_special_characters_are_escaped(self, tmp_html: Path) -> None:
        from stacklens.domain.models.dns import DnsResult, DnsRecord

        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target)
        dns = DnsResult(
            records=[DnsRecord(record_type="TXT", name="example.com", value="<script>alert('xss')</script>", ttl=300)],
            resolved_ips=[],
        )
        report = report.with_layer_result("dns", dns).finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

    def test_ampersand_in_hostname(self, tmp_html: Path) -> None:
        """Ampersands in data must be escaped."""
        from stacklens.domain.models.dns import DnsResult

        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target)
        dns = DnsResult(records=[], resolved_ips=[], hosting_provider="Foo & Bar")
        report = report.with_layer_result("dns", dns).finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "Foo &amp; Bar" in content


def _perf_score() -> PerformanceScore:
    return PerformanceScore(
        overall_score=85,
        grade="B",
        metrics=[
            MetricScore(name="LCP", value=2200, score=90, rating="good", display="2200ms"),
            MetricScore(name="CLS", value=0.05, score=100, rating="good", display="0.050"),
            MetricScore(name="TBT", value=300, score=75, rating="needs-improvement", display="300ms"),
        ],
        resource_breakdown={"script": 150000, "image": 80000},
        third_party_ratio=0.3,
        total_requests=60,
        total_transfer_bytes=1_500_000,
        render_blocking_count=2,
        page_weight_bytes=2_000_000,
    )


class TestPerformanceSection:
    def test_performance_heading_rendered(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target, performance_score=_perf_score())
        report = report.finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "<h2>Performance</h2>" in content

    def test_score_and_grade_in_section(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target, performance_score=_perf_score())
        report = report.finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "85" in content
        assert ">B<" in content

    def test_metric_cards_rendered(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target, performance_score=_perf_score())
        report = report.finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "LCP" in content
        assert "2200ms" in content

    def test_resource_breakdown_rendered(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target, performance_score=_perf_score())
        report = report.finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "Resource Breakdown" in content
        assert "script" in content


class TestSummaryWithPerformanceBadge:
    def test_summary_shows_perf_badge(self, tmp_html: Path) -> None:
        target = AnalysisTarget.from_url("https://example.com")
        summary = ScanSummary(hosting="AWS", tech_stack=["React"], security_posture="Good")
        report = AnalysisReport(
            target=target,
            summary=summary,
            performance_score=_perf_score(),
        ).finalize()

        asyncio.get_event_loop().run_until_complete(
            HtmlReportWriter().write(report, tmp_html)
        )
        content = tmp_html.read_text()
        assert "85/100 (B)" in content
