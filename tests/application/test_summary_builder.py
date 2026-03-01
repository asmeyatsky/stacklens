"""Tests for the cross-layer summary builder."""

from stacklens.application.services.summary_builder import build_summary
from stacklens.domain.models.backend import BackendResult
from stacklens.domain.models.browser import (
    BrowserResult,
    ConsoleSnapshot,
    DomSnapshot,
    FrameworkData,
    GraphQLQuery,
    NetworkSummary,
    PerformanceMetrics,
    WebSocketConnection,
)
from stacklens.domain.models.dns import DnsResult
from stacklens.domain.models.frontend import FrontendResult, TechDetection
from stacklens.domain.models.headers import HeadersResult, SecurityHeader
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.models.tls import TlsCertificate, TlsResult


def _make_report(**layers) -> AnalysisReport:
    target = AnalysisTarget.from_url("https://example.com")
    report = AnalysisReport(target=target)
    for name, result in layers.items():
        report = report.with_layer_result(name, result)
    return report


def test_hosting_from_dns_and_backend():
    dns = DnsResult(hosting_provider="AWS Route53", cdn_detected="Amazon CloudFront")
    backend = BackendResult(cloud_provider=["AWS"])
    report = _make_report(dns=dns, backend=backend)

    summary = build_summary(report)

    assert "AWS Route53" in summary.hosting
    assert "CloudFront" in summary.hosting


def test_hosting_unknown_when_no_data():
    report = _make_report()
    summary = build_summary(report)
    assert summary.hosting == "Unknown"


def test_tech_stack_combines_backend_and_frontend():
    backend = BackendResult(
        server_software="Envoy",
        proxy_gateway=["Envoy"],
        server_framework=["Express"],
    )
    frontend = FrontendResult(
        detections=[
            TechDetection(category="js_framework", name="React", evidence="marker"),
            TechDetection(category="css_framework", name="Tailwind", evidence="marker"),
        ],
        rendering="ssr",
    )
    report = _make_report(backend=backend, frontend=frontend)

    summary = build_summary(report)

    assert "Envoy" in summary.tech_stack
    assert "Express" in summary.tech_stack
    assert "React" in summary.tech_stack
    assert "Tailwind" in summary.tech_stack
    assert "SSR rendering" in summary.tech_stack


def test_security_posture_from_headers_and_tls():
    headers = HeadersResult(
        security_headers=[
            SecurityHeader(name="HSTS", present=True, value="max-age=31536000", rating="good"),
            SecurityHeader(name="CSP", present=True, value="default-src 'self'", rating="good"),
        ],
        score=1.0,
    )
    tls = TlsResult(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=TlsCertificate(
            subject="example.com",
            issuer="DigiCert",
            not_before="2024-01-01T00:00:00",
            not_after="2025-01-01T00:00:00",
            serial_number="abc123",
            san=["example.com"],
        ),
        hsts=True,
    )
    report = _make_report(headers=headers, tls=tls)

    summary = build_summary(report)

    assert "100%" in summary.security_posture
    assert "TLSv1.3" in summary.security_posture
    assert "DigiCert" in summary.security_posture
    assert "HSTS" in summary.security_posture


def test_key_findings_includes_dns_and_backend():
    dns = DnsResult(
        hosting_provider="AWS Route53",
        email_provider="Google Workspace",
        cdn_detected="CloudFront",
    )
    backend = BackendResult(
        server_software="Envoy",
        proxy_gateway=["Envoy"],
        tracing=["Zipkin/Jaeger (B3)"],
        waf=["Cloudflare"],
        infra_hints=["AWS infrastructure: EC2 i-abc123, eu-west-1 (from Via header)"],
    )
    report = _make_report(dns=dns, backend=backend)

    summary = build_summary(report)

    finding_text = " ".join(summary.key_findings)
    assert "Route53" in finding_text
    assert "Google Workspace" in finding_text
    assert "Envoy" in finding_text
    assert "Zipkin" in finding_text
    assert "Cloudflare" in finding_text


def test_key_findings_tls_expiry_warning():
    tls = TlsResult(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        days_until_expiry=10,
    )
    report = _make_report(tls=tls)

    summary = build_summary(report)

    assert any("expires in 10 days" in f for f in summary.key_findings)


def test_empty_report_returns_defaults():
    report = _make_report()
    summary = build_summary(report)

    assert summary.hosting == "Unknown"
    assert summary.tech_stack == []
    assert summary.security_posture == "Unknown"
    assert summary.key_findings == []
    assert summary.architecture == []
    assert summary.integrations == []
    assert summary.api_stack == []
    assert summary.data_storage == []
    assert summary.maturity_rating == "startup"


# ── New tests for deep analysis expansion ─────────────────────────


def test_architecture_from_backend():
    backend = BackendResult(
        architecture=["Microservices (service mesh)", "Service mesh (Envoy)"],
    )
    report = _make_report(backend=backend)
    summary = build_summary(report)

    assert "Microservices (service mesh)" in summary.architecture
    assert "Service mesh (Envoy)" in summary.architecture


def test_integrations_consolidated():
    frontend = FrontendResult(
        detections=[
            TechDetection(category="payment", name="Stripe", evidence="stripe.js"),
            TechDetection(category="analytics", name="GA4", evidence="gtag"),
            TechDetection(category="monitoring", name="New Relic", evidence="NREUM"),
            TechDetection(category="consent", name="CookieBot", evidence="cookiebot"),
            TechDetection(category="auth", name="Auth0", evidence="auth0.com"),
        ],
    )
    backend = BackendResult(
        auth_providers=["Auth0", "Okta"],
    )
    dns = DnsResult(
        dns_services=["Google", "Facebook"],
        spf_includes=["AWS SES", "SendGrid"],
    )
    report = _make_report(frontend=frontend, backend=backend, dns=dns)
    summary = build_summary(report)

    assert "Stripe" in summary.integrations
    assert "GA4" in summary.integrations
    assert "Auth0" in summary.integrations
    assert "Okta" in summary.integrations
    assert "Google" in summary.integrations
    assert "AWS SES" in summary.integrations
    # Verify deduplication
    assert summary.integrations.count("Auth0") == 1


def test_api_stack_from_backend():
    backend = BackendResult(
        api_signals=["GraphQL", "WebSocket"],
    )
    report = _make_report(backend=backend)
    summary = build_summary(report)

    assert "GraphQL" in summary.api_stack
    assert "WebSocket" in summary.api_stack


def test_data_storage_from_backend():
    backend = BackendResult(
        database_hints=["PostgreSQL", "Redis"],
        caching=["X-Cache: HIT (Varnish)"],
    )
    report = _make_report(backend=backend)
    summary = build_summary(report)

    assert "PostgreSQL" in summary.data_storage
    assert "Redis" in summary.data_storage
    assert "Varnish" in summary.data_storage


def test_maturity_enterprise():
    backend = BackendResult(
        tracing=["Zipkin/Jaeger (B3)"],
        architecture=["Microservices (service mesh)"],
        waf=["Cloudflare"],
    )
    dns = DnsResult(
        dmarc_policy="reject",
        caa_issuers=["letsencrypt.org"],
    )
    tls = TlsResult(
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        is_ev=True,
    )
    report = _make_report(backend=backend, dns=dns, tls=tls)
    summary = build_summary(report)

    assert summary.maturity_rating == "enterprise"


def test_maturity_growth():
    dns = DnsResult(
        cdn_detected="CloudFront",
    )
    frontend = FrontendResult(
        detections=[
            TechDetection(category="monitoring", name="New Relic", evidence="marker"),
            TechDetection(category="auth", name="Auth0", evidence="marker"),
        ],
    )
    report = _make_report(dns=dns, frontend=frontend)
    summary = build_summary(report)

    assert summary.maturity_rating == "growth"


def test_maturity_startup():
    report = _make_report()
    summary = build_summary(report)
    assert summary.maturity_rating == "startup"


# ── Browser enrichment tests ────────────────────────────────────────


def test_tech_stack_from_browser_frameworks():
    browser = BrowserResult(
        framework_data=FrameworkData(
            next_data=True,
            global_objects=["React", "Stripe"],
        ),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert "Next.js" in summary.tech_stack
    assert "React" in summary.tech_stack
    assert "Stripe" in summary.tech_stack


def test_integrations_from_browser_third_party_domains():
    browser = BrowserResult(
        network=NetworkSummary(
            third_party_domains=["js.stripe.com", "sentry.io", "fonts.googleapis.com"],
        ),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert "Stripe" in summary.integrations
    assert "Sentry" in summary.integrations
    assert "Google Fonts" in summary.integrations


def test_api_stack_from_browser_graphql_and_ws():
    browser = BrowserResult(
        network=NetworkSummary(
            graphql_queries=[GraphQLQuery(endpoint="/graphql")],
            streaming_endpoints=["https://example.com/events"],
        ),
        websockets=[WebSocketConnection(url="wss://example.com/ws")],
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert "GraphQL" in summary.api_stack
    assert "SSE" in summary.api_stack
    assert "WebSocket" in summary.api_stack


def test_key_findings_browser_poor_lcp():
    browser = BrowserResult(
        performance=PerformanceMetrics(lcp_ms=5000.0),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("Poor LCP" in f for f in summary.key_findings)


def test_key_findings_browser_high_cls():
    browser = BrowserResult(
        performance=PerformanceMetrics(cls=0.5),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("High CLS" in f for f in summary.key_findings)


def test_key_findings_browser_console_errors():
    browser = BrowserResult(
        console=ConsoleSnapshot(error_count=5),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("Console errors: 5" in f for f in summary.key_findings)


def test_key_findings_browser_graphql_ops():
    browser = BrowserResult(
        network=NetworkSummary(
            graphql_queries=[
                GraphQLQuery(endpoint="/graphql", operation_name="GetUser"),
                GraphQLQuery(endpoint="/graphql", operation_name="GetPosts"),
            ],
        ),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("GraphQL: 2 operation(s)" in f for f in summary.key_findings)


def test_key_findings_browser_heavy_page():
    browser = BrowserResult(
        performance=PerformanceMetrics(total_page_weight_bytes=6 * 1024 * 1024),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("Heavy page" in f for f in summary.key_findings)


def test_key_findings_browser_websockets():
    browser = BrowserResult(
        websockets=[
            WebSocketConnection(url="wss://example.com/ws1"),
            WebSocketConnection(url="wss://example.com/ws2"),
        ],
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    assert any("WebSocket connections: 2" in f for f in summary.key_findings)


def test_maturity_browser_signals():
    browser = BrowserResult(
        framework_data=FrameworkData(service_worker_active=True),
        performance=PerformanceMetrics(lcp_ms=2000.0),
        network=NetworkSummary(
            graphql_queries=[GraphQLQuery(endpoint="/graphql")],
        ),
    )
    report = _make_report(browser=browser)
    summary = build_summary(report)

    # 3 growth signals from browser: service_worker, good LCP, graphql
    assert summary.maturity_rating == "growth"


def test_maturity_browser_shadow_dom_enterprise():
    backend = BackendResult(
        tracing=["Zipkin"],
        architecture=["Microservices (service mesh)"],
        waf=["Cloudflare"],
    )
    browser = BrowserResult(
        dom=DomSnapshot(has_shadow_dom=True),
    )
    report = _make_report(backend=backend, browser=browser)
    summary = build_summary(report)

    # 3 enterprise from backend + 1 from shadow_dom = 4 enterprise signals
    assert summary.maturity_rating == "enterprise"
