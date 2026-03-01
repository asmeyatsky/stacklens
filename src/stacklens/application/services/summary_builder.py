from __future__ import annotations

from stacklens.domain.models.backend import BackendResult
from stacklens.domain.models.dns import DnsResult
from stacklens.domain.models.frontend import FrontendResult
from stacklens.domain.models.headers import HeadersResult
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.summary import ScanSummary
from stacklens.domain.models.tls import TlsResult


def build_summary(report: AnalysisReport) -> ScanSummary:
    """Produce a cross-layer summary from a completed AnalysisReport."""
    hosting = _resolve_hosting(report)
    tech_stack = _resolve_tech_stack(report)
    security_posture = _resolve_security(report)
    key_findings = _resolve_key_findings(report)
    architecture = _resolve_architecture(report)
    integrations = _resolve_integrations(report)
    api_stack = _resolve_api_stack(report)
    data_storage = _resolve_data_storage(report)
    maturity_rating = _rate_maturity(report)

    return ScanSummary(
        hosting=hosting,
        tech_stack=tech_stack,
        security_posture=security_posture,
        key_findings=key_findings,
        architecture=architecture,
        integrations=integrations,
        api_stack=api_stack,
        data_storage=data_storage,
        maturity_rating=maturity_rating,
    )


def _resolve_hosting(report: AnalysisReport) -> str:
    parts: list[str] = []

    dns_result = report.layers.get("dns")
    if isinstance(dns_result, DnsResult):
        if dns_result.hosting_provider:
            parts.append(dns_result.hosting_provider)
        if dns_result.cdn_detected:
            parts.append(dns_result.cdn_detected)

    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        for cp in backend_result.cloud_provider:
            if cp not in parts:
                parts.append(cp)

    return " + ".join(parts) if parts else "Unknown"


def _resolve_tech_stack(report: AnalysisReport) -> list[str]:
    stack: list[str] = []

    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        if backend_result.server_software:
            stack.append(backend_result.server_software)
        for gw in backend_result.proxy_gateway:
            if gw not in stack:
                stack.append(gw)
        for fw in backend_result.server_framework:
            if fw not in stack:
                stack.append(fw)
        for cms in backend_result.cms:
            if cms not in stack:
                stack.append(cms)

    frontend_result = report.layers.get("frontend")
    if isinstance(frontend_result, FrontendResult):
        for d in frontend_result.detections:
            if d.category in ("js_framework", "css_framework", "cms"):
                if d.name not in stack:
                    stack.append(d.name)
        if frontend_result.rendering != "unknown":
            stack.append(f"{frontend_result.rendering.upper()} rendering")

    return stack


def _resolve_security(report: AnalysisReport) -> str:
    parts: list[str] = []

    headers_result = report.layers.get("headers")
    if isinstance(headers_result, HeadersResult):
        pct = int(headers_result.score * 100)
        parts.append(f"Headers {pct}%")

    tls_result = report.layers.get("tls")
    if isinstance(tls_result, TlsResult):
        parts.append(tls_result.protocol)
        if tls_result.certificate:
            parts.append(f"Issued by {tls_result.certificate.issuer}")
        if tls_result.hsts:
            parts.append("HSTS")

    return ", ".join(parts) if parts else "Unknown"


def _resolve_key_findings(report: AnalysisReport) -> list[str]:
    findings: list[str] = []

    dns_result = report.layers.get("dns")
    if isinstance(dns_result, DnsResult):
        if dns_result.hosting_provider:
            findings.append(f"DNS hosted on {dns_result.hosting_provider}")
        if dns_result.email_provider:
            findings.append(f"Email via {dns_result.email_provider}")
        if dns_result.cdn_detected:
            findings.append(f"CDN: {dns_result.cdn_detected}")

    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        if backend_result.server_software:
            findings.append(f"Server: {backend_result.server_software}")
        if backend_result.proxy_gateway:
            findings.append(f"Gateway: {', '.join(backend_result.proxy_gateway)}")
        if backend_result.tracing:
            findings.append(f"Tracing: {', '.join(backend_result.tracing)}")
        for hint in backend_result.infra_hints:
            findings.append(hint)
        if backend_result.waf:
            findings.append(f"WAF: {', '.join(backend_result.waf)}")

    frontend_result = report.layers.get("frontend")
    if isinstance(frontend_result, FrontendResult):
        js_frameworks = [d.name for d in frontend_result.detections if d.category == "js_framework"]
        if js_frameworks:
            findings.append(f"Frontend: {', '.join(js_frameworks)}")

    tls_result = report.layers.get("tls")
    if isinstance(tls_result, TlsResult):
        if tls_result.days_until_expiry is not None and tls_result.days_until_expiry < 30:
            findings.append(f"TLS certificate expires in {tls_result.days_until_expiry} days!")

    return findings


def _resolve_architecture(report: AnalysisReport) -> list[str]:
    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        return list(backend_result.architecture)
    return []


def _resolve_integrations(report: AnalysisReport) -> list[str]:
    """Aggregate integrations from all layers, deduplicated."""
    integrations: list[str] = []

    def _add(name: str) -> None:
        if name not in integrations:
            integrations.append(name)

    frontend_result = report.layers.get("frontend")
    if isinstance(frontend_result, FrontendResult):
        _integration_categories = {
            "payment", "auth", "maps", "video", "fonts", "image_cdn",
            "communication", "ecommerce", "monitoring", "consent",
            "analytics", "third_party",
        }
        for d in frontend_result.detections:
            if d.category in _integration_categories:
                _add(d.name)

    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        for ap in backend_result.auth_providers:
            _add(ap)

    dns_result = report.layers.get("dns")
    if isinstance(dns_result, DnsResult):
        for svc in dns_result.dns_services:
            _add(svc)
        for spf in dns_result.spf_includes:
            _add(spf)

    return integrations


def _resolve_api_stack(report: AnalysisReport) -> list[str]:
    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        return list(backend_result.api_signals)
    return []


def _resolve_data_storage(report: AnalysisReport) -> list[str]:
    storage: list[str] = []
    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        for db in backend_result.database_hints:
            if db not in storage:
                storage.append(db)
        # Also add caching layer technologies (not full cache directives)
        for c in backend_result.caching:
            for tech in ("Varnish", "CloudFront", "Fastly", "Redis"):
                if tech.lower() in c.lower() and tech not in storage:
                    storage.append(tech)
    return storage


def _rate_maturity(report: AnalysisReport) -> str:
    """Rate maturity as enterprise/growth/startup based on signal breadth."""
    enterprise_signals = 0
    growth_signals = 0

    backend_result = report.layers.get("backend")
    if isinstance(backend_result, BackendResult):
        if backend_result.tracing:
            enterprise_signals += 1
        if any("mesh" in a.lower() for a in backend_result.architecture):
            enterprise_signals += 1
        if backend_result.waf:
            enterprise_signals += 1

    dns_result = report.layers.get("dns")
    if isinstance(dns_result, DnsResult):
        if dns_result.dmarc_policy == "reject":
            enterprise_signals += 1
        if dns_result.caa_issuers:
            enterprise_signals += 1
        if dns_result.cdn_detected:
            growth_signals += 1

    tls_result = report.layers.get("tls")
    if isinstance(tls_result, TlsResult):
        if tls_result.is_ev:
            enterprise_signals += 1

    frontend_result = report.layers.get("frontend")
    if isinstance(frontend_result, FrontendResult):
        monitoring = [d for d in frontend_result.detections if d.category == "monitoring"]
        if monitoring:
            growth_signals += 1
        auth = [d for d in frontend_result.detections if d.category == "auth"]
        if auth:
            growth_signals += 1

    if enterprise_signals >= 3:
        return "enterprise"
    if enterprise_signals >= 1 or growth_signals >= 2:
        return "growth"
    if growth_signals >= 1:
        return "growth"
    return "startup"
