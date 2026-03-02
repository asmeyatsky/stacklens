"""Analyse report data and produce prioritised, actionable recommendations."""

from __future__ import annotations

from stacklens.domain.models.backend import BackendResult
from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.dns import DnsResult
from stacklens.domain.models.frontend import FrontendResult
from stacklens.domain.models.headers import HeadersResult
from stacklens.domain.models.recommendations import Recommendation, Recommendations
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.tls import TlsResult

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def build_recommendations(report: AnalysisReport) -> Recommendations:
    items: list[Recommendation] = []

    items.extend(_performance_rules(report))
    items.extend(_security_rules(report))
    items.extend(_best_practices_rules(report))
    items.extend(_infrastructure_rules(report))

    items.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 99))
    return Recommendations(items=items)


# ── Performance ────────────────────────────────────────────────


def _performance_rules(report: AnalysisReport) -> list[Recommendation]:
    recs: list[Recommendation] = []
    ps = report.performance_score

    browser = report.layers.get("browser")
    browser_data = browser if isinstance(browser, BrowserResult) else None
    perf = browser_data.performance if browser_data else None

    # CLS
    if perf and perf.cls is not None:
        if perf.cls > 0.25:
            recs.append(Recommendation(
                category="performance",
                severity="critical",
                title="Reduce Cumulative Layout Shift",
                description=f"CLS is {perf.cls:.3f}, which is considered poor (>0.25).",
                impact="Layout shifts frustrate users and hurt Core Web Vitals scores.",
                action="Reserve space for images and ads with explicit width/height or CSS aspect-ratio. Avoid inserting content above existing content.",
            ))
        elif perf.cls > 0.1:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve Cumulative Layout Shift",
                description=f"CLS is {perf.cls:.3f}, which needs improvement (>0.1).",
                impact="Layout shifts degrade user experience and Core Web Vitals.",
                action="Reserve space for images and ads with explicit width/height or CSS aspect-ratio.",
            ))

    # LCP
    if perf and perf.lcp_ms is not None:
        if perf.lcp_ms > 4000:
            recs.append(Recommendation(
                category="performance",
                severity="critical",
                title="Optimise Largest Contentful Paint",
                description=f"LCP is {perf.lcp_ms:.0f}ms, which is poor (>4000ms).",
                impact="Slow LCP means users wait too long to see the main content.",
                action="Preload the hero image, serve assets from a CDN, reduce server response time, and optimise image formats.",
            ))
        elif perf.lcp_ms > 2500:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve Largest Contentful Paint",
                description=f"LCP is {perf.lcp_ms:.0f}ms, which needs improvement (>2500ms).",
                impact="Users may perceive the page as slow to load.",
                action="Preload the hero image, use modern image formats (WebP/AVIF), and consider a CDN.",
            ))

    # TBT
    if perf and perf.tbt_ms is not None:
        if perf.tbt_ms > 600:
            recs.append(Recommendation(
                category="performance",
                severity="critical",
                title="Reduce Total Blocking Time",
                description=f"TBT is {perf.tbt_ms:.0f}ms, which is poor (>600ms).",
                impact="High blocking time makes the page unresponsive to user input.",
                action="Code-split JavaScript bundles, defer non-critical scripts, and consider web workers for heavy computation.",
            ))
        elif perf.tbt_ms > 300:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve Total Blocking Time",
                description=f"TBT is {perf.tbt_ms:.0f}ms, which needs improvement (>300ms).",
                impact="Blocking time can make the page feel sluggish.",
                action="Defer non-critical JavaScript and break up long tasks.",
            ))

    # FCP
    if perf and perf.fcp_ms is not None:
        if perf.fcp_ms > 3000:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve First Contentful Paint",
                description=f"FCP is {perf.fcp_ms:.0f}ms, which is poor (>3000ms).",
                impact="Users see a blank screen for too long before any content appears.",
                action="Inline critical CSS, reduce render-blocking resources, and use font-display: swap.",
            ))
        elif perf.fcp_ms > 1800:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve First Contentful Paint",
                description=f"FCP is {perf.fcp_ms:.0f}ms, which needs improvement (>1800ms).",
                impact="Users may perceive the page as slow to start rendering.",
                action="Inline critical CSS and reduce render-blocking resources.",
            ))

    # TTFB
    if perf and perf.ttfb_ms is not None:
        if perf.ttfb_ms > 1800:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve Server Response Time (TTFB)",
                description=f"TTFB is {perf.ttfb_ms:.0f}ms, which is poor (>1800ms).",
                impact="Slow server response delays every subsequent metric.",
                action="Use a CDN, optimise backend processing, enable server-side caching, and consider edge rendering.",
            ))
        elif perf.ttfb_ms > 800:
            recs.append(Recommendation(
                category="performance",
                severity="warning",
                title="Improve Server Response Time (TTFB)",
                description=f"TTFB is {perf.ttfb_ms:.0f}ms, which needs improvement (>800ms).",
                impact="Server response time affects all downstream metrics.",
                action="Consider a CDN or server-side caching to reduce TTFB.",
            ))

    # Render-blocking resources — only flag if there are many
    if ps and ps.render_blocking_count > 5:
        recs.append(Recommendation(
            category="performance",
            severity="warning",
            title="Defer Render-Blocking Resources",
            description=f"{ps.render_blocking_count} render-blocking resource(s) detected.",
            impact="Render-blocking resources delay first paint.",
            action="Add async or defer attributes to scripts, and use media queries on stylesheets that are not critical.",
        ))

    # Script bundle size
    if ps and ps.resource_breakdown.get("script", 0) > 1_048_576:
        script_mb = ps.resource_breakdown["script"] / 1_048_576
        recs.append(Recommendation(
            category="performance",
            severity="warning",
            title="Reduce JavaScript Payload",
            description=f"Total script size is {script_mb:.1f} MB (>1 MB).",
            impact="Large JavaScript payloads increase parse time and delay interactivity.",
            action="Code-split bundles, tree-shake unused code, and lazy-load non-critical modules.",
        ))

    # Page weight
    if ps and ps.page_weight_bytes > 5_242_880:
        weight_mb = ps.page_weight_bytes / 1_048_576
        recs.append(Recommendation(
            category="performance",
            severity="warning",
            title="Reduce Total Page Weight",
            description=f"Total page weight is {weight_mb:.1f} MB (>5 MB).",
            impact="Heavy pages consume bandwidth and load slowly, especially on mobile.",
            action="Optimise images, enable compression, and remove unused assets.",
        ))

    # Third-party ratio
    if ps and ps.third_party_ratio > 0.5:
        recs.append(Recommendation(
            category="performance",
            severity="warning",
            title="High Third-Party Dependency",
            description=f"{ps.third_party_ratio:.0%} of requests are third-party.",
            impact="Third-party scripts are outside your control and can slow the page.",
            action="Audit third-party scripts, remove unnecessary ones, and self-host critical resources.",
        ))

    # Total requests
    if ps and ps.total_requests > 100:
        recs.append(Recommendation(
            category="performance",
            severity="info",
            title="Consider Reducing HTTP Requests",
            description=f"Page makes {ps.total_requests} requests.",
            impact="Many requests can slow page load due to connection overhead.",
            action="Bundle assets, use image sprites or inline SVGs, and lazy-load below-the-fold content.",
        ))

    return recs


# ── Security ───────────────────────────────────────────────────


def _security_rules(report: AnalysisReport) -> list[Recommendation]:
    recs: list[Recommendation] = []

    headers = report.layers.get("headers")
    headers_data = headers if isinstance(headers, HeadersResult) else None

    tls = report.layers.get("tls")
    tls_data = tls if isinstance(tls, TlsResult) else None

    # Header score
    if headers_data and headers_data.score < 0.5:
        recs.append(Recommendation(
            category="security",
            severity="critical",
            title="Add Missing Security Headers",
            description=f"Security header score is {headers_data.score:.0%}, below the 50% threshold.",
            impact="Missing security headers leave the site vulnerable to common attacks like XSS and clickjacking.",
            action="Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and other recommended headers.",
        ))

    # Individual missing headers
    if headers_data:
        header_map = {h.name.lower(): h for h in headers_data.security_headers}

        csp = header_map.get("content-security-policy")
        if csp and not csp.present:
            recs.append(Recommendation(
                category="security",
                severity="warning",
                title="Add Content-Security-Policy",
                description="No Content-Security-Policy header detected.",
                impact="CSP helps prevent XSS attacks by controlling which resources can be loaded.",
                action="Define a Content-Security-Policy that whitelists trusted sources for scripts, styles, and other resources.",
            ))

        hsts = header_map.get("strict-transport-security")
        if hsts and not hsts.present:
            recs.append(Recommendation(
                category="security",
                severity="warning",
                title="Enable Strict-Transport-Security",
                description="No Strict-Transport-Security (HSTS) header detected.",
                impact="Without HSTS, users may be vulnerable to protocol downgrade attacks.",
                action="Add Strict-Transport-Security header with a max-age of at least 31536000 and include includeSubDomains.",
            ))

        xcto = header_map.get("x-content-type-options")
        if xcto and not xcto.present:
            recs.append(Recommendation(
                category="security",
                severity="info",
                title="Add X-Content-Type-Options",
                description="X-Content-Type-Options header is missing.",
                impact="Browsers may MIME-sniff responses, potentially executing malicious content.",
                action="Add the header X-Content-Type-Options: nosniff.",
            ))

        # Removed Referrer-Policy and Permissions-Policy — they fire on most
        # sites and are low-impact info-level items that add noise.

    # TLS certificate expiry
    if tls_data and tls_data.days_until_expiry is not None and tls_data.days_until_expiry < 30:
        recs.append(Recommendation(
            category="security",
            severity="critical",
            title="TLS Certificate Expiring Soon",
            description=f"Certificate expires in {tls_data.days_until_expiry} day(s).",
            impact="An expired certificate will cause browsers to show security warnings, blocking users.",
            action="Renew the TLS certificate immediately. Consider automated renewal with Let's Encrypt or your CA.",
        ))

    # TLS protocol version
    if tls_data and tls_data.protocol and "1.3" not in tls_data.protocol:
        recs.append(Recommendation(
            category="security",
            severity="info",
            title="Upgrade to TLS 1.3",
            description=f"Server is using {tls_data.protocol} instead of TLS 1.3.",
            impact="TLS 1.3 offers better performance (fewer round-trips) and stronger security.",
            action="Configure the server to prefer TLS 1.3. Most modern servers and clients support it.",
        ))

    # Insecure cookies
    if headers_data and headers_data.cookies:
        insecure = [c for c in headers_data.cookies if not c.secure or not c.http_only]
        if insecure:
            names = ", ".join(c.name for c in insecure[:5])
            recs.append(Recommendation(
                category="security",
                severity="warning",
                title="Secure Cookie Flags Missing",
                description=f"Cookies without Secure/HttpOnly flags: {names}.",
                impact="Cookies without Secure can be sent over HTTP; without HttpOnly they are accessible to JavaScript (XSS risk).",
                action="Set Secure and HttpOnly flags on all sensitive cookies. Use SameSite=Lax or Strict.",
            ))

    return recs


# ── Best Practices ─────────────────────────────────────────────


def _best_practices_rules(report: AnalysisReport) -> list[Recommendation]:
    recs: list[Recommendation] = []

    browser = report.layers.get("browser")
    browser_data = browser if isinstance(browser, BrowserResult) else None

    frontend = report.layers.get("frontend")
    frontend_data = frontend if isinstance(frontend, FrontendResult) else None

    # Console errors
    if browser_data and browser_data.console.error_count > 0:
        recs.append(Recommendation(
            category="best-practices",
            severity="warning",
            title="Fix JavaScript Errors",
            description=f"{browser_data.console.error_count} console error(s) detected.",
            impact="JavaScript errors can break functionality and degrade user experience.",
            action="Investigate and fix the console errors. Check the browser console output for details.",
        ))

    # Uncaught exceptions
    if browser_data and browser_data.console.uncaught_exceptions:
        recs.append(Recommendation(
            category="best-practices",
            severity="warning",
            title="Handle Uncaught Exceptions",
            description=f"{len(browser_data.console.uncaught_exceptions)} uncaught exception(s) detected.",
            impact="Uncaught exceptions can crash application features and leave users stuck.",
            action="Add error boundaries (React) or global error handlers to catch and handle exceptions gracefully.",
        ))

    # Uncaught exceptions already covered above — removed generic info-level
    # recommendations (service worker, lazy images, CSR/SSR, structured data)
    # that fire on nearly every site and add noise without actionable insight.

    return recs


# ── Infrastructure ─────────────────────────────────────────────


def _infrastructure_rules(report: AnalysisReport) -> list[Recommendation]:
    recs: list[Recommendation] = []

    dns = report.layers.get("dns")
    dns_data = dns if isinstance(dns, DnsResult) else None

    backend = report.layers.get("backend")
    backend_data = backend if isinstance(backend, BackendResult) else None

    # No CDN
    if dns_data and not dns_data.cdn_detected:
        recs.append(Recommendation(
            category="infrastructure",
            severity="warning",
            title="Use a CDN",
            description="No CDN detected for this domain.",
            impact="Without a CDN, users far from the origin server experience slower load times.",
            action="Configure a CDN (e.g. Cloudflare, Fastly, CloudFront) to cache and serve static assets globally.",
        ))

    # DMARC policy
    if dns_data and dns_data.dmarc_policy and dns_data.dmarc_policy.lower() == "none":
        recs.append(Recommendation(
            category="infrastructure",
            severity="warning",
            title="Strengthen DMARC Policy",
            description="DMARC policy is set to 'none', which only monitors without enforcement.",
            impact="A 'none' policy does not prevent email spoofing of your domain.",
            action="Upgrade the DMARC policy to 'quarantine' or 'reject' after reviewing aggregate reports.",
        ))

    # Exposed debug endpoints
    if backend_data:
        debug_paths = {"/swagger", "/graphql", "/graphiql", "/_debug", "/debug"}
        exposed = [
            p for p in backend_data.endpoint_probes
            if p.accessible and any(d in p.path.lower() for d in debug_paths)
        ]
        if exposed:
            paths = ", ".join(p.path for p in exposed)
            recs.append(Recommendation(
                category="infrastructure",
                severity="warning",
                title="Restrict Debug Endpoints",
                description=f"Debug/development endpoints are publicly accessible: {paths}.",
                impact="Exposed debug endpoints can leak internal information and provide attack vectors.",
                action="Restrict access to debug endpoints in production using authentication or IP whitelisting.",
            ))

    # Database hints exposed
    if backend_data and backend_data.database_hints:
        recs.append(Recommendation(
            category="infrastructure",
            severity="warning",
            title="Database Technology Fingerprints Exposed",
            description=f"Database hints detected: {', '.join(backend_data.database_hints)}.",
            impact="Exposing database technology makes it easier for attackers to craft targeted exploits.",
            action="Remove database-identifying headers and error messages from production responses.",
        ))

    return recs
