from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from stacklens.domain.models.browser import (
    BrowserResult,
    ConsoleSnapshot,
    CookieInfo,
    DomSnapshot,
    FrameworkData,
    GraphQLQuery,
    NetworkRequest,
    NetworkSummary,
    PerformanceMetrics,
    StorageSummary,
    WebSocketConnection,
)
from stacklens.domain.models.target import AnalysisTarget

_MAX_REQUESTS = 500
_MAX_ERRORS = 20


class BrowserAnalyser:
    """Playwright-based runtime analyser — optional, activated via --deep."""

    @property
    def name(self) -> str:
        return "browser"

    @property
    def depends_on(self) -> list[str]:
        return []

    @property
    def timeout(self) -> float:
        return 60.0

    async def analyse(self, target: AnalysisTarget) -> BrowserResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise RuntimeError(
                "Playwright is not installed. "
                "Install it with: uv add --optional browser 'playwright>=1.40' "
                "&& uv run playwright install chromium"
            )

        start = time.monotonic()
        browser = None
        pw = None

        try:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1920, "height": 1080},
            )
            page = await context.new_page()

            collectors = _Collectors()
            self._setup_listeners(page, collectors)
            final_url = await self._navigate(page, target.url)
            performance = await self._collect_performance(page)
            runtime = await self._collect_runtime_js(page)
            storage = await self._collect_storage(page, context)

            elapsed_ms = (time.monotonic() - start) * 1000

            requests = self._build_requests(collectors, target.hostname)
            network = self._build_network_summary(requests, target.hostname)

            framework_data = FrameworkData(
                next_data=runtime.get("next_data", False),
                nuxt_data=runtime.get("nuxt_data", False),
                remix_context=runtime.get("remix_context", False),
                service_worker_active=runtime.get("service_worker_active", False),
                global_objects=runtime.get("global_objects", []),
                browser_features=runtime.get("browser_features", []),
            )

            dom = DomSnapshot(
                total_elements=runtime.get("total_elements", 0),
                iframe_sources=runtime.get("iframe_sources", []),
                has_shadow_dom=runtime.get("has_shadow_dom", False),
                lazy_image_count=runtime.get("lazy_image_count", 0),
                rendered_html_length=runtime.get("rendered_html_length", 0),
            )

            console = ConsoleSnapshot(
                error_count=collectors.error_count,
                warning_count=collectors.warning_count,
                errors=collectors.errors[:_MAX_ERRORS],
                uncaught_exceptions=collectors.uncaught_exceptions[:_MAX_ERRORS],
            )

            websockets = [
                WebSocketConnection(
                    url=ws["url"],
                    frames_sent=ws["frames_sent"],
                    frames_received=ws["frames_received"],
                )
                for ws in collectors.websockets
            ]

            return BrowserResult(
                network=network,
                requests=requests[:_MAX_REQUESTS],
                framework_data=framework_data,
                performance=performance,
                storage=storage,
                websockets=websockets,
                console=console,
                dom=dom,
                page_title=runtime.get("page_title", ""),
                final_url=final_url,
                elapsed_ms=elapsed_ms,
            )
        finally:
            if browser:
                await browser.close()
            if pw:
                await pw.stop()

    def _setup_listeners(self, page: Any, collectors: _Collectors) -> None:
        def on_request(request: Any) -> None:
            collectors.request_starts[request.url] = {
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "start_time": time.monotonic(),
            }

        def on_response(response: Any) -> None:
            url = response.url
            entry = collectors.request_starts.get(url, {})
            start_time = entry.get("start_time", time.monotonic())
            timing_ms = (time.monotonic() - start_time) * 1000

            collectors.responses.append({
                "url": url,
                "method": entry.get("method", "GET"),
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "resource_type": entry.get("resource_type", "other"),
                "transfer_size": int(response.headers.get("content-length", 0)),
                "timing_ms": timing_ms,
                "protocol": response.headers.get(":status", None),
            })

        def on_websocket(ws: Any) -> None:
            ws_data: dict[str, Any] = {
                "url": ws.url,
                "frames_sent": 0,
                "frames_received": 0,
            }
            collectors.websockets.append(ws_data)

            def on_frame_sent(_: Any) -> None:
                ws_data["frames_sent"] += 1

            def on_frame_received(_: Any) -> None:
                ws_data["frames_received"] += 1

            ws.on("framesent", on_frame_sent)
            ws.on("framereceived", on_frame_received)

        def on_console(msg: Any) -> None:
            if msg.type == "error":
                collectors.error_count += 1
                if len(collectors.errors) < _MAX_ERRORS:
                    collectors.errors.append(msg.text)
            elif msg.type == "warning":
                collectors.warning_count += 1

        def on_page_error(exc: Any) -> None:
            collectors.uncaught_exceptions.append(str(exc))

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("websocket", on_websocket)
        page.on("console", on_console)
        page.on("pageerror", on_page_error)

    async def _navigate(self, page: Any, url: str) -> str:
        try:
            await page.goto(url, wait_until="networkidle", timeout=45000)
        except Exception:
            try:
                await page.goto(url, wait_until="load", timeout=45000)
            except Exception:
                pass
        return page.url

    async def _collect_performance(self, page: Any) -> PerformanceMetrics:
        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("Performance.enable")
            cdp_metrics = await cdp.send("Performance.getMetrics")
            await cdp.detach()

            metric_map: dict[str, float] = {}
            for m in cdp_metrics.get("metrics", []):
                metric_map[m["name"]] = m["value"]

            nav_timing = await page.evaluate("""() => {
                const nav = performance.getEntriesByType('navigation')[0];
                if (!nav) return {};
                return {
                    ttfb: nav.responseStart - nav.startTime,
                    domInteractive: nav.domInteractive,
                    domComplete: nav.domComplete,
                    loadEvent: nav.loadEventEnd,
                    transferSize: nav.transferSize || 0,
                };
            }""")

            fcp = metric_map.get("FirstContentfulPaint")
            lcp = metric_map.get("LargestContentfulPaint")

            cls_val = await page.evaluate("""() => {
                return new Promise(resolve => {
                    let cls = 0;
                    const observer = new PerformanceObserver(list => {
                        for (const entry of list.getEntries()) {
                            if (!entry.hadRecentInput) cls += entry.value;
                        }
                    });
                    try {
                        observer.observe({type: 'layout-shift', buffered: true});
                    } catch(e) {}
                    setTimeout(() => { observer.disconnect(); resolve(cls); }, 100);
                });
            }""")

            total_weight = await page.evaluate("""() => {
                const entries = performance.getEntriesByType('resource');
                return entries.reduce((sum, e) => sum + (e.transferSize || 0), 0)
                    + (performance.getEntriesByType('navigation')[0]?.transferSize || 0);
            }""")

            return PerformanceMetrics(
                ttfb_ms=nav_timing.get("ttfb"),
                fcp_ms=fcp * 1000 if fcp and fcp > 0 else None,
                lcp_ms=lcp * 1000 if lcp and lcp > 0 else None,
                cls=cls_val if isinstance(cls_val, (int, float)) else None,
                dom_interactive_ms=nav_timing.get("domInteractive"),
                dom_complete_ms=nav_timing.get("domComplete"),
                load_event_ms=nav_timing.get("loadEvent"),
                total_page_weight_bytes=int(total_weight) if total_weight else 0,
            )
        except Exception:
            return PerformanceMetrics()

    async def _collect_runtime_js(self, page: Any) -> dict[str, Any]:
        try:
            return await page.evaluate("""() => {
                const result = {};

                // Framework detection
                result.next_data = !!window.__NEXT_DATA__;
                result.nuxt_data = !!window.__NUXT__;
                result.remix_context = !!window.__remixContext;

                // Service worker
                try {
                    result.service_worker_active = !!(navigator.serviceWorker && navigator.serviceWorker.controller);
                } catch(e) { result.service_worker_active = false; }

                // Global objects
                const globals = [];
                if (window.React || document.querySelector('[data-reactroot]') || document.querySelector('#__next')) globals.push('React');
                if (window.Vue || window.__VUE__) globals.push('Vue');
                if (window.angular || window.ng) globals.push('Angular');
                if (window.Shopify) globals.push('Shopify');
                if (window.Stripe) globals.push('Stripe');
                if (window.firebase) globals.push('Firebase');
                if (window.jQuery || window.$?.fn?.jquery) globals.push('jQuery');
                result.global_objects = globals;

                // Browser features
                const features = [];
                if (typeof WebSocket !== 'undefined') features.push('WebSocket');
                if (typeof SharedWorker !== 'undefined') features.push('SharedWorker');
                if (typeof indexedDB !== 'undefined') features.push('indexedDB');
                if (typeof BroadcastChannel !== 'undefined') features.push('BroadcastChannel');
                result.browser_features = features;

                // DOM stats
                result.total_elements = document.querySelectorAll('*').length;
                result.iframe_sources = Array.from(document.querySelectorAll('iframe[src]'))
                    .map(f => f.src).filter(Boolean).slice(0, 20);
                result.has_shadow_dom = !!document.querySelector('*');
                // Check for actual shadow DOM usage
                let hasShadow = false;
                document.querySelectorAll('*').forEach(el => {
                    if (el.shadowRoot) hasShadow = true;
                });
                result.has_shadow_dom = hasShadow;
                result.lazy_image_count = document.querySelectorAll('img[loading="lazy"]').length;
                result.rendered_html_length = document.documentElement.outerHTML.length;
                result.page_title = document.title || '';

                return result;
            }""")
        except Exception:
            return {}

    async def _collect_storage(self, page: Any, context: Any) -> StorageSummary:
        try:
            cookies_raw = await context.cookies()
            cookies = [
                CookieInfo(
                    name=c.get("name", ""),
                    domain=c.get("domain", ""),
                    path=c.get("path", "/"),
                    expires=c.get("expires", None),
                    secure=c.get("secure", False),
                    http_only=c.get("httpOnly", False),
                    same_site=c.get("sameSite", None),
                )
                for c in cookies_raw
            ]

            storage_data = await page.evaluate("""() => {
                const result = {local_storage_keys: [], session_storage_keys: []};
                try {
                    for (let i = 0; i < localStorage.length; i++)
                        result.local_storage_keys.push(localStorage.key(i));
                } catch(e) {}
                try {
                    for (let i = 0; i < sessionStorage.length; i++)
                        result.session_storage_keys.push(sessionStorage.key(i));
                } catch(e) {}
                return result;
            }""")

            return StorageSummary(
                cookies=cookies,
                cookie_count=len(cookies),
                local_storage_keys=storage_data.get("local_storage_keys", []),
                session_storage_keys=storage_data.get("session_storage_keys", []),
            )
        except Exception:
            return StorageSummary()

    def _build_requests(
        self, collectors: _Collectors, target_hostname: str
    ) -> list[NetworkRequest]:
        target_domain = self._registrable_domain(target_hostname)
        requests: list[NetworkRequest] = []
        for resp in collectors.responses:
            parsed = urlparse(resp["url"])
            domain = parsed.hostname or ""
            is_third_party = self._registrable_domain(domain) != target_domain
            requests.append(
                NetworkRequest(
                    url=resp["url"],
                    method=resp["method"],
                    status=resp["status"],
                    content_type=resp.get("content_type", ""),
                    protocol=resp.get("protocol"),
                    resource_type=resp.get("resource_type", "other"),
                    transfer_size=resp.get("transfer_size", 0),
                    timing_ms=resp.get("timing_ms", 0),
                    is_third_party=is_third_party,
                    domain=domain,
                )
            )
        return requests

    def _build_network_summary(
        self, requests: list[NetworkRequest], target_hostname: str
    ) -> NetworkSummary:
        total_transfer = sum(r.transfer_size for r in requests)
        first_party = [r for r in requests if not r.is_third_party]
        third_party = [r for r in requests if r.is_third_party]

        by_type: dict[str, int] = {}
        for r in requests:
            rt = r.resource_type or "other"
            by_type[rt] = by_type.get(rt, 0) + 1

        third_party_domains = sorted(set(r.domain for r in third_party if r.domain))

        # GraphQL detection
        graphql_queries: list[GraphQLQuery] = []
        for r in requests:
            if r.method == "POST" and "/graphql" in (r.url or ""):
                graphql_queries.append(
                    GraphQLQuery(endpoint=r.url)
                )

        # SSE detection
        streaming: list[str] = []
        for r in requests:
            ct = r.content_type or ""
            if "text/event-stream" in ct:
                streaming.append(r.url)

        # Protocols
        protocols = sorted(set(
            r.protocol for r in requests if r.protocol
        ))

        return NetworkSummary(
            total_requests=len(requests),
            total_transfer_bytes=total_transfer,
            first_party_requests=len(first_party),
            third_party_requests=len(third_party),
            requests_by_type=by_type,
            third_party_domains=third_party_domains,
            graphql_queries=graphql_queries,
            streaming_endpoints=streaming,
            protocols_used=protocols,
        )

    @staticmethod
    def _registrable_domain(hostname: str) -> str:
        """Extract the registrable domain (eTLD+1) using a simple heuristic."""
        if not hostname:
            return ""
        parts = hostname.rstrip(".").split(".")
        if len(parts) <= 2:
            return hostname.lower()

        # Handle known two-part TLDs
        _TWO_PART_TLDS = {
            "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
            "com.au", "com.br", "com.cn", "com.mx", "com.tw", "com.sg",
            "org.uk", "net.au", "ac.uk", "gov.uk", "ne.jp", "or.jp",
        }
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in _TWO_PART_TLDS:
            return ".".join(parts[-3:]).lower() if len(parts) >= 3 else hostname.lower()
        return ".".join(parts[-2:]).lower()


class _Collectors:
    """Mutable state bag for Playwright event listeners."""

    def __init__(self) -> None:
        self.request_starts: dict[str, dict[str, Any]] = {}
        self.responses: list[dict[str, Any]] = []
        self.websockets: list[dict[str, Any]] = []
        self.error_count: int = 0
        self.warning_count: int = 0
        self.errors: list[str] = []
        self.uncaught_exceptions: list[str] = []
