import pytest

from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpResponse
from stacklens.infrastructure.analysers.frontend_analyser import FrontendAnalyser


class FakeHttpClient:
    def __init__(self, response: HttpResponse):
        self._response = response

    async def get(self, url, *, follow_redirects=True):
        return self._response

    async def head(self, url, *, follow_redirects=True):
        return self._response

    async def options(self, url, *, follow_redirects=True):
        return self._response

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_detects_react_and_nextjs():
    html = """
    <html><head></head><body>
    <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
    <div data-reactroot="">Hello</div>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Next.js" in names
    assert "React" in names


@pytest.mark.asyncio
async def test_detects_vue():
    html = '<html><body><div data-v-abc123>Vue app</div></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Vue" in names


@pytest.mark.asyncio
async def test_detects_analytics():
    html = """
    <html><head>
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-123"></script>
    <script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)}</script>
    <script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime()});})(window,document,'script','dataLayer','GTM-XXXX');</script>
    <noscript><iframe src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></iframe></noscript>
    </head><body><p>Content</p></body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "GA4" in names
    assert "GTM" in names


@pytest.mark.asyncio
async def test_detects_tailwind():
    html = '<html><body><div class="flex px-4 mt-2 text-sm">Tailwind</div></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Tailwind" in names


@pytest.mark.asyncio
async def test_detects_meta_generator_wordpress():
    html = '<html><head><meta name="generator" content="WordPress 6.4"></head><body><p>Blog</p></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.meta_generator == "WordPress 6.4"
    names = {d.name for d in result.detections}
    assert "WordPress" in names


@pytest.mark.asyncio
async def test_infers_spa_rendering():
    html = """
    <html><body>
    <div id="root"></div>
    <script src="/static/js/bundle.a1b2c3.js"></script>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.rendering == "spa"


@pytest.mark.asyncio
async def test_infers_ssr_rendering():
    html = """
    <html><body>
    <h1>Welcome to our website</h1>
    <p>This is a fully rendered page with lots of content that is visible without JavaScript.</p>
    <div>More content here for the user to read and interact with normally.</div>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.rendering == "ssr"


@pytest.mark.asyncio
async def test_detects_third_party_services():
    html = """
    <html><body>
    <script src="https://widget.intercom.com/widget/abc"></script>
    <script src="https://www.google.com/recaptcha/api.js"></script>
    <p>Enough content to fill the page for visitors to see and interact with.</p>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Intercom" in names
    assert "reCAPTCHA" in names


@pytest.mark.asyncio
async def test_empty_html_returns_defaults():
    resp = HttpResponse(status_code=200, headers={}, text="", url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.detections == []
    assert result.meta_generator is None
    assert result.rendering == "unknown"
    assert result.script_dependencies == []
    assert result.structured_data_types == []
    assert result.preconnect_domains == []


@pytest.mark.asyncio
async def test_detects_jquery():
    html = '<html><body><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "jQuery" in names


@pytest.mark.asyncio
async def test_detects_htmx():
    html = '<html><body><button hx-get="/api/data" hx-trigger="click">Load</button></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "HTMX" in names


@pytest.mark.asyncio
async def test_detects_stripe():
    html = '<html><body><script src="https://js.stripe.com/v3/"></script><p>Checkout page with payment form</p></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Stripe" in names


@pytest.mark.asyncio
async def test_detects_sentry():
    html = '<html><body><script src="https://browser.sentry-cdn.com/7.0.0/bundle.min.js"></script><p>App content</p></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Sentry" in names


@pytest.mark.asyncio
async def test_detects_pwa_manifest():
    html = '<html><head><link rel="manifest" href="/manifest.json"></head><body><p>PWA app</p></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Web App Manifest" in names


@pytest.mark.asyncio
async def test_detects_open_graph():
    html = """
    <html><head>
    <meta property="og:title" content="My Site">
    <meta property="og:description" content="Desc">
    <meta property="og:image" content="https://example.com/img.png">
    </head><body><p>Content</p></body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Open Graph" in names


@pytest.mark.asyncio
async def test_detects_twitter_cards():
    html = """
    <html><head>
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:site" content="@example">
    </head><body><p>Content</p></body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Twitter Cards" in names


@pytest.mark.asyncio
async def test_counts_script_tags():
    html = """
    <html><body>
    <script src="https://cdn.example.com/app.js"></script>
    <script src="https://analytics.example.com/track.js"></script>
    <script>console.log("inline")</script>
    <p>Content</p>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    script_det = [d for d in result.detections if d.name == "Script tags"]
    assert len(script_det) == 1
    assert "3 total" in script_det[0].evidence
    assert "2 external domains" in script_det[0].evidence


@pytest.mark.asyncio
async def test_detects_hotjar():
    html = '<html><body><script src="https://static.hotjar.com/c/hotjar-123.js"></script><p>Content</p></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Hotjar" in names


@pytest.mark.asyncio
async def test_detects_alpine_js():
    html = '<html><body><div x-data="{ open: false }"><button @click="open = !open">Toggle</button></div></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Alpine.js" in names


# ── New tests for deep analysis expansion ─────────────────────────


@pytest.mark.asyncio
async def test_detects_paypal():
    html = '<html><body><script src="https://www.paypal.com/sdk/js?client-id=abc"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "PayPal" in names


@pytest.mark.asyncio
async def test_detects_auth0():
    html = '<html><body><script src="https://cdn.auth0.com/js/auth0-spa-js/1.0/auth0-spa-js.production.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Auth0" in names


@pytest.mark.asyncio
async def test_detects_google_maps():
    html = '<html><body><script src="https://maps.googleapis.com/maps/api/js?key=abc"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Google Maps" in names


@pytest.mark.asyncio
async def test_detects_youtube_embed():
    html = '<html><body><iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "YouTube" in names


@pytest.mark.asyncio
async def test_detects_google_fonts():
    html = '<html><head><link href="https://fonts.googleapis.com/css2?family=Roboto" rel="stylesheet"></head><body></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Google Fonts" in names


@pytest.mark.asyncio
async def test_detects_shopify():
    html = '<html><body><script src="https://cdn.shopify.com/s/files/1/theme.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Shopify" in names


@pytest.mark.asyncio
async def test_detects_new_relic():
    html = '<html><body><script>window.NREUM||(NREUM={})</script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "New Relic" in names


@pytest.mark.asyncio
async def test_detects_cookiebot():
    html = '<html><body><script src="https://consent.cookiebot.com/uc.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "CookieBot" in names


@pytest.mark.asyncio
async def test_extracts_cdn_script_dependencies():
    html = """
    <html><body>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
    <script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>
    </body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    deps_by_name = {d.name: d for d in result.script_dependencies}
    assert "lodash.js" in deps_by_name
    assert deps_by_name["lodash.js"].version == "4.17.21"
    assert deps_by_name["lodash.js"].cdn == "cdnjs"
    assert "axios" in deps_by_name
    assert deps_by_name["axios"].version == "1.6.0"
    assert deps_by_name["axios"].cdn == "jsdelivr"
    assert "react" in deps_by_name
    assert deps_by_name["react"].version == "18.2.0"
    assert deps_by_name["react"].cdn == "unpkg"


@pytest.mark.asyncio
async def test_extracts_json_ld_structured_data():
    html = """
    <html><head>
    <script type="application/ld+json">{"@type": "Organization", "name": "Example"}</script>
    <script type="application/ld+json">{"@type": "WebSite", "url": "https://example.com"}</script>
    </head><body></body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Organization" in result.structured_data_types
    assert "WebSite" in result.structured_data_types


@pytest.mark.asyncio
async def test_extracts_preconnect_domains():
    html = """
    <html><head>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="dns-prefetch" href="https://cdn.example.com">
    <link rel="preconnect" href="https://api.example.com">
    </head><body></body></html>
    """
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "fonts.googleapis.com" in result.preconnect_domains
    assert "cdn.example.com" in result.preconnect_domains
    assert "api.example.com" in result.preconnect_domains


@pytest.mark.asyncio
async def test_detects_cloudinary():
    html = '<html><body><img src="https://res.cloudinary.com/demo/image/upload/sample.jpg"></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Cloudinary" in names


@pytest.mark.asyncio
async def test_detects_socket_io():
    html = '<html><body><script src="/socket.io/socket.io.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = FrontendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    names = {d.name for d in result.detections}
    assert "Socket.io" in names
