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
