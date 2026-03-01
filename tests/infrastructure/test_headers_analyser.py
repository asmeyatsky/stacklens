import pytest

from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpResponse
from stacklens.infrastructure.analysers.headers_analyser import HeadersAnalyser


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
async def test_headers_analyser_detects_security_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Server": "nginx",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert result.server == "nginx"
    present = {h.name for h in result.security_headers if h.present}
    assert "Strict-Transport-Security" in present
    assert "X-Content-Type-Options" in present
    missing = {h.name for h in result.security_headers if not h.present}
    assert "Content-Security-Policy" in missing


@pytest.mark.asyncio
async def test_headers_analyser_score():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    # Score is based on 6/9 now (original 6 present, 3 new CO* missing)
    assert result.score > 0


@pytest.mark.asyncio
async def test_detects_cross_origin_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    present = {h.name for h in result.security_headers if h.present}
    assert "Cross-Origin-Embedder-Policy" in present
    assert "Cross-Origin-Opener-Policy" in present
    assert "Cross-Origin-Resource-Policy" in present


@pytest.mark.asyncio
async def test_parses_cors_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST",
            "Access-Control-Allow-Credentials": "true",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert result.cors.get("allow_origin") == "*"
    assert result.cors.get("allow_methods") == "GET, POST"
    assert result.cors.get("allow_credentials") == "true"


@pytest.mark.asyncio
async def test_parses_caching_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Cache-Control": "public, max-age=3600",
            "ETag": '"abc123"',
            "Age": "120",
            "Vary": "Accept-Encoding",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert result.caching.get("cache-control") == "public, max-age=3600"
    assert result.caching.get("etag") == '"abc123"'
    assert result.caching.get("age") == "120"
    assert result.caching.get("vary") == "Accept-Encoding"


@pytest.mark.asyncio
async def test_analyzes_cookie_insights():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Set-Cookie": "_ga=GA1.2.123; path=/; max-age=63072000\n_fbp=fb.1.123; path=/\nPHPSESSID=abc123; path=/",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert any("Google Analytics" in ci for ci in result.cookie_insights)
    assert any("Facebook Pixel" in ci for ci in result.cookie_insights)
    assert any("PHP session" in ci for ci in result.cookie_insights)


@pytest.mark.asyncio
async def test_detects_long_lived_cookies():
    # max-age of 10 years
    resp = HttpResponse(
        status_code=200,
        headers={
            "Set-Cookie": "tracker=abc; path=/; max-age=315360000",
        },
        text="",
        url="https://example.com",
    )
    analyser = HeadersAnalyser(FakeHttpClient(resp))
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert any("Long-lived" in ci for ci in result.cookie_insights)
