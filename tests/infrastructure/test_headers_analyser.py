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

    assert result.score == 1.0
