import pytest

from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpResponse
from stacklens.infrastructure.analysers.backend_analyser import BackendAnalyser


class FakeHttpClient:
    """Fake HTTP client that returns configurable responses for GET and HEAD."""

    def __init__(
        self,
        get_response: HttpResponse,
        head_responses: dict[str, HttpResponse] | None = None,
    ):
        self._get_response = get_response
        self._head_responses = head_responses or {}

    async def get(self, url, *, follow_redirects=True):
        return self._get_response

    async def head(self, url, *, follow_redirects=True):
        if url in self._head_responses:
            return self._head_responses[url]
        return HttpResponse(status_code=404, headers={}, text="", url=url)

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_detects_framework_from_cookies():
    resp = HttpResponse(
        status_code=200,
        headers={"Set-Cookie": "laravel_session=abc123; path=/"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Laravel" in result.server_framework


@pytest.mark.asyncio
async def test_detects_framework_from_powered_by():
    resp = HttpResponse(
        status_code=200,
        headers={"X-Powered-By": "Express"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Express" in result.server_framework


@pytest.mark.asyncio
async def test_detects_wordpress_cms():
    html = '<html><body><link rel="stylesheet" href="/wp-content/themes/default/style.css"></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "WordPress" in result.cms


@pytest.mark.asyncio
async def test_detects_aws_cloud():
    resp = HttpResponse(
        status_code=200,
        headers={"x-amzn-requestid": "abc-123-def"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "AWS" in result.cloud_provider


@pytest.mark.asyncio
async def test_detects_cloudflare_waf():
    resp = HttpResponse(
        status_code=200,
        headers={"cf-ray": "abc123-LAX", "Server": "cloudflare"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Cloudflare" in result.waf


@pytest.mark.asyncio
async def test_endpoint_probing():
    get_resp = HttpResponse(
        status_code=200, headers={}, text="<html><body></body></html>", url="https://example.com"
    )
    head_responses = {
        "https://example.com/api": HttpResponse(status_code=200, headers={}, text="", url=""),
        "https://example.com/graphql": HttpResponse(status_code=405, headers={}, text="", url=""),
        "https://example.com/sitemap.xml": HttpResponse(status_code=200, headers={}, text="", url=""),
    }
    analyser = BackendAnalyser(FakeHttpClient(get_resp, head_responses))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    probes_by_path = {p.path: p for p in result.endpoint_probes}
    assert probes_by_path["/api"].accessible is True
    assert probes_by_path["/graphql"].accessible is False
    assert probes_by_path["/sitemap.xml"].accessible is True
    assert probes_by_path["/swagger/"].accessible is False


@pytest.mark.asyncio
async def test_detects_django_from_cookie():
    resp = HttpResponse(
        status_code=200,
        headers={"Set-Cookie": "csrftoken=abc123; path=/"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Django" in result.server_framework


@pytest.mark.asyncio
async def test_detects_azure_cloud():
    resp = HttpResponse(
        status_code=200,
        headers={"x-azure-ref": "abc123"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Azure" in result.cloud_provider


@pytest.mark.asyncio
async def test_empty_response_returns_defaults():
    resp = HttpResponse(status_code=200, headers={}, text="", url="https://example.com")
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.server_framework == []
    assert result.cms == []
    assert result.cloud_provider == []
    assert result.waf == []
    assert len(result.endpoint_probes) == 7  # All probed, all inaccessible
