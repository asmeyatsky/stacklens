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
        get_responses: dict[str, HttpResponse] | None = None,
    ):
        self._get_response = get_response
        self._head_responses = head_responses or {}
        self._get_responses = get_responses or {}

    async def get(self, url, *, follow_redirects=True):
        if url in self._get_responses:
            return self._get_responses[url]
        # For probe URLs (not the main target), return 404
        if url != self._get_response.url and self._get_response.url and url != self._get_response.url.rstrip("/"):
            return HttpResponse(status_code=404, headers={}, text="", url=url)
        return self._get_response

    async def head(self, url, *, follow_redirects=True):
        if url in self._head_responses:
            return self._head_responses[url]
        return HttpResponse(status_code=404, headers={}, text="", url=url)

    async def options(self, url, *, follow_redirects=True):
        return HttpResponse(status_code=200, headers={}, text="", url=url)

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
        "https://example.com/sitemap.xml": HttpResponse(status_code=200, headers={}, text="", url=""),
    }
    analyser = BackendAnalyser(FakeHttpClient(get_resp, head_responses))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    probes_by_path = {p.path: p for p in result.endpoint_probes}
    assert probes_by_path["/api"].accessible is True
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
    assert result.server_software is None
    assert result.proxy_gateway == []
    assert result.tracing == []
    assert result.infra_hints == []
    assert result.api_signals == []
    assert result.database_hints == []
    assert result.architecture == []
    assert result.caching == []
    assert result.auth_providers == []
    assert result.cookie_insights == []


# ── Enriched backend detection tests ─────────────────────────────


@pytest.mark.asyncio
async def test_detects_envoy_server_software():
    resp = HttpResponse(
        status_code=200,
        headers={"Server": "envoy"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.server_software == "Envoy"


@pytest.mark.asyncio
async def test_detects_nginx_server_software():
    resp = HttpResponse(
        status_code=200,
        headers={"Server": "nginx/1.25.3"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.server_software == "nginx"


@pytest.mark.asyncio
async def test_detects_envoy_proxy_from_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Server": "envoy",
            "x-envoy-upstream-service-time": "42",
        },
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Envoy" in result.proxy_gateway


@pytest.mark.asyncio
async def test_detects_via_header_cloudfront():
    resp = HttpResponse(
        status_code=200,
        headers={"Via": "1.1 abc123.cloudfront.net (CloudFront)"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "CloudFront" in result.proxy_gateway


@pytest.mark.asyncio
async def test_detects_b3_tracing():
    resp = HttpResponse(
        status_code=200,
        headers={"x-b3-traceid": "abc123def456", "x-b3-spanid": "789ghi"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Zipkin/Jaeger (B3)" in result.tracing


@pytest.mark.asyncio
async def test_detects_w3c_tracing():
    resp = HttpResponse(
        status_code=200,
        headers={"traceparent": "00-abc123-def456-01"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "W3C Trace Context" in result.tracing


@pytest.mark.asyncio
async def test_detects_datadog_tracing():
    resp = HttpResponse(
        status_code=200,
        headers={"x-datadog-trace-id": "12345678"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Datadog APM" in result.tracing


@pytest.mark.asyncio
async def test_detects_aws_infra_from_via_header():
    resp = HttpResponse(
        status_code=200,
        headers={"Via": "2 i-052b9a1a50092cf63 (eu-west-1)"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert len(result.infra_hints) >= 1
    assert any("EC2" in h and "eu-west-1" in h for h in result.infra_hints)


@pytest.mark.asyncio
async def test_detects_custom_header_namespace():
    resp = HttpResponse(
        status_code=200,
        headers={
            "x-netflix-request-id": "abc",
            "x-netflix-region": "us-east-1",
        },
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert any("x-netflix-" in h for h in result.infra_hints)


@pytest.mark.asyncio
async def test_detects_wordpress_from_cookie():
    resp = HttpResponse(
        status_code=200,
        headers={"Set-Cookie": "wp_settings-1=value; path=/"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "WordPress" in result.server_framework


@pytest.mark.asyncio
async def test_unknown_server_returns_raw():
    resp = HttpResponse(
        status_code=200,
        headers={"Server": "MyCustomServer/2.0"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert result.server_software == "MyCustomServer/2.0"


# ── New tests for deep analysis expansion ─────────────────────────


@pytest.mark.asyncio
async def test_detects_graphql_api_signal():
    get_resp = HttpResponse(
        status_code=200, headers={}, text="<html><body></body></html>", url="https://example.com"
    )
    get_responses = {
        "https://example.com/graphql": HttpResponse(
            status_code=200, headers={}, text='{"data":{"viewer":null}}', url=""
        ),
    }
    analyser = BackendAnalyser(FakeHttpClient(get_resp, get_responses=get_responses))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "GraphQL" in result.api_signals


@pytest.mark.asyncio
async def test_detects_websocket_in_html():
    html = '<html><body><script>var ws = new WebSocket("wss://example.com/ws")</script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "WebSocket" in result.api_signals


@pytest.mark.asyncio
async def test_detects_rest_link_pagination():
    resp = HttpResponse(
        status_code=200,
        headers={"Link": '<https://api.example.com/items?page=2>; rel="next"'},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert any("REST" in s for s in result.api_signals)


@pytest.mark.asyncio
async def test_detects_database_hints_from_error():
    get_resp = HttpResponse(
        status_code=200, headers={}, text="<html><body></body></html>", url="https://example.com"
    )
    # Simulate error page with DB leak
    error_body = "ERROR: relation \"users\" does not exist - PostgreSQL 14.2"
    get_responses = {}
    analyser = BackendAnalyser(FakeHttpClient(get_resp, get_responses=get_responses))
    # We need to mock the error page probe; instead test the static method directly
    hints = BackendAnalyser._detect_database_hints({}, error_body)
    assert "PostgreSQL" in hints


@pytest.mark.asyncio
async def test_detects_database_hints_from_headers():
    resp = HttpResponse(
        status_code=200,
        headers={"x-redis-cache": "HIT"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Redis" in result.database_hints


@pytest.mark.asyncio
async def test_infers_microservices_architecture():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Server": "envoy",
            "x-envoy-upstream-service-time": "42",
            "x-b3-traceid": "abc",
        },
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert any("Microservices" in a for a in result.architecture)
    assert any("mesh" in a.lower() for a in result.architecture)


@pytest.mark.asyncio
async def test_infers_monolith_architecture():
    resp = HttpResponse(
        status_code=200,
        headers={"X-Powered-By": "Express"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Monolith" in result.architecture


@pytest.mark.asyncio
async def test_detects_caching_headers():
    resp = HttpResponse(
        status_code=200,
        headers={
            "Cache-Control": "public, max-age=3600, s-maxage=86400",
            "X-Cache": "HIT from CloudFront",
            "Age": "120",
            "ETag": 'W/"abc123"',
        },
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert any("max-age" in c for c in result.caching)
    assert any("X-Cache" in c for c in result.caching)
    assert any("Age" in c for c in result.caching)
    assert any("ETag" in c for c in result.caching)


@pytest.mark.asyncio
async def test_detects_auth_providers_from_html():
    html = '<html><body><script src="https://cdn.auth0.com/js/auth0/9.0/auth0.min.js"></script></body></html>'
    resp = HttpResponse(status_code=200, headers={}, text=html, url="https://example.com")
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Auth0" in result.auth_providers


@pytest.mark.asyncio
async def test_fingerprint_error_page_django():
    body = "Traceback (most recent call last): File \"/app/views.py\", line 42"
    frameworks = BackendAnalyser._fingerprint_error_page(body)
    assert "Django" in frameworks


@pytest.mark.asyncio
async def test_fingerprint_error_page_spring_boot():
    body = "<html><body><h1>Whitelabel Error Page</h1></body></html>"
    frameworks = BackendAnalyser._fingerprint_error_page(body)
    assert "Spring Boot" in frameworks


@pytest.mark.asyncio
async def test_parse_robots_txt_wordpress():
    body = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php"
    hints = BackendAnalyser._parse_robots_txt(body)
    assert "WordPress" in hints


@pytest.mark.asyncio
async def test_detects_cookie_insights():
    resp = HttpResponse(
        status_code=200,
        headers={"Set-Cookie": "_ga=GA1.2.123; path=/\n_fbp=fb.1.123; path=/"},
        text="<html><body></body></html>",
        url="https://example.com",
    )
    analyser = BackendAnalyser(FakeHttpClient(resp))
    result = await analyser.analyse(AnalysisTarget.from_url("https://example.com"))

    assert "Google Analytics" in result.cookie_insights
    assert "Facebook Pixel" in result.cookie_insights
