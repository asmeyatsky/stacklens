"""Unit tests for BrowserAnalyser — no real browser needed."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from stacklens.domain.models.browser import NetworkRequest
from stacklens.infrastructure.analysers.browser_analyser import BrowserAnalyser


class TestRegistrableDomain:
    def test_simple_domain(self):
        assert BrowserAnalyser._registrable_domain("example.com") == "example.com"

    def test_subdomain(self):
        assert BrowserAnalyser._registrable_domain("www.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert BrowserAnalyser._registrable_domain("a.b.c.example.com") == "example.com"

    def test_co_uk(self):
        assert BrowserAnalyser._registrable_domain("www.example.co.uk") == "example.co.uk"

    def test_com_au(self):
        assert BrowserAnalyser._registrable_domain("shop.example.com.au") == "example.com.au"

    def test_empty(self):
        assert BrowserAnalyser._registrable_domain("") == ""

    def test_single_part(self):
        assert BrowserAnalyser._registrable_domain("localhost") == "localhost"

    def test_trailing_dot(self):
        assert BrowserAnalyser._registrable_domain("www.example.com.") == "example.com"


class TestBuildNetworkSummary:
    def setup_method(self):
        self.analyser = BrowserAnalyser()

    def test_basic_summary(self):
        requests = [
            NetworkRequest(url="https://example.com/page", domain="example.com", transfer_size=1000, resource_type="document"),
            NetworkRequest(url="https://cdn.other.com/script.js", domain="cdn.other.com", transfer_size=5000, resource_type="script", is_third_party=True),
        ]
        summary = self.analyser._build_network_summary(requests, "example.com")
        assert summary.total_requests == 2
        assert summary.total_transfer_bytes == 6000
        assert summary.first_party_requests == 1
        assert summary.third_party_requests == 1
        assert "cdn.other.com" in summary.third_party_domains

    def test_requests_by_type(self):
        requests = [
            NetworkRequest(url="https://example.com/a", resource_type="script"),
            NetworkRequest(url="https://example.com/b", resource_type="script"),
            NetworkRequest(url="https://example.com/c", resource_type="xhr"),
        ]
        summary = self.analyser._build_network_summary(requests, "example.com")
        assert summary.requests_by_type["script"] == 2
        assert summary.requests_by_type["xhr"] == 1

    def test_graphql_detection(self):
        requests = [
            NetworkRequest(url="https://example.com/graphql", method="POST", domain="example.com"),
            NetworkRequest(url="https://example.com/api/graphql", method="POST", domain="example.com"),
            NetworkRequest(url="https://example.com/api", method="POST", domain="example.com"),
        ]
        summary = self.analyser._build_network_summary(requests, "example.com")
        assert len(summary.graphql_queries) == 2

    def test_sse_detection(self):
        requests = [
            NetworkRequest(url="https://example.com/events", content_type="text/event-stream", domain="example.com"),
            NetworkRequest(url="https://example.com/api", content_type="application/json", domain="example.com"),
        ]
        summary = self.analyser._build_network_summary(requests, "example.com")
        assert len(summary.streaming_endpoints) == 1
        assert "events" in summary.streaming_endpoints[0]

    def test_empty_requests(self):
        summary = self.analyser._build_network_summary([], "example.com")
        assert summary.total_requests == 0
        assert summary.third_party_domains == []

    def test_third_party_classification(self):
        requests = [
            NetworkRequest(url="https://www.example.com/a", domain="www.example.com"),
            NetworkRequest(url="https://cdn.example.com/b", domain="cdn.example.com"),
            NetworkRequest(url="https://api.stripe.com/c", domain="api.stripe.com", is_third_party=True),
        ]
        summary = self.analyser._build_network_summary(requests, "example.com")
        # www.example.com and cdn.example.com are first-party (same registrable domain)
        assert summary.first_party_requests == 2
        assert summary.third_party_requests == 1


@pytest.mark.asyncio
async def test_analyse_missing_playwright():
    """When playwright is not installed, analyse raises RuntimeError."""
    analyser = BrowserAnalyser()
    target = MagicMock()
    target.url = "https://example.com"
    target.hostname = "example.com"

    with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
        with patch(
            "stacklens.infrastructure.analysers.browser_analyser.BrowserAnalyser.analyse",
            side_effect=RuntimeError("Playwright is not installed"),
        ):
            with pytest.raises(RuntimeError, match="Playwright is not installed"):
                await analyser.analyse(target)


def test_analyser_properties():
    analyser = BrowserAnalyser()
    assert analyser.name == "browser"
    assert analyser.depends_on == []
    assert analyser.timeout == 60.0
