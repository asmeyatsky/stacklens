"""Tests for browser domain models."""

import pytest

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


def test_network_request_defaults():
    req = NetworkRequest(url="https://example.com/api")
    assert req.method == "GET"
    assert req.status is None
    assert req.transfer_size == 0
    assert req.is_third_party is False


def test_network_request_full():
    req = NetworkRequest(
        url="https://cdn.example.com/script.js",
        method="GET",
        status=200,
        content_type="application/javascript",
        protocol="h2",
        resource_type="script",
        transfer_size=12345,
        timing_ms=42.5,
        is_third_party=True,
        domain="cdn.example.com",
    )
    assert req.status == 200
    assert req.is_third_party is True


def test_network_request_frozen():
    req = NetworkRequest(url="https://example.com")
    with pytest.raises(Exception):
        req.url = "https://other.com"


def test_graphql_query_defaults():
    gql = GraphQLQuery(endpoint="/graphql")
    assert gql.operation_name is None
    assert gql.operation_type is None


def test_graphql_query_full():
    gql = GraphQLQuery(
        endpoint="/graphql",
        operation_name="GetUser",
        operation_type="query",
    )
    assert gql.operation_name == "GetUser"


def test_network_summary_defaults():
    ns = NetworkSummary()
    assert ns.total_requests == 0
    assert ns.third_party_domains == []
    assert ns.graphql_queries == []


def test_network_summary_full():
    ns = NetworkSummary(
        total_requests=100,
        total_transfer_bytes=500000,
        first_party_requests=60,
        third_party_requests=40,
        requests_by_type={"script": 30, "xhr": 20},
        third_party_domains=["cdn.example.com"],
        graphql_queries=[GraphQLQuery(endpoint="/graphql")],
        streaming_endpoints=["https://example.com/events"],
        protocols_used=["h2"],
    )
    assert ns.total_requests == 100
    assert len(ns.graphql_queries) == 1


def test_framework_data_defaults():
    fw = FrameworkData()
    assert fw.next_data is False
    assert fw.global_objects == []


def test_framework_data_full():
    fw = FrameworkData(
        next_data=True,
        nuxt_data=False,
        remix_context=True,
        service_worker_active=True,
        global_objects=["React", "Stripe"],
        browser_features=["WebSocket", "indexedDB"],
    )
    assert fw.next_data is True
    assert "React" in fw.global_objects


def test_performance_metrics_defaults():
    pm = PerformanceMetrics()
    assert pm.ttfb_ms is None
    assert pm.total_page_weight_bytes == 0


def test_performance_metrics_full():
    pm = PerformanceMetrics(
        ttfb_ms=120.0,
        fcp_ms=800.0,
        lcp_ms=2500.0,
        cls=0.05,
        dom_interactive_ms=1200.0,
        dom_complete_ms=3000.0,
        load_event_ms=3200.0,
        total_page_weight_bytes=2_000_000,
    )
    assert pm.lcp_ms == 2500.0


def test_cookie_info():
    cookie = CookieInfo(
        name="session",
        domain=".example.com",
        path="/",
        expires=1700000000.0,
        secure=True,
        http_only=True,
        same_site="Lax",
    )
    assert cookie.secure is True
    assert cookie.http_only is True


def test_storage_summary_defaults():
    ss = StorageSummary()
    assert ss.cookies == []
    assert ss.cookie_count == 0


def test_websocket_connection():
    ws = WebSocketConnection(url="wss://example.com/ws", frames_sent=10, frames_received=20)
    assert ws.frames_sent == 10


def test_console_snapshot_defaults():
    cs = ConsoleSnapshot()
    assert cs.error_count == 0
    assert cs.errors == []


def test_dom_snapshot_defaults():
    ds = DomSnapshot()
    assert ds.total_elements == 0
    assert ds.has_shadow_dom is False


def test_dom_snapshot_full():
    ds = DomSnapshot(
        total_elements=1500,
        iframe_sources=["https://youtube.com/embed/abc"],
        has_shadow_dom=True,
        lazy_image_count=12,
        rendered_html_length=250000,
    )
    assert ds.has_shadow_dom is True


def test_browser_result_defaults():
    br = BrowserResult()
    assert br.network.total_requests == 0
    assert br.requests == []
    assert br.page_title == ""
    assert br.elapsed_ms == 0.0


def test_browser_result_full():
    br = BrowserResult(
        network=NetworkSummary(total_requests=50),
        requests=[NetworkRequest(url="https://example.com")],
        framework_data=FrameworkData(next_data=True),
        performance=PerformanceMetrics(fcp_ms=800.0),
        storage=StorageSummary(cookie_count=5),
        websockets=[WebSocketConnection(url="wss://example.com/ws")],
        console=ConsoleSnapshot(error_count=2),
        dom=DomSnapshot(total_elements=500),
        page_title="Example",
        final_url="https://www.example.com",
        elapsed_ms=5000.0,
    )
    assert br.network.total_requests == 50
    assert br.framework_data.next_data is True
    assert br.page_title == "Example"


def test_browser_result_frozen():
    br = BrowserResult()
    with pytest.raises(Exception):
        br.page_title = "changed"
