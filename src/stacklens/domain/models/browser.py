from __future__ import annotations

from pydantic import BaseModel


class NetworkRequest(BaseModel, frozen=True):
    url: str
    method: str = "GET"
    status: int | None = None
    content_type: str | None = None
    protocol: str | None = None
    resource_type: str | None = None
    transfer_size: int = 0
    timing_ms: float = 0.0
    is_third_party: bool = False
    domain: str = ""


class GraphQLQuery(BaseModel, frozen=True):
    endpoint: str
    operation_name: str | None = None
    operation_type: str | None = None  # "query" | "mutation"


class NetworkSummary(BaseModel, frozen=True):
    total_requests: int = 0
    total_transfer_bytes: int = 0
    first_party_requests: int = 0
    third_party_requests: int = 0
    requests_by_type: dict[str, int] = {}
    third_party_domains: list[str] = []
    graphql_queries: list[GraphQLQuery] = []
    streaming_endpoints: list[str] = []
    protocols_used: list[str] = []


class FrameworkData(BaseModel, frozen=True):
    next_data: bool = False
    nuxt_data: bool = False
    remix_context: bool = False
    service_worker_active: bool = False
    global_objects: list[str] = []
    browser_features: list[str] = []


class PerformanceMetrics(BaseModel, frozen=True):
    ttfb_ms: float | None = None
    fcp_ms: float | None = None
    lcp_ms: float | None = None
    cls: float | None = None
    dom_interactive_ms: float | None = None
    dom_complete_ms: float | None = None
    load_event_ms: float | None = None
    total_page_weight_bytes: int = 0


class CookieInfo(BaseModel, frozen=True):
    name: str
    domain: str = ""
    path: str = "/"
    expires: float | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


class StorageSummary(BaseModel, frozen=True):
    cookies: list[CookieInfo] = []
    cookie_count: int = 0
    local_storage_keys: list[str] = []
    session_storage_keys: list[str] = []


class WebSocketConnection(BaseModel, frozen=True):
    url: str
    frames_sent: int = 0
    frames_received: int = 0


class ConsoleSnapshot(BaseModel, frozen=True):
    error_count: int = 0
    warning_count: int = 0
    errors: list[str] = []
    uncaught_exceptions: list[str] = []


class DomSnapshot(BaseModel, frozen=True):
    total_elements: int = 0
    iframe_sources: list[str] = []
    has_shadow_dom: bool = False
    lazy_image_count: int = 0
    rendered_html_length: int = 0


class BrowserResult(BaseModel, frozen=True):
    network: NetworkSummary = NetworkSummary()
    requests: list[NetworkRequest] = []
    framework_data: FrameworkData = FrameworkData()
    performance: PerformanceMetrics = PerformanceMetrics()
    storage: StorageSummary = StorageSummary()
    websockets: list[WebSocketConnection] = []
    console: ConsoleSnapshot = ConsoleSnapshot()
    dom: DomSnapshot = DomSnapshot()
    page_title: str = ""
    final_url: str = ""
    elapsed_ms: float = 0.0
