from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointProbe(BaseModel, frozen=True):
    """Result of probing a well-known endpoint."""

    path: str  # e.g. "/api", "/graphql"
    status_code: int
    accessible: bool  # True if 2xx or 3xx
    body: str = ""  # body content for GET probes


class BackendResult(BaseModel, frozen=True):
    """Aggregated backend / infrastructure analysis."""

    server_framework: list[str] = Field(default_factory=list)
    cms: list[str] = Field(default_factory=list)
    cloud_provider: list[str] = Field(default_factory=list)
    waf: list[str] = Field(default_factory=list)
    endpoint_probes: list[EndpointProbe] = Field(default_factory=list)
    server_software: str | None = None
    proxy_gateway: list[str] = Field(default_factory=list)
    tracing: list[str] = Field(default_factory=list)
    infra_hints: list[str] = Field(default_factory=list)
    api_signals: list[str] = Field(default_factory=list)
    database_hints: list[str] = Field(default_factory=list)
    architecture: list[str] = Field(default_factory=list)
    caching: list[str] = Field(default_factory=list)
    auth_providers: list[str] = Field(default_factory=list)
    cookie_insights: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0.0
