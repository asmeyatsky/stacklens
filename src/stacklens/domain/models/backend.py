from __future__ import annotations

from pydantic import BaseModel, Field


class EndpointProbe(BaseModel, frozen=True):
    """Result of probing a well-known endpoint."""

    path: str  # e.g. "/api", "/graphql"
    status_code: int
    accessible: bool  # True if 2xx or 3xx


class BackendResult(BaseModel, frozen=True):
    """Aggregated backend / infrastructure analysis."""

    server_framework: list[str] = Field(default_factory=list)  # e.g. ["Laravel", "PHP"]
    cms: list[str] = Field(default_factory=list)  # e.g. ["WordPress"]
    cloud_provider: list[str] = Field(default_factory=list)  # e.g. ["AWS"]
    waf: list[str] = Field(default_factory=list)  # e.g. ["Cloudflare"]
    endpoint_probes: list[EndpointProbe] = Field(default_factory=list)
