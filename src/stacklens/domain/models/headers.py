from __future__ import annotations

from pydantic import BaseModel, Field


class SecurityHeader(BaseModel, frozen=True):
    name: str
    present: bool
    value: str | None = None
    rating: str = "missing"  # "good", "warning", "missing"


class CookieAnalysis(BaseModel, frozen=True):
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


class HeadersResult(BaseModel, frozen=True):
    server: str | None = None
    powered_by: str | None = None
    security_headers: list[SecurityHeader] = Field(default_factory=list)
    cookies: list[CookieAnalysis] = Field(default_factory=list)
    score: float = 0.0
    cors: dict[str, str] = Field(default_factory=dict)
    caching: dict[str, str] = Field(default_factory=dict)
    cookie_insights: list[str] = Field(default_factory=list)
