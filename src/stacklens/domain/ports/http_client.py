from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class RedirectHop(BaseModel, frozen=True):
    url: str
    status_code: int


class HttpResponse(BaseModel, frozen=True):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    text: str = ""
    url: str = ""
    elapsed_ms: float = 0.0
    redirect_chain: list[RedirectHop] = Field(default_factory=list)


@runtime_checkable
class HttpClientPort(Protocol):
    async def get(self, url: str, *, follow_redirects: bool = True) -> HttpResponse: ...
    async def head(self, url: str, *, follow_redirects: bool = True) -> HttpResponse: ...
    async def options(self, url: str, *, follow_redirects: bool = True) -> HttpResponse: ...
    async def close(self) -> None: ...
