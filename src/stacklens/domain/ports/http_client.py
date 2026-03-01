from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class HttpResponse(BaseModel, frozen=True):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    text: str = ""
    url: str = ""


@runtime_checkable
class HttpClientPort(Protocol):
    async def get(self, url: str, *, follow_redirects: bool = True) -> HttpResponse: ...
    async def head(self, url: str, *, follow_redirects: bool = True) -> HttpResponse: ...
    async def close(self) -> None: ...
