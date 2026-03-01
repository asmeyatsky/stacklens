from __future__ import annotations

import httpx

from stacklens.domain.ports.http_client import HttpResponse, RedirectHop


class HttpxClientAdapter:
    """Async HTTP client backed by httpx."""

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            headers={"User-Agent": "StackLens/0.1 (+https://github.com/stacklens)"},
            timeout=httpx.Timeout(15.0),
            follow_redirects=True,
        )

    def _build_redirect_chain(self, resp: httpx.Response) -> list[RedirectHop]:
        return [
            RedirectHop(url=str(r.url), status_code=r.status_code)
            for r in resp.history
        ]

    async def get(self, url: str, *, follow_redirects: bool = True) -> HttpResponse:
        resp = await self._client.get(url, follow_redirects=follow_redirects)
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            url=str(resp.url),
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            redirect_chain=self._build_redirect_chain(resp),
        )

    async def head(self, url: str, *, follow_redirects: bool = True) -> HttpResponse:
        resp = await self._client.head(url, follow_redirects=follow_redirects)
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text="",
            url=str(resp.url),
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            redirect_chain=self._build_redirect_chain(resp),
        )

    async def options(self, url: str, *, follow_redirects: bool = True) -> HttpResponse:
        resp = await self._client.options(url, follow_redirects=follow_redirects)
        return HttpResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            text=resp.text,
            url=str(resp.url),
            elapsed_ms=resp.elapsed.total_seconds() * 1000,
            redirect_chain=self._build_redirect_chain(resp),
        )

    async def close(self) -> None:
        await self._client.aclose()
