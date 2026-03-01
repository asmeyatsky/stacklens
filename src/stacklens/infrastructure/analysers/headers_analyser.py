from __future__ import annotations

from stacklens.domain.models.headers import CookieAnalysis, HeadersResult, SecurityHeader
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpClientPort
from stacklens.domain.services.header_scoring import score_security_headers

SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
]


class HeadersAnalyser:
    def __init__(self, http_client: HttpClientPort) -> None:
        self._http = http_client

    @property
    def name(self) -> str:
        return "headers"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target: AnalysisTarget) -> HeadersResult:
        resp = await self._http.get(target.url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        security = self._check_security_headers(headers_lower)
        cookies = self._parse_cookies(headers_lower)
        score = score_security_headers(security)

        return HeadersResult(
            server=headers_lower.get("server"),
            powered_by=headers_lower.get("x-powered-by"),
            security_headers=security,
            cookies=cookies,
            score=score,
        )

    @staticmethod
    def _check_security_headers(headers: dict[str, str]) -> list[SecurityHeader]:
        result = []
        for key, display_name in SECURITY_HEADERS:
            value = headers.get(key)
            if value:
                rating = "good"
                if key == "x-frame-options" and value.upper() not in (
                    "DENY",
                    "SAMEORIGIN",
                ):
                    rating = "warning"
                result.append(
                    SecurityHeader(
                        name=display_name, present=True, value=value, rating=rating
                    )
                )
            else:
                result.append(SecurityHeader(name=display_name, present=False))
        return result

    @staticmethod
    def _parse_cookies(headers: dict[str, str]) -> list[CookieAnalysis]:
        raw = headers.get("set-cookie")
        if not raw:
            return []
        cookies = []
        for cookie_str in raw.split("\n"):
            parts = cookie_str.split(";")
            if not parts:
                continue
            name_val = parts[0].strip()
            name = name_val.split("=", 1)[0].strip()
            if not name:
                continue
            flags = cookie_str.lower()
            cookies.append(
                CookieAnalysis(
                    name=name,
                    secure="secure" in flags,
                    http_only="httponly" in flags,
                    same_site=_extract_samesite(flags),
                )
            )
        return cookies


def _extract_samesite(flags: str) -> str | None:
    for part in flags.split(";"):
        part = part.strip()
        if part.startswith("samesite="):
            return part.split("=", 1)[1].strip().capitalize()
    return None
