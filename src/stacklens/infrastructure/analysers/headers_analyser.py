from __future__ import annotations

import re

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
    ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
]

# ── Cookie → insight mapping ─────────────────────────────────────────
_COOKIE_TRACKING: list[tuple[str, str]] = [
    ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"),
    ("_fbp", "Facebook Pixel"),
    ("_fbc", "Facebook Pixel"),
    ("__stripe_mid", "Stripe"),
    ("ajs_", "Segment"),
    ("_hjid", "Hotjar"),
    ("hubspotutk", "HubSpot"),
    ("amplitude_id", "Amplitude"),
    ("mp_", "Mixpanel"),
    ("optimizelyEndUserId", "Optimizely"),
]

_SESSION_TYPES: list[tuple[str, str]] = [
    ("connect.sid", "Node.js session"),
    ("PHPSESSID", "PHP session"),
    ("JSESSIONID", "Java session"),
    ("ASP.NET_SessionId", "ASP.NET session"),
    ("laravel_session", "Laravel session"),
    ("rack.session", "Ruby session"),
    ("csrftoken", "Django CSRF"),
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
        cors = self._parse_cors(headers_lower)
        caching = self._parse_caching(headers_lower)
        cookie_insights = self._analyze_cookie_insights(headers_lower.get("set-cookie", ""))

        return HeadersResult(
            server=headers_lower.get("server"),
            powered_by=headers_lower.get("x-powered-by"),
            security_headers=security,
            cookies=cookies,
            score=score,
            cors=cors,
            caching=caching,
            cookie_insights=cookie_insights,
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

    @staticmethod
    def _parse_cors(headers: dict[str, str]) -> dict[str, str]:
        cors: dict[str, str] = {}
        cors_headers = [
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-allow-credentials",
            "access-control-max-age",
            "access-control-expose-headers",
        ]
        for key in cors_headers:
            value = headers.get(key)
            if value:
                display = key.replace("access-control-", "").replace("-", "_")
                cors[display] = value
        return cors

    @staticmethod
    def _parse_caching(headers: dict[str, str]) -> dict[str, str]:
        caching: dict[str, str] = {}
        for key in ("cache-control", "etag", "age", "vary", "surrogate-control"):
            value = headers.get(key)
            if value:
                caching[key] = value
        return caching

    @staticmethod
    def _analyze_cookie_insights(cookies_raw: str) -> list[str]:
        if not cookies_raw:
            return []
        insights: list[str] = []
        cookies_lower = cookies_raw.lower()

        # Tracking cookies
        for prefix, service in _COOKIE_TRACKING:
            if prefix.lower() in cookies_lower and service not in insights:
                insights.append(f"Tracking: {service}")

        # Session type
        for prefix, session_type in _SESSION_TYPES:
            if prefix.lower() in cookies_lower and session_type not in insights:
                insights.append(f"Session: {session_type}")

        # Check for extreme durations
        max_age_matches = re.findall(r'max-age=(\d+)', cookies_lower)
        for age_str in max_age_matches:
            age = int(age_str)
            if age > 365 * 24 * 3600:
                years = age // (365 * 24 * 3600)
                insights.append(f"Long-lived cookie ({years}+ years)")
                break

        return insights


def _extract_samesite(flags: str) -> str | None:
    for part in flags.split(";"):
        part = part.strip()
        if part.startswith("samesite="):
            return part.split("=", 1)[1].strip().capitalize()
    return None
