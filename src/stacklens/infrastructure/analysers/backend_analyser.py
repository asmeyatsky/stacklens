from __future__ import annotations

import asyncio
import re

from stacklens.domain.models.backend import BackendResult, EndpointProbe
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpClientPort

# ── Cookie → framework mapping ──────────────────────────────────────
_COOKIE_FRAMEWORKS: list[tuple[str, str]] = [
    ("JSESSIONID", "Java"),
    ("laravel_session", "Laravel"),
    ("_rails", "Rails"),
    ("PHPSESSID", "PHP"),
    ("connect.sid", "Express"),
    ("csrftoken", "Django"),
    ("ASP.NET_SessionId", "ASP.NET"),
]

# ── CMS detection from HTML paths ──────────────────────────────────
_CMS_PATTERNS: list[tuple[str, str]] = [
    (r"wp-content|wp-includes|wp-json", "WordPress"),
    (r'sites/default/files|drupal\.js', "Drupal"),
    (r"components/com_|/joomla", "Joomla"),
    (r'ghost/api|class="gh-', "Ghost"),
]

# ── Cloud/API gateway headers ──────────────────────────────────────
_CLOUD_HEADERS: list[tuple[str, str, str]] = [
    # (header_key, pattern, provider_name)
    ("x-amzn-requestid", "", "AWS"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amz-request-id", "", "AWS S3"),
    ("x-goog-generation", "", "GCP"),
    ("x-guploader-uploadid", "", "GCP"),
    ("x-azure-ref", "", "Azure"),
    ("x-ms-request-id", "", "Azure"),
]

# ── WAF detection ───────────────────────────────────────────────────
_WAF_HEADERS: list[tuple[str, str, str]] = [
    ("cf-ray", "", "Cloudflare"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-cdn", "imperva", "Imperva"),
    ("server", r"akamaighost|akamai", "Akamai"),
    ("server", r"cloudflare", "Cloudflare"),
]

# ── Endpoints to probe ──────────────────────────────────────────────
_PROBE_PATHS = [
    "/api",
    "/graphql",
    "/swagger/",
    "/openapi.json",
    "/.well-known/security.txt",
    "/health",
    "/sitemap.xml",
]


class BackendAnalyser:
    """Infers server-side architecture from HTTP signals."""

    def __init__(self, http_client: HttpClientPort) -> None:
        self._http = http_client

    @property
    def name(self) -> str:
        return "backend"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target: AnalysisTarget) -> BackendResult:
        resp = await self._http.get(target.url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        html = resp.text

        server_framework = self._detect_frameworks(headers_lower)
        cms = self._detect_cms(html)
        cloud_provider = self._detect_cloud(headers_lower)
        waf = self._detect_waf(headers_lower)
        probes = await self._probe_endpoints(target)

        return BackendResult(
            server_framework=server_framework,
            cms=cms,
            cloud_provider=cloud_provider,
            waf=waf,
            endpoint_probes=probes,
        )

    @staticmethod
    def _detect_frameworks(headers: dict[str, str]) -> list[str]:
        frameworks: list[str] = []

        # Check X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            frameworks.append(powered_by)

        # Check cookies for framework signatures
        cookies = headers.get("set-cookie", "")
        for cookie_prefix, framework_name in _COOKIE_FRAMEWORKS:
            if cookie_prefix.lower() in cookies.lower():
                if framework_name not in frameworks:
                    frameworks.append(framework_name)

        return frameworks

    @staticmethod
    def _detect_cms(html: str) -> list[str]:
        cms_list: list[str] = []
        for pattern, cms_name in _CMS_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                if cms_name not in cms_list:
                    cms_list.append(cms_name)
        return cms_list

    @staticmethod
    def _detect_cloud(headers: dict[str, str]) -> list[str]:
        providers: list[str] = []
        for header_key, pattern, provider_name in _CLOUD_HEADERS:
            value = headers.get(header_key)
            if value is not None:
                if not pattern or re.search(pattern, value, re.IGNORECASE):
                    if provider_name not in providers:
                        providers.append(provider_name)
        return providers

    @staticmethod
    def _detect_waf(headers: dict[str, str]) -> list[str]:
        waf_list: list[str] = []
        for header_key, pattern, waf_name in _WAF_HEADERS:
            value = headers.get(header_key)
            if value is not None:
                if not pattern or re.search(pattern, value, re.IGNORECASE):
                    if waf_name not in waf_list:
                        waf_list.append(waf_name)
        return waf_list

    async def _probe_endpoints(self, target: AnalysisTarget) -> list[EndpointProbe]:
        base = f"{target.scheme}://{target.hostname}"
        if (target.scheme == "https" and target.port != 443) or (
            target.scheme == "http" and target.port != 80
        ):
            base = f"{base}:{target.port}"

        async def _probe(path: str) -> EndpointProbe:
            url = f"{base}{path}"
            try:
                resp = await self._http.head(url, follow_redirects=True)
                return EndpointProbe(
                    path=path,
                    status_code=resp.status_code,
                    accessible=resp.status_code < 400,
                )
            except Exception:
                return EndpointProbe(path=path, status_code=0, accessible=False)

        results = await asyncio.gather(*[_probe(p) for p in _PROBE_PATHS])
        return list(results)
