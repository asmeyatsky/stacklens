from __future__ import annotations

import asyncio
import re
import uuid

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
    ("wp_", "WordPress"),
    ("_gh_sess", "GitHub"),
    ("__cf_bm", "Cloudflare Bot Management"),
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

# ── Server header → software name ──────────────────────────────────
_SERVER_MAP: list[tuple[str, str]] = [
    ("envoy", "Envoy"),
    ("nginx", "nginx"),
    ("apache", "Apache"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("openresty", "OpenResty"),
    ("caddy", "Caddy"),
    ("litespeed", "LiteSpeed"),
    ("microsoft-iis", "Microsoft IIS"),
    ("amazons3", "Amazon S3"),
    ("gws", "Google Web Server"),
    ("gfe", "Google Frontend"),
    ("cloudflare", "Cloudflare"),
    ("varnish", "Varnish"),
    ("cowboy", "Cowboy (Erlang)"),
    ("jetty", "Jetty"),
    ("tengine", "Tengine"),
]

# ── Tracing headers ────────────────────────────────────────────────
_TRACING_HEADERS: list[tuple[str, str]] = [
    ("x-b3-traceid", "Zipkin/Jaeger (B3)"),
    ("x-b3-spanid", "Zipkin/Jaeger (B3)"),
    ("traceparent", "W3C Trace Context"),
    ("x-datadog-trace-id", "Datadog APM"),
    ("x-cloud-trace-context", "Google Cloud Trace"),
    ("x-amzn-trace-id", "AWS X-Ray"),
    ("x-request-id", "Request ID tracking"),
]

# ── AWS region pattern ─────────────────────────────────────────────
_AWS_REGION_RE = re.compile(
    r"(?:us|eu|ap|sa|ca|me|af)-(?:east|west|north|south|central|northeast|southeast|northwest|southwest)-\d"
)
_EC2_INSTANCE_RE = re.compile(r"i-[0-9a-f]{8,17}")

# ── Cookie → insight mapping ──────────────────────────────────────
_COOKIE_INSIGHTS: list[tuple[str, str]] = [
    ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"),
    ("ajs_", "Segment"),
    ("_fbp", "Facebook Pixel"),
    ("_fbc", "Facebook Pixel"),
    ("__stripe_mid", "Stripe"),
    ("__stripe_sid", "Stripe"),
    ("_hp2_", "Heap Analytics"),
    ("mp_", "Mixpanel"),
    ("amplitude_id", "Amplitude"),
    ("_hjid", "Hotjar"),
    ("hubspotutk", "HubSpot"),
    ("__hstc", "HubSpot"),
    ("intercom-", "Intercom"),
    ("_dd_s", "Datadog RUM"),
    ("optimizelyEndUserId", "Optimizely"),
]

_SESSION_STORE_HINTS: list[tuple[str, str]] = [
    ("connect.sid", "Node.js session"),
    ("rack.session", "Ruby session"),
    ("PHPSESSID", "PHP session"),
    ("JSESSIONID", "Java session"),
    ("ASP.NET_SessionId", "ASP.NET session"),
    ("laravel_session", "Laravel session"),
    ("csrftoken", "Django session"),
    ("_rails", "Rails session"),
]

# ── Database leak patterns in error pages ──────────────────────────
_DB_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"PostgreSQL|SQLSTATE|psycopg|pg_", "PostgreSQL"),
    (r"MySQL|mysqli|MariaDB", "MySQL"),
    (r"MongoDB|MongoError|mongo\.", "MongoDB"),
    (r"Redis|redis\.", "Redis"),
    (r"SQLite|sqlite3", "SQLite"),
    (r"ORA-\d{5}", "Oracle"),
    (r"MSSQL|SqlClient|Microsoft SQL", "Microsoft SQL Server"),
    (r"Cassandra|cassandra\.", "Cassandra"),
    (r"Elasticsearch|elasticsearch", "Elasticsearch"),
]

# ── Error page → framework fingerprints ────────────────────────────
_ERROR_PAGE_FRAMEWORKS: list[tuple[str, str]] = [
    (r"Django|Traceback \(most recent call last\)|WSGI application", "Django"),
    (r"Rails|ActionController|ActiveRecord", "Rails"),
    (r"Spring Boot|Whitelabel Error Page", "Spring Boot"),
    (r"ASP\.NET|__doPostBack|aspnet_client", "ASP.NET"),
    (r"Express(?:JS)?|Cannot GET|<!DOCTYPE html>.*<pre>Cannot", "Express"),
    (r"Laravel|Symfony.*Component|Ignition", "Laravel"),
    (r"Symfony\\|symfony/", "Symfony"),
    (r"Flask|Werkzeug|Debugger", "Flask"),
    (r"Phoenix Framework|Phoenix\.Router", "Phoenix"),
    (r"CakePHP|cake\.generic\.css", "CakePHP"),
]

# ── Robots.txt → CMS/framework hints ─────────────────────────────
_ROBOTS_PATTERNS: list[tuple[str, str]] = [
    (r"wp-admin|wp-includes|wp-content", "WordPress"),
    (r"/rails/|/admin/sidekiq", "Rails"),
    (r"/admin/content|/node/", "Drupal"),
    (r"Sitemap:\s*\S+sitemap", "XML Sitemap"),
    (r"/administrator/|/components/", "Joomla"),
]

# ── HEAD-only probes (existence check) ────────────────────────────
_HEAD_PROBE_PATHS = [
    "/api",
    "/swagger/",
    "/health",
    "/sitemap.xml",
    "/favicon.ico",
    "/wp-login.php",
    "/wp-admin/",
]

# ── GET probes (body inspection) ──────────────────────────────────
_GET_PROBE_PATHS = [
    "/robots.txt",
    "/graphql",
    "/.well-known/openid-configuration",
    "/manifest.json",
    "/.well-known/security.txt",
    "/openapi.json",
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
        elapsed_ms = resp.elapsed_ms

        server_framework = self._detect_frameworks(headers_lower)
        cms = self._detect_cms(html)
        cloud_provider = self._detect_cloud(headers_lower)
        waf = self._detect_waf(headers_lower)
        server_software = self._detect_server_software(headers_lower)
        proxy_gateway = self._detect_proxy_gateway(headers_lower)
        tracing = self._detect_tracing(headers_lower)
        infra_hints = self._detect_infra_hints(headers_lower)
        caching = self._detect_caching(headers_lower)
        cookie_insights = self._detect_cookie_insights(headers_lower)

        # Probe endpoints (HEAD + GET)
        head_probes, get_probes = await self._probe_endpoints(target)
        all_probes = head_probes + get_probes

        # Build lookup of GET probe bodies
        get_probe_map = {p.path: p for p in get_probes}

        # Error page fingerprinting via random UUID path
        error_probe = await self._probe_error_page(target)
        error_body = error_probe.body if error_probe else ""
        if error_probe:
            all_probes.append(error_probe)

        # Detect from probes and HTML
        api_signals = self._detect_api_signals(headers_lower, get_probe_map, html)
        database_hints = self._detect_database_hints(headers_lower, error_body)
        auth_providers = self._detect_auth_providers(get_probe_map, html)

        # Parse robots.txt for framework hints
        robots_probe = get_probe_map.get("/robots.txt")
        if robots_probe and robots_probe.accessible and robots_probe.body:
            for hint in self._parse_robots_txt(robots_probe.body):
                if hint not in cms:
                    cms.append(hint)

        # Error page framework fingerprinting
        if error_body:
            for fw in self._fingerprint_error_page(error_body):
                if fw not in server_framework:
                    server_framework.append(fw)

        # Infer architecture
        custom_ns = [h for h in infra_hints if "Custom x-" in h]
        architecture = self._infer_architecture(
            tracing, proxy_gateway, server_framework, cloud_provider, custom_ns
        )

        return BackendResult(
            server_framework=server_framework,
            cms=cms,
            cloud_provider=cloud_provider,
            waf=waf,
            endpoint_probes=all_probes,
            server_software=server_software,
            proxy_gateway=proxy_gateway,
            tracing=tracing,
            infra_hints=infra_hints,
            api_signals=api_signals,
            database_hints=database_hints,
            architecture=architecture,
            caching=caching,
            auth_providers=auth_providers,
            cookie_insights=cookie_insights,
            elapsed_ms=elapsed_ms,
        )

    @staticmethod
    def _detect_frameworks(headers: dict[str, str]) -> list[str]:
        frameworks: list[str] = []
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            frameworks.append(powered_by)
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

    @staticmethod
    def _detect_server_software(headers: dict[str, str]) -> str | None:
        server = headers.get("server", "")
        if not server:
            return None
        server_lower = server.lower()
        for pattern, name in _SERVER_MAP:
            if pattern in server_lower:
                return name
        return server

    @staticmethod
    def _detect_proxy_gateway(headers: dict[str, str]) -> list[str]:
        proxies: list[str] = []
        server = headers.get("server", "").lower()
        if "envoy" in server:
            proxies.append("Envoy")
        if headers.get("x-envoy-upstream-service-time") is not None:
            if "Envoy" not in proxies:
                proxies.append("Envoy")
        if headers.get("x-envoy-decorator-operation") is not None:
            if "Envoy" not in proxies:
                proxies.append("Envoy")
        via = headers.get("via", "")
        if via:
            if "cloudfront" in via.lower():
                if "CloudFront" not in proxies:
                    proxies.append("CloudFront")
            if "varnish" in via.lower():
                if "Varnish" not in proxies:
                    proxies.append("Varnish")
            if "vegur" in via.lower():
                if "Heroku" not in proxies:
                    proxies.append("Heroku")
        x_cache = headers.get("x-cache", "").lower()
        if "cloudfront" in x_cache:
            if "CloudFront" not in proxies:
                proxies.append("CloudFront")
        if "varnish" in x_cache:
            if "Varnish" not in proxies:
                proxies.append("Varnish")
        return proxies

    @staticmethod
    def _detect_tracing(headers: dict[str, str]) -> list[str]:
        tracing: list[str] = []
        for header_key, trace_system in _TRACING_HEADERS:
            if headers.get(header_key) is not None:
                if trace_system not in tracing:
                    tracing.append(trace_system)
        return tracing

    @staticmethod
    def _detect_infra_hints(headers: dict[str, str]) -> list[str]:
        hints: list[str] = []
        via = headers.get("via", "")
        if via:
            ec2_match = _EC2_INSTANCE_RE.search(via)
            region_match = _AWS_REGION_RE.search(via)
            if ec2_match or region_match:
                parts = []
                if ec2_match:
                    parts.append(f"EC2 {ec2_match.group()}")
                if region_match:
                    parts.append(region_match.group())
                hints.append(f"AWS infrastructure: {', '.join(parts)} (from Via header)")

        custom_prefixes: dict[str, int] = {}
        for key in headers:
            if key.startswith("x-"):
                parts = key.split("-")
                if len(parts) >= 3:
                    namespace = parts[1]
                    if namespace not in (
                        "powered", "content", "frame", "xss", "request",
                        "forwarded", "real", "amzn", "amz", "goog", "azure",
                        "ms", "envoy", "b3", "datadog", "cloud", "cache",
                        "cdn", "sucuri",
                    ):
                        custom_prefixes[namespace] = custom_prefixes.get(namespace, 0) + 1

        for ns, count in custom_prefixes.items():
            if count >= 2:
                hints.append(f"Custom x-{ns}-* headers detected ({count} headers)")
        return hints

    # ── New detection methods ──────────────────────────────────────

    @staticmethod
    def _detect_api_signals(
        headers: dict[str, str],
        get_probes: dict[str, EndpointProbe],
        html: str,
    ) -> list[str]:
        signals: list[str] = []

        # GraphQL
        gql_probe = get_probes.get("/graphql")
        if gql_probe and gql_probe.accessible:
            body = gql_probe.body.lower()
            if '{"data"' in body or "__schema" in body or "graphql" in body:
                signals.append("GraphQL")
        ct = headers.get("content-type", "")
        if "application/graphql" in ct:
            if "GraphQL" not in signals:
                signals.append("GraphQL")

        # REST signals
        if headers.get("link") and ("rel=" in headers.get("link", "")):
            signals.append("REST (Link pagination)")
        if "application/vnd.api+json" in ct:
            signals.append("REST (JSON:API)")

        # gRPC-Web
        if "application/grpc-web" in ct:
            signals.append("gRPC-Web")

        # WebSocket
        if headers.get("upgrade", "").lower() == "websocket":
            signals.append("WebSocket")
        if re.search(r'wss?://', html):
            if "WebSocket" not in signals:
                signals.append("WebSocket")

        # OpenAPI/Swagger
        openapi_probe = get_probes.get("/openapi.json")
        if openapi_probe and openapi_probe.accessible:
            signals.append("OpenAPI")

        return signals

    @staticmethod
    def _detect_database_hints(
        headers: dict[str, str], error_body: str,
    ) -> list[str]:
        hints: list[str] = []

        # Headers with DB-specific prefixes
        for key in headers:
            key_lower = key.lower()
            if "redis" in key_lower and "Redis" not in hints:
                hints.append("Redis")
            if "mongo" in key_lower and "MongoDB" not in hints:
                hints.append("MongoDB")
            if "pgsql" in key_lower or "postgres" in key_lower:
                if "PostgreSQL" not in hints:
                    hints.append("PostgreSQL")

        # Error page fingerprinting
        if error_body:
            for pattern, db_name in _DB_ERROR_PATTERNS:
                if re.search(pattern, error_body, re.IGNORECASE):
                    if db_name not in hints:
                        hints.append(db_name)

        # Cookie patterns
        cookies = headers.get("set-cookie", "").lower()
        if "_redis_session" in cookies and "Redis" not in hints:
            hints.append("Redis")

        return hints

    @staticmethod
    def _infer_architecture(
        tracing: list[str],
        proxy_gateway: list[str],
        server_framework: list[str],
        cloud_provider: list[str],
        custom_namespaces: list[str],
    ) -> list[str]:
        arch: list[str] = []

        has_envoy = "Envoy" in proxy_gateway
        has_tracing = len(tracing) > 0

        # Check for Istio (envoy + istio-specific headers would be in proxy)
        # For now, Envoy presence implies service mesh
        if has_envoy:
            arch.append("Service mesh (Envoy)")

        if has_tracing and has_envoy:
            arch.append("Microservices (service mesh)")
        elif has_tracing or len(custom_namespaces) > 0:
            if "Microservices" not in " ".join(arch):
                arch.append("Microservices")

        # Serverless signals
        for cp in cloud_provider:
            if "Lambda" in cp or "Cloud Functions" in cp:
                arch.append("Serverless")

        # Check for serverless headers
        # (Lambda headers are usually x-amzn-requestid which maps to AWS)

        # Monolith inference: single framework, no tracing, no mesh
        if (
            not arch
            and len(server_framework) <= 1
            and not has_tracing
            and not has_envoy
            and not custom_namespaces
        ):
            if server_framework:
                arch.append("Monolith")

        return arch

    @staticmethod
    def _detect_caching(headers: dict[str, str]) -> list[str]:
        caching: list[str] = []

        # Cache-Control
        cc = headers.get("cache-control", "")
        if cc:
            directives = [d.strip() for d in cc.split(",")]
            for d in directives:
                if d.startswith("max-age="):
                    caching.append(f"Cache-Control: {d}")
                elif d.startswith("s-maxage="):
                    caching.append(f"Cache-Control: {d}")
                elif d in ("no-cache", "no-store", "public", "private"):
                    caching.append(f"Cache-Control: {d}")

        # X-Cache
        x_cache = headers.get("x-cache", "")
        if x_cache:
            origin = ""
            x_lower = x_cache.lower()
            if "cloudfront" in x_lower:
                origin = " (CloudFront)"
            elif "varnish" in x_lower:
                origin = " (Varnish)"
            elif "fastly" in x_lower:
                origin = " (Fastly)"
            caching.append(f"X-Cache: {x_cache}{origin}")

        # Age header
        age = headers.get("age")
        if age:
            caching.append(f"Age: {age}s")

        # ETag
        etag = headers.get("etag", "")
        if etag:
            strength = "weak" if etag.startswith("W/") else "strong"
            caching.append(f"ETag ({strength})")

        # Surrogate-Control
        sc = headers.get("surrogate-control")
        if sc:
            caching.append(f"Surrogate-Control: {sc}")

        # CDN-Cache-Control
        ccc = headers.get("cdn-cache-control")
        if ccc:
            caching.append(f"CDN-Cache-Control: {ccc}")

        return caching

    @staticmethod
    def _detect_auth_providers(
        get_probes: dict[str, EndpointProbe], html: str,
    ) -> list[str]:
        providers: list[str] = []

        # Check OIDC discovery
        oidc_probe = get_probes.get("/.well-known/openid-configuration")
        if oidc_probe and oidc_probe.accessible and oidc_probe.body:
            body = oidc_probe.body.lower()
            if "auth0.com" in body:
                providers.append("Auth0")
            elif "okta.com" in body or "oktapreview.com" in body:
                providers.append("Okta")
            elif "cognito" in body or "amazoncognito" in body:
                providers.append("AWS Cognito")
            elif "firebase" in body or "securetoken.google.com" in body:
                providers.append("Firebase Auth")
            elif "keycloak" in body:
                providers.append("Keycloak")

        # HTML references
        _html_auth = [
            ("auth0.com", "Auth0"),
            ("okta.com", "Okta"),
            ("accounts.google.com", "Google Sign-In"),
            ("login.microsoftonline.com", "Microsoft Identity"),
            ("cognito", "AWS Cognito"),
            ("firebase", "Firebase Auth"),
        ]
        html_lower = html.lower()
        for pattern, name in _html_auth:
            if pattern in html_lower and name not in providers:
                providers.append(name)

        return providers

    @staticmethod
    def _detect_cookie_insights(headers: dict[str, str]) -> list[str]:
        insights: list[str] = []
        cookies = headers.get("set-cookie", "")
        if not cookies:
            return insights

        cookies_lower = cookies.lower()

        # Analytics / tracking cookies
        for prefix, service in _COOKIE_INSIGHTS:
            if prefix.lower() in cookies_lower and service not in insights:
                insights.append(service)

        # Session store hints
        for prefix, store in _SESSION_STORE_HINTS:
            if prefix.lower() in cookies_lower and store not in insights:
                insights.append(store)

        return insights

    @staticmethod
    def _parse_robots_txt(body: str) -> list[str]:
        hints: list[str] = []
        for pattern, name in _ROBOTS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if name not in hints:
                    hints.append(name)
        return hints

    @staticmethod
    def _fingerprint_error_page(body: str) -> list[str]:
        frameworks: list[str] = []
        for pattern, name in _ERROR_PAGE_FRAMEWORKS:
            if re.search(pattern, body, re.IGNORECASE):
                if name not in frameworks:
                    frameworks.append(name)
        return frameworks

    def _base_url(self, target: AnalysisTarget) -> str:
        base = f"{target.scheme}://{target.hostname}"
        if (target.scheme == "https" and target.port != 443) or (
            target.scheme == "http" and target.port != 80
        ):
            base = f"{base}:{target.port}"
        return base

    async def _probe_endpoints(
        self, target: AnalysisTarget,
    ) -> tuple[list[EndpointProbe], list[EndpointProbe]]:
        base = self._base_url(target)

        async def _head_probe(path: str) -> EndpointProbe:
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

        async def _get_probe(path: str) -> EndpointProbe:
            url = f"{base}{path}"
            try:
                resp = await self._http.get(url, follow_redirects=True)
                return EndpointProbe(
                    path=path,
                    status_code=resp.status_code,
                    accessible=resp.status_code < 400,
                    body=resp.text[:4096],
                )
            except Exception:
                return EndpointProbe(path=path, status_code=0, accessible=False)

        head_results, get_results = await asyncio.gather(
            asyncio.gather(*[_head_probe(p) for p in _HEAD_PROBE_PATHS]),
            asyncio.gather(*[_get_probe(p) for p in _GET_PROBE_PATHS]),
        )
        return list(head_results), list(get_results)

    async def _probe_error_page(self, target: AnalysisTarget) -> EndpointProbe | None:
        base = self._base_url(target)
        random_path = f"/{uuid.uuid4()}"
        url = f"{base}{random_path}"
        try:
            resp = await self._http.get(url, follow_redirects=True)
            return EndpointProbe(
                path=random_path,
                status_code=resp.status_code,
                accessible=False,
                body=resp.text[:4096],
            )
        except Exception:
            return None
