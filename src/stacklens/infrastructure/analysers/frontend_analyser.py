from __future__ import annotations

import json
import re

from stacklens.domain.models.frontend import FrontendResult, ScriptDependency, TechDetection
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpClientPort

# ── JS framework signatures ─────────────────────────────────────────
_JS_FRAMEWORKS: list[tuple[str, str, str]] = [
    ("Next.js", r'__NEXT_DATA__|/_next/', "__NEXT_DATA__ or /_next/ reference"),
    ("React", r'react[-.]|reactDOM|data-reactroot|data-reactid', "React runtime marker"),
    ("Vue", r'vue[.-]|__vue|data-v-', "Vue runtime marker"),
    ("Angular", r'ng-version|ng-app|angular[.-]', "Angular attribute or script"),
    ("Svelte", r'svelte[/-]|__svelte', "Svelte marker"),
    ("Nuxt", r'__NUXT__|_nuxt/', "Nuxt runtime marker"),
    ("Remix", r'__remix|remix-run', "Remix runtime marker"),
    ("Astro", r'astro-island|astro[/-]', "Astro component marker"),
    ("jQuery", r'jquery[.-]|jQuery', "jQuery library"),
    ("Ember", r'ember[.-]|EmberENV|ember-cli', "Ember.js marker"),
    ("Backbone", r'backbone[.-]|Backbone\.', "Backbone.js marker"),
    ("Alpine.js", r'x-data\s*=|alpine[.-]', "Alpine.js directive"),
    ("HTMX", r'htmx[.-]|hx-get|hx-post|hx-trigger', "HTMX attribute"),
    ("Stimulus", r'stimulus[.-]|data-controller', "Stimulus controller"),
    ("Lit", r'lit-html|lit-element|@lit/', "Lit element marker"),
    ("Preact", r'preact[.-]|preactjs', "Preact marker"),
    ("Gatsby", r'gatsby-|___gatsby', "Gatsby marker"),
    ("Webpack", r'webpackJsonp|__webpack_', "Webpack bundle marker"),
    ("Vite", r'/@vite|vite/client', "Vite dev marker"),
]

# ── CSS framework signatures ────────────────────────────────────────
_CSS_FRAMEWORKS: list[tuple[str, str, str]] = [
    ("Tailwind", r'class="[^"]*\b(?:flex|grid|px-|py-|mt-|mb-|text-)\b', "Tailwind utility classes"),
    ("Bootstrap", r'bootstrap[.-]|class="[^"]*\b(?:container|row|col-)\b', "Bootstrap classes or script"),
    ("Material UI", r'mui[-/]|MuiButton|MuiTypography', "Material UI component marker"),
    ("Foundation", r'foundation[.-]|class="[^"]*\b(?:small-|medium-|large-)\d', "Foundation grid classes"),
    ("Bulma", r'bulma[.-]|class="[^"]*\b(?:is-primary|is-info|is-success)\b', "Bulma utility classes"),
    ("Chakra UI", r'chakra-ui|ChakraProvider', "Chakra UI marker"),
]

# ── Analytics & tag managers ────────────────────────────────────────
_ANALYTICS: list[tuple[str, str, str]] = [
    ("GA4", r'gtag\(|google-analytics|googletagmanager\.com/gtag', "Google Analytics 4 snippet"),
    ("GTM", r'googletagmanager\.com/gtm|GTM-[A-Z0-9]+', "Google Tag Manager"),
    ("Segment", r'segment\.com/analytics|analytics\.js', "Segment analytics"),
    ("Mixpanel", r'mixpanel\.com|mixpanel\.init', "Mixpanel snippet"),
    ("Heap", r'heap-\d+|heapanalytics\.com', "Heap analytics"),
    ("Adobe Analytics", r's_code|omniture|demdex\.net|omtrdc\.net', "Adobe Analytics snippet"),
    ("Hotjar", r'hotjar\.com|_hjSettings', "Hotjar tracking"),
    ("FullStory", r'fullstory\.com|_fs_namespace', "FullStory session replay"),
    ("Microsoft Clarity", r'clarity\.ms|clarity\.js', "Microsoft Clarity"),
    ("Amplitude", r'amplitude\.com|amplitude\.init', "Amplitude analytics"),
]

# ── Third-party services ────────────────────────────────────────────
_THIRD_PARTY: list[tuple[str, str, str]] = [
    ("Intercom", r'intercom\.com|intercomSettings', "Intercom widget"),
    ("Zendesk", r'zdassets\.com|zendesk', "Zendesk assets"),
    ("HubSpot", r'hs-scripts\.com|hubspot\.com|_hsp', "HubSpot tracking"),
    ("OneTrust", r'onetrust\.com|otBannerSdk', "OneTrust consent banner"),
    ("reCAPTCHA", r'recaptcha|grecaptcha', "Google reCAPTCHA"),
    ("Stripe", r'js\.stripe\.com/v3|stripe\.js', "Stripe payments"),
    ("Sentry", r'sentry\.io|sentry-cdn\.com|@sentry|Sentry\.init', "Sentry error tracking"),
    ("LaunchDarkly", r'launchdarkly\.com|ld-client', "LaunchDarkly feature flags"),
    ("Optimizely", r'optimizely\.com|optimizely\.js', "Optimizely experimentation"),
    ("Drift", r'drift\.com|driftt\.com', "Drift chat"),
    ("LiveChat", r'livechatinc\.com|__lc\b', "LiveChat widget"),
    ("Crisp", r'crisp\.chat|CRISP_WEBSITE_ID', "Crisp chat"),
    ("Freshdesk", r'freshdesk\.com|freshchat', "Freshdesk support"),
    ("Salesforce Chat", r'salesforceliveagent|liveagent\.salesforce', "Salesforce live agent"),
]

# ── Payment services ────────────────────────────────────────────────
_PAYMENT: list[tuple[str, str, str]] = [
    ("PayPal", r'paypal\.com/sdk|paypalobjects\.com', "PayPal SDK"),
    ("Square", r'squareup\.com|square\.js|web-payments-sdk', "Square payments"),
    ("Braintree", r'braintree-api\.com|braintreegateway\.com|braintree\.js', "Braintree payments"),
    ("Adyen", r'adyen\.com|checkoutshopper', "Adyen payments"),
    ("Razorpay", r'razorpay\.com|Razorpay', "Razorpay payments"),
]

# ── Auth services ───────────────────────────────────────────────────
_AUTH: list[tuple[str, str, str]] = [
    ("Auth0", r'auth0\.com|auth0-js|auth0\.js', "Auth0 SDK"),
    ("Okta", r'okta\.com|okta-auth-js', "Okta SDK"),
    ("Firebase Auth", r'firebase\.google\.com|firebaseapp\.com|firebase/auth', "Firebase Auth"),
    ("Clerk", r'clerk\.com|clerk\.js|@clerk/', "Clerk auth"),
]

# ── Maps ────────────────────────────────────────────────────────────
_MAPS: list[tuple[str, str, str]] = [
    ("Google Maps", r'maps\.googleapis\.com|maps\.google\.com', "Google Maps API"),
    ("Mapbox", r'mapbox\.com|mapboxgl|mapbox-gl', "Mapbox"),
    ("Leaflet", r'leaflet\.js|leaflet\.css|L\.map', "Leaflet maps"),
]

# ── Video ───────────────────────────────────────────────────────────
_VIDEO: list[tuple[str, str, str]] = [
    ("YouTube", r'youtube\.com/embed|youtube-nocookie\.com|ytimg\.com', "YouTube embed"),
    ("Vimeo", r'player\.vimeo\.com|vimeo\.com/video', "Vimeo embed"),
    ("Wistia", r'wistia\.com|wistia-video|wistia\.net', "Wistia video"),
    ("Vidyard", r'vidyard\.com|play\.vidyard', "Vidyard video"),
]

# ── Fonts ───────────────────────────────────────────────────────────
_FONTS: list[tuple[str, str, str]] = [
    ("Google Fonts", r'fonts\.googleapis\.com|fonts\.gstatic\.com', "Google Fonts"),
    ("Adobe Fonts", r'use\.typekit\.net|typekit\.com|fonts\.adobe\.com', "Adobe Fonts/Typekit"),
    ("Font Awesome", r'fontawesome|font-awesome|fa-[a-z]', "Font Awesome"),
]

# ── Image CDN ───────────────────────────────────────────────────────
_IMAGE_CDN: list[tuple[str, str, str]] = [
    ("Cloudinary", r'cloudinary\.com|res\.cloudinary', "Cloudinary image CDN"),
    ("imgix", r'imgix\.net|imgix\.com', "imgix image CDN"),
    ("Fastly IO", r'fastly\.net.*\?.*format=|fastly\.io', "Fastly Image Optimization"),
]

# ── Communication ───────────────────────────────────────────────────
_COMMUNICATION: list[tuple[str, str, str]] = [
    ("Twilio", r'twilio\.com', "Twilio"),
    ("Pusher", r'pusher\.com|pusher\.js', "Pusher realtime"),
    ("Firebase Realtime", r'firebaseio\.com|firebase\.database', "Firebase Realtime DB"),
    ("Socket.io", r'socket\.io|socketio', "Socket.io"),
]

# ── E-commerce ──────────────────────────────────────────────────────
_ECOMMERCE: list[tuple[str, str, str]] = [
    ("Shopify", r'cdn\.shopify\.com|myshopify\.com|Shopify\.theme', "Shopify platform"),
    ("BigCommerce", r'bigcommerce\.com|stencil-utils', "BigCommerce platform"),
    ("WooCommerce", r'woocommerce|wc-blocks|wc-settings', "WooCommerce plugin"),
    ("Magento", r'mage/|magento|requirejs-config\.js.*Magento', "Magento platform"),
]

# ── Monitoring ──────────────────────────────────────────────────────
_MONITORING: list[tuple[str, str, str]] = [
    ("New Relic", r'newrelic\.com|nr-data\.net|NREUM', "New Relic monitoring"),
    ("Datadog RUM", r'datadoghq\.com.*rum|dd-rum|DD_RUM', "Datadog RUM"),
    ("Dynatrace", r'dynatrace\.com|dynaTrace|dtagent', "Dynatrace monitoring"),
]

# ── Consent ─────────────────────────────────────────────────────────
_CONSENT: list[tuple[str, str, str]] = [
    ("CookieBot", r'cookiebot\.com|CookieConsent|Cookiebot', "CookieBot consent"),
    ("Osano", r'osano\.com|osano\.js', "Osano consent"),
    ("Termly", r'termly\.io|termly\.js', "Termly consent"),
]

# ── Meta generator → CMS mapping ───────────────────────────────────
_GENERATOR_MAP: list[tuple[str, str]] = [
    ("WordPress", "wordpress"),
    ("Drupal", "drupal"),
    ("Ghost", "ghost"),
    ("Wix", "wix"),
    ("Squarespace", "squarespace"),
    ("Joomla", "joomla"),
    ("Shopify", "shopify"),
    ("Hugo", "hugo"),
    ("Jekyll", "jekyll"),
]

# ── CDN URL patterns for dependency extraction ─────────────────────
_CDN_PATTERNS = [
    # cdnjs.cloudflare.com/ajax/libs/{name}/{version}/...
    re.compile(r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)'),
    # cdn.jsdelivr.net/npm/{name}@{version}/...
    re.compile(r'cdn\.jsdelivr\.net/npm/([^@/]+)@([^/]+)'),
    # unpkg.com/{name}@{version}/...
    re.compile(r'unpkg\.com/([^@/]+)@([^/]+)'),
]


class FrontendAnalyser:
    """Analyses HTML for client-side technology signals."""

    def __init__(self, http_client: HttpClientPort) -> None:
        self._http = http_client

    @property
    def name(self) -> str:
        return "frontend"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target: AnalysisTarget) -> FrontendResult:
        resp = await self._http.get(target.url)
        html = resp.text

        detections: list[TechDetection] = []

        # Scan for technology patterns across all categories
        for category, patterns in [
            ("js_framework", _JS_FRAMEWORKS),
            ("css_framework", _CSS_FRAMEWORKS),
            ("analytics", _ANALYTICS),
            ("third_party", _THIRD_PARTY),
            ("payment", _PAYMENT),
            ("auth", _AUTH),
            ("maps", _MAPS),
            ("video", _VIDEO),
            ("fonts", _FONTS),
            ("image_cdn", _IMAGE_CDN),
            ("communication", _COMMUNICATION),
            ("ecommerce", _ECOMMERCE),
            ("monitoring", _MONITORING),
            ("consent", _CONSENT),
        ]:
            for tech_name, pattern, evidence in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    detections.append(
                        TechDetection(category=category, name=tech_name, evidence=evidence)
                    )

        # Meta generator tag
        meta_generator = self._extract_meta_generator(html)
        if meta_generator:
            for cms_name, keyword in _GENERATOR_MAP:
                if keyword in meta_generator.lower():
                    detections.append(
                        TechDetection(
                            category="cms",
                            name=cms_name,
                            evidence=f'<meta generator="{meta_generator}">',
                        )
                    )
                    break

        # PWA detection
        if re.search(r'<link[^>]+rel=["\']manifest["\']', html, re.IGNORECASE):
            detections.append(
                TechDetection(category="pwa", name="Web App Manifest", evidence='<link rel="manifest">')
            )
        if re.search(r'serviceWorker\.register|navigator\.serviceWorker', html, re.IGNORECASE):
            detections.append(
                TechDetection(category="pwa", name="Service Worker", evidence="Service worker registration")
            )

        # Open Graph / social meta tags
        og_tags = re.findall(r'<meta[^>]+property=["\']og:(\w+)["\']', html, re.IGNORECASE)
        twitter_tags = re.findall(r'<meta[^>]+name=["\']twitter:(\w+)["\']', html, re.IGNORECASE)
        if og_tags:
            detections.append(
                TechDetection(
                    category="social_meta",
                    name="Open Graph",
                    evidence=f"og:{', og:'.join(sorted(set(og_tags[:5])))}",
                )
            )
        if twitter_tags:
            detections.append(
                TechDetection(
                    category="social_meta",
                    name="Twitter Cards",
                    evidence=f"twitter:{', twitter:'.join(sorted(set(twitter_tags[:5])))}",
                )
            )

        # Script complexity signal
        script_tags = re.findall(r'<script\b[^>]*>', html, re.IGNORECASE)
        total_scripts = len(script_tags)
        external_domains: set[str] = set()
        for tag in script_tags:
            src_match = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if src_match:
                domain_match = re.match(r'https?://([^/]+)', src_match.group(1))
                if domain_match:
                    external_domains.add(domain_match.group(1))
        if total_scripts > 0:
            detections.append(
                TechDetection(
                    category="complexity",
                    name="Script tags",
                    evidence=f"{total_scripts} total, {len(external_domains)} external domains",
                )
            )

        # SPA vs SSR inference
        rendering = self._infer_rendering(html)

        # New extractions
        script_dependencies = self._extract_script_dependencies(html)
        structured_data_types = self._extract_structured_data(html)
        preconnect_domains = self._extract_preconnect_domains(html)

        return FrontendResult(
            detections=detections,
            meta_generator=meta_generator,
            rendering=rendering,
            script_dependencies=script_dependencies,
            structured_data_types=structured_data_types,
            preconnect_domains=preconnect_domains,
        )

    @staticmethod
    def _extract_meta_generator(html: str) -> str | None:
        m = re.search(
            r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if m:
            return m.group(1).strip()
        m = re.search(
            r'<meta\s[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
            html,
            re.IGNORECASE,
        )
        return m.group(1).strip() if m else None

    @staticmethod
    def _infer_rendering(html: str) -> str:
        body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.DOTALL | re.IGNORECASE)
        if not body_match:
            return "unknown"
        body_content = body_match.group(1).strip()
        text_only = re.sub(r"<script[^>]*>.*?</script>", "", body_content, flags=re.DOTALL | re.IGNORECASE)
        text_only = re.sub(r"<[^>]+>", "", text_only).strip()
        has_js_bundle = bool(re.search(r'<script[^>]+src=["\'][^"\']+\.js', body_content, re.IGNORECASE))
        if len(text_only) < 50 and has_js_bundle:
            return "spa"
        if len(text_only) >= 50:
            return "ssr"
        return "static"

    @staticmethod
    def _extract_script_dependencies(html: str) -> list[ScriptDependency]:
        deps: list[ScriptDependency] = []
        seen: set[str] = set()

        src_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in src_matches:
            for cdn_pattern in _CDN_PATTERNS:
                m = cdn_pattern.search(src)
                if m:
                    name = m.group(1)
                    version = m.group(2)
                    key = f"{name}@{version}"
                    if key not in seen:
                        seen.add(key)
                        cdn = ""
                        if "cdnjs" in src:
                            cdn = "cdnjs"
                        elif "jsdelivr" in src:
                            cdn = "jsdelivr"
                        elif "unpkg" in src:
                            cdn = "unpkg"
                        deps.append(ScriptDependency(name=name, version=version, cdn=cdn))
                    break
        return deps

    @staticmethod
    def _extract_structured_data(html: str) -> list[str]:
        types: list[str] = []
        ld_blocks = re.findall(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        for block in ld_blocks:
            try:
                data = json.loads(block.strip())
                if isinstance(data, dict) and "@type" in data:
                    t = data["@type"]
                    if isinstance(t, list):
                        types.extend(t)
                    else:
                        types.append(t)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "@type" in item:
                            t = item["@type"]
                            if isinstance(t, list):
                                types.extend(t)
                            else:
                                types.append(t)
            except (json.JSONDecodeError, TypeError):
                pass
        return list(dict.fromkeys(types))  # dedupe preserving order

    @staticmethod
    def _extract_preconnect_domains(html: str) -> list[str]:
        domains: list[str] = []
        matches = re.findall(
            r'<link[^>]+rel=["\'](?:dns-prefetch|preconnect)["\'][^>]+href=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        # Also try reversed attribute order
        matches += re.findall(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:dns-prefetch|preconnect)["\']',
            html,
            re.IGNORECASE,
        )
        for href in matches:
            # Extract domain from URL
            domain_match = re.match(r'(?:https?://)?([^/]+)', href)
            if domain_match:
                domain = domain_match.group(1)
                if domain not in domains:
                    domains.append(domain)
        return domains
