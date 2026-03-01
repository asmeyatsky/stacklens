from __future__ import annotations

import re

from stacklens.domain.models.frontend import FrontendResult, TechDetection
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.ports.http_client import HttpClientPort

# ── JS framework signatures ─────────────────────────────────────────
_JS_FRAMEWORKS: list[tuple[str, str, str]] = [
    # (name, regex pattern on HTML, evidence description)
    ("Next.js", r'__NEXT_DATA__|/_next/', "__NEXT_DATA__ or /_next/ reference"),
    ("React", r'react[-.]|reactDOM|data-reactroot|data-reactid', "React runtime marker"),
    ("Vue", r'vue[.-]|__vue|data-v-', "Vue runtime marker"),
    ("Angular", r'ng-version|ng-app|angular[.-]', "Angular attribute or script"),
    ("Svelte", r'svelte[/-]|__svelte', "Svelte marker"),
    ("Nuxt", r'__NUXT__|_nuxt/', "Nuxt runtime marker"),
    ("Remix", r'__remix|remix-run', "Remix runtime marker"),
    ("Astro", r'astro-island|astro[/-]', "Astro component marker"),
]

# ── CSS framework signatures ────────────────────────────────────────
_CSS_FRAMEWORKS: list[tuple[str, str, str]] = [
    ("Tailwind", r'class="[^"]*\b(?:flex|grid|px-|py-|mt-|mb-|text-)\b', "Tailwind utility classes"),
    ("Bootstrap", r'bootstrap[.-]|class="[^"]*\b(?:container|row|col-)\b', "Bootstrap classes or script"),
    ("Material UI", r'mui[-/]|MuiButton|MuiTypography', "Material UI component marker"),
]

# ── Analytics & tag managers ────────────────────────────────────────
_ANALYTICS: list[tuple[str, str, str]] = [
    ("GA4", r'gtag\(|google-analytics|googletagmanager\.com/gtag', "Google Analytics 4 snippet"),
    ("GTM", r'googletagmanager\.com/gtm|GTM-[A-Z0-9]+', "Google Tag Manager"),
    ("Segment", r'segment\.com/analytics|analytics\.js', "Segment analytics"),
    ("Mixpanel", r'mixpanel\.com|mixpanel\.init', "Mixpanel snippet"),
    ("Heap", r'heap-\d+|heapanalytics\.com', "Heap analytics"),
]

# ── Third-party services ────────────────────────────────────────────
_THIRD_PARTY: list[tuple[str, str, str]] = [
    ("Intercom", r'intercom\.com|intercomSettings', "Intercom widget"),
    ("Zendesk", r'zdassets\.com|zendesk', "Zendesk assets"),
    ("HubSpot", r'hs-scripts\.com|hubspot\.com|_hsp', "HubSpot tracking"),
    ("OneTrust", r'onetrust\.com|otBannerSdk', "OneTrust consent banner"),
    ("reCAPTCHA", r'recaptcha|grecaptcha', "Google reCAPTCHA"),
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

        # Scan for technology patterns
        for category, patterns in [
            ("js_framework", _JS_FRAMEWORKS),
            ("css_framework", _CSS_FRAMEWORKS),
            ("analytics", _ANALYTICS),
            ("third_party", _THIRD_PARTY),
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

        # SPA vs SSR inference
        rendering = self._infer_rendering(html)

        return FrontendResult(
            detections=detections,
            meta_generator=meta_generator,
            rendering=rendering,
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
        # Also try reversed attribute order
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

        # Remove script tags and count remaining visible text
        text_only = re.sub(r"<script[^>]*>.*?</script>", "", body_content, flags=re.DOTALL | re.IGNORECASE)
        text_only = re.sub(r"<[^>]+>", "", text_only).strip()

        has_js_bundle = bool(re.search(r'<script[^>]+src=["\'][^"\']+\.js', body_content, re.IGNORECASE))

        if len(text_only) < 50 and has_js_bundle:
            return "spa"
        if len(text_only) >= 50:
            return "ssr"
        return "static"
