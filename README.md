# StackLens

**Reverse-engineer the tech stack of any public website from a single URL.**

StackLens analyses DNS records, TLS certificates, HTTP headers, frontend source, backend behaviour, and optionally runs a headless browser to capture runtime performance — then produces a unified report with cross-layer intelligence.

## Quick Start

```bash
# Install
uv sync

# Basic scan (DNS + TLS + Headers + Frontend + Backend)
uv run stacklens analyze https://example.com

# Deep scan with browser analysis
uv run stacklens analyze https://example.com --deep

# Performance scoring
uv run stacklens analyze https://example.com --perf

# Generate HTML report
uv run stacklens analyze https://example.com --deep --html
```

## Installation

Requires Python 3.11+.

```bash
git clone <repo-url> && cd stacklens
uv sync
```

For browser analysis (`--deep` / `--perf`), install Playwright:

```bash
uv sync --extra browser
uv run playwright install chromium
```

## CLI Usage

### `stacklens analyze`

Analyse a public-facing URL across multiple layers.

```
stacklens analyze <URL> [OPTIONS]
```

| Option | Description |
|---|---|
| `--layers`, `-l` | Comma-separated layers to run (default: `dns,tls,headers,frontend,backend`) |
| `--deep` | Enable browser analysis (requires Playwright) |
| `--perf` | Enable Lighthouse-style performance scoring (implies `--deep`) |
| `--html` | Generate an HTML report alongside JSON |
| `--output-dir`, `-o` | Output directory (default: `stacklens_output`) |
| `--ethical-strict` | Abort if `robots.txt` disallows scanning |
| `--no-ai` / `--ai` | Disable/enable AI analysis (default: disabled) |

### `stacklens report`

Convert an existing JSON report to a self-contained HTML file.

```
stacklens report <JSON_PATH> [--output PATH]
```

## Analysis Layers

### DNS

Queries A, AAAA, MX, TXT, CNAME, NS records. Detects:

- **Hosting providers** — AWS Route53, Cloudflare, Google Cloud DNS, Azure DNS, and more
- **CDN** — CloudFront, Cloudflare, Akamai, Fastly, Edgecast, Azure CDN
- **Email providers** — Google Workspace, Microsoft 365, Proofpoint, Mimecast
- **Email services** (via SPF) — AWS SES, SendGrid, Mailchimp, Mandrill, HubSpot
- **Domain verifications** — Google, Facebook, Apple, Atlassian, Stripe, GitHub, Adobe
- **Security** — DMARC policy, CAA issuers, PTR records

### TLS

Connects and inspects the TLS handshake:

- Protocol version (TLS 1.2, 1.3)
- Cipher suite and strength assessment
- Certificate subject, issuer, SAN list
- Days until expiry
- Wildcard and Extended Validation detection
- Key type (RSA, ECDSA)

### Headers

Fetches the page and evaluates HTTP response headers:

- **Security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COEP, COOP, CORP
- **CORS** configuration
- **Caching** — Cache-Control, ETag, Vary
- **Cookie analysis** — Secure, HttpOnly, SameSite flags; tracking cookie identification (GA, Facebook Pixel, Stripe, Hotjar, HubSpot, etc.)
- **Security score** — 0–100% based on header presence

### Frontend

Parses the HTML source to detect client-side technologies:

- **JS frameworks** — React, Next.js, Vue, Nuxt, Angular, Svelte, Remix, Astro, jQuery, Alpine.js, HTMX, Lit, Preact, Gatsby, and more
- **CSS frameworks** — Tailwind, Bootstrap, Material UI, Chakra UI, Bulma, Foundation
- **Analytics** — GA4, GTM, Segment, Mixpanel, Heap, Adobe Analytics, Hotjar, FullStory, Clarity, Amplitude
- **Third-party services** — Intercom, Zendesk, Sentry, LaunchDarkly, OneTrust, reCAPTCHA, Stripe, Auth0, Okta
- **Payment, maps, video, fonts, image CDNs** — PayPal, Google Maps, Mapbox, YouTube, Vimeo, Google Fonts, Cloudinary, imgix
- **Rendering mode** — CSR vs SSR
- **Script dependencies** with version and CDN source
- **Structured data** (JSON-LD) and preconnect hints

### Backend

Probes response headers, cookies, and well-known endpoints:

- **Server software** — nginx, Apache, IIS, Gunicorn, Uvicorn, Caddy, LiteSpeed, Envoy, Varnish
- **Cloud providers** — AWS (with region detection), GCP, Azure
- **WAF** — Cloudflare, Sucuri, Imperva, Akamai
- **Tracing** — B3 (Zipkin/Jaeger), W3C Trace Context, Datadog, AWS X-Ray
- **API signals** — REST, GraphQL, gRPC
- **Database hints** — PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch
- **Architecture patterns** — microservices, serverless, monolithic
- **Auth providers** — OAuth flows, SAML, SSO providers
- **Endpoint probing** — `/api`, `/graphql`, `/swagger/`, `/health`, `/sitemap.xml`, `/.well-known/security.txt`

### Browser (optional)

Launches a headless Chromium via Playwright to capture runtime behaviour:

- **Network** — total requests, transfer size, first-party vs third-party split, HTTP protocols, GraphQL queries, SSE endpoints, WebSocket connections
- **Core Web Vitals** — TTFB, FCP, LCP, CLS, TBT
- **Page timing** — DOM Interactive, DOM Complete, Load Event
- **Resource breakdown** — bytes by resource type, render-blocking resource count
- **Runtime detection** — Next.js, Nuxt, Remix, Service Worker status, global objects
- **Storage** — cookies with full attributes, localStorage/sessionStorage keys
- **DOM** — element count, iframes, Shadow DOM, lazy images, rendered HTML size
- **Console** — error count, warning count, uncaught exceptions

## Performance Scoring

When `--perf` is passed, StackLens computes a Lighthouse-style performance score using Google's Web Vitals thresholds:

| Metric | Good | Needs Improvement | Poor | Weight |
|---|---|---|---|---|
| LCP | ≤ 2500 ms | ≤ 4000 ms | > 4000 ms | 25% |
| CLS | ≤ 0.10 | ≤ 0.25 | > 0.25 | 25% |
| TBT | ≤ 200 ms | ≤ 600 ms | > 600 ms | 30% |
| FCP | ≤ 1800 ms | ≤ 3000 ms | > 3000 ms | 10% |
| TTFB | ≤ 800 ms | ≤ 1800 ms | > 1800 ms | 10% |

The overall score (0–100) is a weighted average of available metrics, graded A (≥90) through F (<25). Missing metrics are excluded and weights redistributed.

The performance section includes:
- Overall score with letter grade
- Per-metric scores and ratings
- Resource breakdown by type
- Network stats (requests, third-party ratio, transfer size, render-blocking count)

## Cross-Layer Intelligence

The summary builder aggregates findings across all layers to produce:

- **Hosting** — combined DNS provider, CDN, and cloud provider
- **Tech stack** — unified list from frontend and backend detections
- **Security posture** — derived from header score, TLS version, HSTS, and certificate quality
- **Architecture** — microservices, serverless, monolithic signals
- **API stack** — GraphQL, REST, gRPC, SSE, WebSocket
- **Integrations** — deduplicated third-party services (250+ recognized)
- **Data/storage** — database and caching technology hints
- **Maturity rating** — enterprise / growth / startup based on signal breadth
- **Key findings** — curated insights (poor LCP, console errors, heavy page weight, TLS expiry warnings)

## Output Formats

### JSON

Structured report saved to `stacklens_output/stacklens_<scan_id>.json`. Contains all raw data from every layer, the cross-layer summary, and performance score.

### HTML

Self-contained HTML file with a dark-themed dashboard including:
- Summary card with tech stack, security posture, and performance badge
- Performance section with SVG score gauge, metric cards, and resource breakdown chart
- Detailed cards for each analysis layer
- Integrations table

Generate with `--html` during analysis, or convert an existing JSON report:

```bash
uv run stacklens report stacklens_output/stacklens_*.json
```

## Ethics

StackLens only analyses public-facing URLs. The `--ethical-strict` flag checks `robots.txt` before scanning and aborts if the site disallows it. All requests use a standard browser user-agent.

## Architecture

```
src/stacklens/
├── domain/              # Models, ports (interfaces), domain services
├── application/         # Use cases, pipeline orchestration, summary builder
├── infrastructure/      # Analysers, HTTP adapter, report writers, DI container
└── presentation/        # CLI commands (Typer + Rich)
```

Key design decisions:
- **Hexagonal architecture** — domain logic is isolated from infrastructure behind protocol-based ports
- **Immutable models** — all domain objects are frozen Pydantic models, built via copy-on-write (`with_layer_result`, `with_summary`)
- **DAG orchestration** — the analysis pipeline resolves analyser dependencies via topological sort and runs independent layers concurrently (5-worker semaphore)
- **Error isolation** — a failing layer produces an error dict instead of aborting the entire scan

## Testing

```bash
# Full suite
uv run pytest tests/ -v

# Specific areas
uv run pytest tests/domain/test_performance_scoring.py -v
uv run pytest tests/infrastructure/test_html_writer.py -v
```

## License

See [LICENSE](LICENSE) for details.
