/* ── StackLens Web Frontend ─────────────────────────────── */
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const el = (tag, attrs = {}, ...children) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "className") e.className = v;
    else if (k === "innerHTML") e.innerHTML = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2).toLowerCase(), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (typeof c === "string") e.appendChild(document.createTextNode(c));
    else if (c) e.appendChild(c);
  }
  return e;
};

const esc = (s) => {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
};

const formatBytes = (n) => {
  for (const u of ["B", "KB", "MB", "GB"]) {
    if (Math.abs(n) < 1024) return u === "B" ? `${n.toFixed(0)} ${u}` : `${n.toFixed(1)} ${u}`;
    n /= 1024;
  }
  return `${n.toFixed(1)} TB`;
};

const VALID_LAYERS = ["dns", "tls", "headers", "frontend", "backend", "browser"];
const DEFAULT_LAYERS = ["dns", "tls", "headers", "frontend", "backend"];

const app = $("#app");
let currentReport = null;

/* ── Landing View ──────────────────────────────────────── */
function showLanding() {
  app.innerHTML = "";
  const wrap = el("div", { className: "landing" });

  wrap.appendChild(el("h1", {}, "StackLens"));
  wrap.appendChild(el("p", { className: "subtitle" }, "AI-augmented web technology analysis"));

  const box = el("div", { className: "form-box" });

  box.appendChild(el("label", { for: "url" }, "URL to analyse"));
  const input = el("input", {
    type: "text",
    id: "url",
    className: "url-input",
    placeholder: "example.com",
    autocomplete: "off",
  });
  box.appendChild(input);

  // Layer checkboxes
  const layerDiv = el("div", { className: "layer-checks" });
  layerDiv.appendChild(el("label", { style: "color:#8b949e;font-size:.8rem;width:100%" }, "Layers:"));
  for (const l of VALID_LAYERS) {
    const checked = DEFAULT_LAYERS.includes(l);
    const cb = el("input", { type: "checkbox", value: l, ...(checked ? { checked: "" } : {}) });
    if (checked) cb.checked = true;
    layerDiv.appendChild(el("label", {}, cb, ` ${l}`));
  }
  box.appendChild(layerDiv);

  // Perf toggle
  const perfDiv = el("div", { className: "perf-toggle" });
  const perfCb = el("input", { type: "checkbox", id: "perf" });
  perfDiv.appendChild(el("label", {}, perfCb, " Enable performance scoring"));
  box.appendChild(perfDiv);

  const btn = el("button", { className: "btn-analyze", type: "button" }, "Analyze");
  box.appendChild(btn);

  wrap.appendChild(box);
  app.appendChild(wrap);

  input.addEventListener("keydown", (e) => { if (e.key === "Enter") btn.click(); });
  btn.addEventListener("click", () => {
    const url = input.value.trim();
    if (!url) return;
    const layers = $$(".layer-checks input:checked", box).map((c) => c.value);
    const perf = perfCb.checked;
    startAnalysis(url, layers, perf);
  });

  input.focus();
}

/* ── Loading / SSE Progress View ───────────────────────── */
function startAnalysis(url, layers, perf) {
  app.innerHTML = "";
  const wrap = el("div", { className: "loading" });
  wrap.appendChild(el("h2", {}, `Analysing ${url}...`));

  const list = el("div", { className: "progress-layers" });
  const statusMap = {};
  for (const l of layers) {
    const row = el("div", { className: "layer-status pending" });
    row.innerHTML = `<span class="icon">&#x25CB;</span><span>${esc(l)}</span>`;
    list.appendChild(row);
    statusMap[l] = row;
  }
  wrap.appendChild(list);
  app.appendChild(wrap);

  const setLayerStatus = (layer, status) => {
    const row = statusMap[layer];
    if (!row) return;
    row.className = `layer-status ${status}`;
    if (status === "running")
      row.querySelector(".icon").innerHTML = '<span class="spinner"></span>';
    else if (status === "done")
      row.querySelector(".icon").innerHTML = "&#x2713;";
    else if (status === "error")
      row.querySelector(".icon").innerHTML = "&#x2717;";
  };

  // SSE stream
  const params = new URLSearchParams({ url, layers: layers.join(","), perf: perf ? "1" : "0" });
  const evtSource = new EventSource(`/api/analyze/stream?${params}`);

  evtSource.addEventListener("layer_start", (e) => {
    const d = JSON.parse(e.data);
    setLayerStatus(d.layer, "running");
  });

  evtSource.addEventListener("layer_done", (e) => {
    const d = JSON.parse(e.data);
    setLayerStatus(d.layer, "done");
  });

  evtSource.addEventListener("layer_error", (e) => {
    const d = JSON.parse(e.data);
    setLayerStatus(d.layer, "error");
  });

  evtSource.addEventListener("complete", (e) => {
    evtSource.close();
    const report = JSON.parse(e.data);
    currentReport = report;
    showDashboard(report);
  });

  evtSource.addEventListener("error_msg", (e) => {
    evtSource.close();
    const d = JSON.parse(e.data);
    showError(d.error || "Analysis failed");
  });

  evtSource.onerror = () => {
    evtSource.close();
    showError("Connection lost during analysis.");
  };
}

/* ── Error View ────────────────────────────────────────── */
function showError(msg) {
  app.innerHTML = "";
  const wrap = el("div", { className: "error-view" });
  wrap.appendChild(el("div", { className: "error-msg" }, msg));
  const btn = el("button", { className: "btn btn-primary", onClick: showLanding }, "Try Again");
  wrap.appendChild(btn);
  app.appendChild(wrap);
}

/* ── Dashboard ─────────────────────────────────────────── */
function showDashboard(report) {
  app.innerHTML = "";
  const dash = el("div", { className: "dashboard" });

  // Header
  const hdr = el("div", { className: "dash-header" });
  hdr.appendChild(el("h1", {}, `StackLens — ${esc(report.target?.hostname || "")}`));
  const meta = report.meta || {};
  const layerList = (meta.layers || []).join(", ") || "—";
  hdr.appendChild(el("p", { className: "meta" },
    `Scan ID: ${esc(meta.scan_id)} · ${esc(meta.started_at)} · Layers: ${esc(layerList)} · v${esc(meta.version)}`
  ));

  // Action buttons
  const actions = el("div", { className: "dash-actions" });
  actions.appendChild(el("button", { className: "btn", onClick: downloadJSON }, "Download JSON"));
  actions.appendChild(el("button", { className: "btn", onClick: exportHTML }, "Export HTML"));
  actions.appendChild(el("button", { className: "btn btn-primary", onClick: showLanding }, "New Scan"));
  hdr.appendChild(actions);
  dash.appendChild(hdr);

  // Summary card
  if (report.summary) dash.appendChild(buildSummaryCard(report));

  // Performance card
  if (report.performance_score) dash.appendChild(buildPerformanceCard(report.performance_score));

  // Recommendations
  if (report.recommendations?.items?.length) dash.appendChild(buildRecommendations(report.recommendations));

  // Layer cards
  const layerRenderers = {
    dns: buildDnsCard,
    tls: buildTlsCard,
    headers: buildHeadersCard,
    frontend: buildFrontendCard,
    backend: buildBackendCard,
    browser: buildBrowserCard,
  };
  for (const [name, renderer] of Object.entries(layerRenderers)) {
    const data = report.layers?.[name];
    if (!data) continue;
    if (data.error) {
      dash.appendChild(buildErrorCard(name, data.error));
    } else {
      dash.appendChild(renderer(data));
    }
  }

  // Integrations
  if (report.summary?.integrations?.length) dash.appendChild(buildIntegrations(report.summary.integrations));

  app.appendChild(dash);
}

/* ── Export Actions ─────────────────────────────────────── */
function downloadJSON() {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
  const a = el("a", { href: URL.createObjectURL(blob), download: `stacklens_${currentReport.meta?.scan_id || "report"}.json` });
  a.click();
  URL.revokeObjectURL(a.href);
}

async function exportHTML() {
  if (!currentReport) return;
  try {
    const res = await fetch("/api/export/html", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentReport),
    });
    if (!res.ok) throw new Error("Export failed");
    const html = await res.text();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) {
    alert("HTML export failed: " + e.message);
  }
}

/* ── Card Builders ─────────────────────────────────────── */

function collapsibleCard(title, buildBody) {
  const card = el("div", { className: "card card-collapsible" });
  const h2 = el("h2", {}, title);
  const body = el("div", { className: "card-body" });
  buildBody(body);
  h2.addEventListener("click", () => card.classList.toggle("open"));
  card.appendChild(h2);
  card.appendChild(body);
  return card;
}

function kvGrid(pairs) {
  const dl = el("dl", { className: "kv" });
  for (const [label, value] of pairs) {
    if (value == null || value === "" || value === "Unknown") continue;
    dl.appendChild(el("dt", {}, label));
    const dd = el("dd");
    if (typeof value === "object" && value.nodeType) dd.appendChild(value);
    else dd.textContent = String(value);
    dl.appendChild(dd);
  }
  return dl;
}

function securityBadge(posture) {
  const low = (posture || "").toLowerCase();
  let cls = "badge-bad";
  if (low.includes("good") || low.includes("strong")) cls = "badge-good";
  else if (low.includes("moderate") || low.includes("mixed")) cls = "badge-warn";
  return el("span", { className: `badge ${cls}` }, posture);
}

/* ── Summary Card ──────────────────────────────────────── */
function buildSummaryCard(report) {
  const s = report.summary;
  const card = el("div", { className: "card" });
  card.appendChild(el("h2", {}, "Summary"));

  const pairs = [];
  if (s.hosting && s.hosting !== "Unknown") pairs.push(["Hosting", s.hosting]);
  if (s.tech_stack?.length) pairs.push(["Stack", s.tech_stack.join(", ")]);
  if (s.architecture?.length) pairs.push(["Architecture", s.architecture.join(", ")]);
  if (s.api_stack?.length) pairs.push(["API Stack", s.api_stack.join(", ")]);
  if (s.data_storage?.length) pairs.push(["Data/Storage", s.data_storage.join(", ")]);
  if (s.security_posture && s.security_posture !== "Unknown")
    pairs.push(["Security", securityBadge(s.security_posture)]);
  if (s.maturity_rating && s.maturity_rating !== "unknown")
    pairs.push(["Maturity", el("span", { className: "badge badge-good" }, s.maturity_rating)]);

  const ps = report.performance_score;
  if (ps) {
    const gradeColors = { A: "#2dd4bf", B: "#2dd4bf", C: "#f59e0b", D: "#f87171", F: "#f87171" };
    const c = gradeColors[ps.grade] || "#c9d1d9";
    const badge = el("span", { className: "perf-badge", style: `background:${c}20;color:${c}` },
      `${ps.overall_score}/100 (${ps.grade})`);
    pairs.push(["Performance", badge]);
  }

  card.appendChild(kvGrid(pairs));

  if (s.key_findings?.length) {
    const sec = el("div", { className: "sub-section" });
    sec.appendChild(el("h3", {}, "Key Findings"));
    for (const f of s.key_findings) sec.appendChild(el("div", { className: "finding" }, `\u2022 ${f}`));
    card.appendChild(sec);
  }

  return card;
}

/* ── Performance Card ──────────────────────────────────── */
function buildPerformanceCard(ps) {
  const card = el("div", { className: "card" });
  card.appendChild(el("h2", {}, "Performance"));

  const gradeColors = { A: "#2dd4bf", B: "#2dd4bf", C: "#f59e0b", D: "#f87171", F: "#f87171" };
  const color = gradeColors[ps.grade] || "#c9d1d9";
  const radius = 40;
  const circ = 2 * Math.PI * radius;
  const offset = circ * (1 - ps.overall_score / 100);

  const circle = el("div", { className: "score-circle", innerHTML:
    `<svg width="100" height="100" viewBox="0 0 100 100">` +
    `<circle cx="50" cy="50" r="${radius}" fill="none" stroke="#21262d" stroke-width="6"/>` +
    `<circle cx="50" cy="50" r="${radius}" fill="none" stroke="${color}" stroke-width="6" ` +
    `stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}" ` +
    `stroke-linecap="round" transform="rotate(-90 50 50)"/>` +
    `</svg>` +
    `<div style="text-align:center">` +
    `<div class="score-text" style="color:${color}">${ps.overall_score}</div>` +
    `<div class="grade-text">${ps.grade}</div></div>`
  });
  card.appendChild(circle);

  // Metric cards
  const ratingColors = { good: "#2dd4bf", "needs-improvement": "#f59e0b", poor: "#f87171" };
  const grid = el("div", { className: "metric-grid" });
  for (const m of ps.metrics || []) {
    if (m.rating === "unknown") continue;
    const mc = ratingColors[m.rating] || "#8b949e";
    const mc_el = el("div", { className: "metric-card", innerHTML:
      `<div class="metric-name">${esc(m.name)}</div>` +
      `<div class="metric-value" style="color:${mc}">${esc(m.display)}</div>` +
      `<div class="metric-bar" style="background:${mc}"></div>`
    });
    grid.appendChild(mc_el);
  }
  if (grid.children.length) card.appendChild(grid);

  // Resource breakdown
  if (ps.resource_breakdown && Object.keys(ps.resource_breakdown).length) {
    const maxBytes = Math.max(...Object.values(ps.resource_breakdown));
    const sec = el("div", { className: "sub-section" });
    sec.appendChild(el("h3", {}, "Resource Breakdown"));
    const chart = el("div", { className: "bar-chart" });
    const sorted = Object.entries(ps.resource_breakdown).sort((a, b) => b[1] - a[1]);
    for (const [rtype, rbytes] of sorted) {
      const pct = maxBytes > 0 ? (rbytes / maxBytes * 100) : 0;
      chart.appendChild(el("div", { className: "bar-row", innerHTML:
        `<span class="bar-label">${esc(rtype)}</span>` +
        `<span class="bar-track"><span class="bar-fill" style="width:${pct.toFixed(0)}%"></span></span>` +
        `<span class="bar-size">${formatBytes(rbytes)}</span>`
      }));
    }
    sec.appendChild(chart);
    card.appendChild(sec);
  }

  // Network stats
  const stats = [`Requests: ${ps.total_requests}`];
  if (ps.third_party_ratio > 0) stats.push(`3rd party: ${(ps.third_party_ratio * 100).toFixed(0)}%`);
  if (ps.total_transfer_bytes) stats.push(`Transfer: ${formatBytes(ps.total_transfer_bytes)}`);
  if (ps.render_blocking_count) stats.push(`Render-blocking: ${ps.render_blocking_count}`);
  card.appendChild(el("div", { style: "color:#8b949e;font-size:.85rem;margin-top:.75rem" }, stats.join(" \u00b7 ")));

  return card;
}

/* ── Recommendations ───────────────────────────────────── */
function buildRecommendations(recs) {
  const card = el("div", { className: "card" });
  card.appendChild(el("h2", {}, "Recommendations"));
  const grid = el("div", { className: "rec-grid" });
  for (const rec of recs.items) {
    grid.appendChild(el("div", { className: `rec-item rec-${rec.severity}`, innerHTML:
      `<div style="margin-bottom:.5rem">` +
      `<span class="rec-severity rec-severity-${rec.severity}">${esc(rec.severity)}</span>` +
      `<span class="rec-category">${esc(rec.category)}</span></div>` +
      `<div class="rec-title">${esc(rec.title)}</div>` +
      `<div class="rec-desc">${esc(rec.description)}</div>` +
      `<div class="rec-impact">${esc(rec.impact)}</div>` +
      `<div class="rec-action">${esc(rec.action)}</div>`
    }));
  }
  card.appendChild(grid);
  return card;
}

/* ── DNS Card ──────────────────────────────────────────── */
function buildDnsCard(r) {
  return collapsibleCard("DNS", (body) => {
    body.appendChild(kvGrid([
      ["DNS Provider", r.hosting_provider],
      ["CDN", r.cdn_detected],
      ["Email Provider", r.email_provider],
      ["SPF Services", r.spf_includes?.join(", ")],
      ["DNS Services", r.dns_services?.join(", ")],
      ["DMARC Policy", r.dmarc_policy],
      ["CAA Issuers", r.caa_issuers?.join(", ")],
      ["PTR Records", r.ptr_records?.join(", ")],
      ["Resolved IPs", r.resolved_ips?.join(", ")],
    ]));

    if (r.records?.length) {
      const tbl = el("table", { innerHTML:
        `<tr><th>Type</th><th>Value</th></tr>` +
        r.records.map((rec) =>
          `<tr><td style="color:#8b949e">${esc(rec.record_type)}</td><td style="color:#8b949e">${esc(rec.value)}</td></tr>`
        ).join("")
      });
      body.appendChild(tbl);
    }
  });
}

/* ── TLS Card ──────────────────────────────────────────── */
function buildTlsCard(r) {
  return collapsibleCard("TLS", (body) => {
    const pairs = [
      ["Protocol", r.protocol],
      ["Cipher", r.cipher],
    ];
    if (r.cipher_strength && r.cipher_strength !== "unknown") pairs.push(["Cipher Strength", r.cipher_strength]);
    if (r.key_type) pairs.push(["Key Type", r.key_type]);
    if (r.certificate) {
      pairs.push(["Subject", r.certificate.subject]);
      pairs.push(["Issuer", r.certificate.issuer]);
    }
    if (r.is_wildcard) pairs.push(["Wildcard", "Yes"]);
    if (r.is_ev) pairs.push(["EV Certificate", "Yes"]);
    if (r.days_until_expiry != null) pairs.push(["Days Until Expiry", String(r.days_until_expiry)]);
    body.appendChild(kvGrid(pairs));
  });
}

/* ── Headers Card ──────────────────────────────────────── */
function buildHeadersCard(r) {
  return collapsibleCard("Headers", (body) => {
    let rows = "";
    for (const h of r.security_headers || []) {
      const cls = h.present ? "status-present" : "status-missing";
      const label = h.present ? "present" : "missing";
      rows += `<tr><td>${esc(h.name)}</td><td class="${cls}">${label}</td><td>${esc(h.value || "")}</td></tr>`;
    }
    if (r.score != null) rows += `<tr><td><strong>Score</strong></td><td></td><td><strong>${(r.score * 100).toFixed(0)}%</strong></td></tr>`;

    if (r.cors) for (const [k, v] of Object.entries(r.cors))
      rows += `<tr><td>CORS ${esc(k)}</td><td class="status-present">present</td><td>${esc(v)}</td></tr>`;
    if (r.caching) for (const [k, v] of Object.entries(r.caching))
      rows += `<tr><td>${esc(k)}</td><td class="status-present">present</td><td>${esc(v)}</td></tr>`;
    if (r.cookie_insights) for (const ci of r.cookie_insights)
      rows += `<tr><td>Cookie</td><td></td><td>${esc(ci)}</td></tr>`;

    body.appendChild(el("table", { innerHTML: `<tr><th>Header</th><th>Status</th><th>Value</th></tr>${rows}` }));
  });
}

/* ── Frontend Card ─────────────────────────────────────── */
function buildFrontendCard(r) {
  return collapsibleCard("Frontend", (body) => {
    let rows = "";
    for (const d of r.detections || [])
      rows += `<tr><td>${esc(d.category)}</td><td>${esc(d.name)}</td><td>${esc(d.evidence)}</td></tr>`;
    if (r.meta_generator)
      rows += `<tr><td>generator</td><td>${esc(r.meta_generator)}</td><td>&lt;meta&gt; tag</td></tr>`;
    rows += `<tr><td>rendering</td><td>${esc(r.rendering)}</td><td></td></tr>`;
    if (r.script_dependencies) for (const dep of r.script_dependencies) {
      const ver = dep.version ? `v${dep.version}` : "";
      const cdn = dep.cdn ? ` (${dep.cdn})` : "";
      rows += `<tr><td>dependency</td><td>${esc(dep.name)}</td><td>${esc(ver + cdn)}</td></tr>`;
    }
    if (r.structured_data_types?.length)
      rows += `<tr><td>structured_data</td><td>${esc(r.structured_data_types.join(", "))}</td><td>JSON-LD</td></tr>`;
    if (r.preconnect_domains?.length)
      rows += `<tr><td>preconnect</td><td>${esc(r.preconnect_domains.join(", "))}</td><td>dns-prefetch/preconnect</td></tr>`;

    body.appendChild(el("table", { innerHTML: `<tr><th>Category</th><th>Technology</th><th>Evidence</th></tr>${rows}` }));
  });
}

/* ── Backend Card ──────────────────────────────────────── */
function buildBackendCard(r) {
  return collapsibleCard("Backend", (body) => {
    const pairs = [
      ["Server Software", r.server_software],
      ["Proxy/Gateway", r.proxy_gateway?.join(", ")],
      ["Tracing", r.tracing?.join(", ")],
      ["Framework", r.server_framework?.join(", ")],
      ["CMS", r.cms?.join(", ")],
      ["Cloud", r.cloud_provider?.join(", ")],
      ["WAF", r.waf?.join(", ")],
      ["API Signals", r.api_signals?.join(", ")],
      ["Database Hints", r.database_hints?.join(", ")],
      ["Architecture", r.architecture?.join(", ")],
      ["Auth Providers", r.auth_providers?.join(", ")],
    ];
    if (r.caching) for (const c of r.caching) pairs.push(["Caching", c]);
    if (r.cookie_insights) for (const ci of r.cookie_insights) pairs.push(["Cookie Insight", ci]);
    if (r.elapsed_ms > 0) pairs.push(["Response Time", `${r.elapsed_ms.toFixed(0)}ms`]);
    if (r.infra_hints) for (const h of r.infra_hints) pairs.push(["Infra Hint", h]);
    body.appendChild(kvGrid(pairs));

    const accessible = (r.endpoint_probes || []).filter((p) => p.accessible);
    if (accessible.length) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Accessible Endpoints"));
      let rows = "";
      for (const p of accessible) rows += `<tr><td>${esc(p.path)}</td><td class="status-present">${p.status_code}</td></tr>`;
      sec.appendChild(el("table", { innerHTML: `<tr><th>Path</th><th>Status</th></tr>${rows}` }));
      body.appendChild(sec);
    }
  });
}

/* ── Browser Card ──────────────────────────────────────── */
function buildBrowserCard(r) {
  return collapsibleCard("Browser", (body) => {
    const net = r.network;
    if (net) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Network"));
      const pairs = [
        ["Total Requests", String(net.total_requests)],
        ["Transfer Size", formatBytes(net.total_transfer_bytes)],
        ["1st Party Requests", String(net.first_party_requests)],
        ["3rd Party Requests", String(net.third_party_requests)],
      ];
      if (net.third_party_domains?.length)
        pairs.push(["3rd Party Domains", net.third_party_domains.slice(0, 15).join(", ")]);
      if (net.graphql_queries?.length)
        pairs.push(["GraphQL Queries", String(net.graphql_queries.length)]);
      if (net.streaming_endpoints?.length)
        pairs.push(["SSE Endpoints", String(net.streaming_endpoints.length)]);
      if (net.protocols_used?.length)
        pairs.push(["Protocols", net.protocols_used.join(", ")]);
      if (net.requests_by_type) {
        const breakdown = Object.entries(net.requests_by_type)
          .sort((a, b) => b[1] - a[1])
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ");
        pairs.push(["By Type", breakdown]);
      }
      sec.appendChild(kvGrid(pairs));
      body.appendChild(sec);
    }

    const perf = r.performance;
    if (perf && (perf.ttfb_ms || perf.fcp_ms || perf.lcp_ms || perf.load_event_ms)) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Performance"));
      const pairs = [];
      if (perf.ttfb_ms != null) pairs.push(["TTFB", `${perf.ttfb_ms.toFixed(0)}ms`]);
      if (perf.fcp_ms != null) pairs.push(["FCP", `${perf.fcp_ms.toFixed(0)}ms`]);
      if (perf.lcp_ms != null) pairs.push(["LCP", `${perf.lcp_ms.toFixed(0)}ms`]);
      if (perf.cls != null) pairs.push(["CLS", perf.cls.toFixed(3)]);
      if (perf.dom_interactive_ms != null) pairs.push(["DOM Interactive", `${perf.dom_interactive_ms.toFixed(0)}ms`]);
      if (perf.dom_complete_ms != null) pairs.push(["DOM Complete", `${perf.dom_complete_ms.toFixed(0)}ms`]);
      if (perf.load_event_ms != null) pairs.push(["Load Event", `${perf.load_event_ms.toFixed(0)}ms`]);
      if (perf.total_page_weight_bytes) pairs.push(["Page Weight", formatBytes(perf.total_page_weight_bytes)]);
      sec.appendChild(kvGrid(pairs));
      body.appendChild(sec);
    }

    const fw = r.framework_data;
    if (fw && (fw.next_data || fw.nuxt_data || fw.remix_context || fw.global_objects?.length || fw.service_worker_active)) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Runtime"));
      const pairs = [];
      if (fw.next_data) pairs.push(["Next.js", "detected"]);
      if (fw.nuxt_data) pairs.push(["Nuxt", "detected"]);
      if (fw.remix_context) pairs.push(["Remix", "detected"]);
      if (fw.service_worker_active) pairs.push(["Service Worker", "active"]);
      if (fw.global_objects?.length) pairs.push(["Global Objects", fw.global_objects.join(", ")]);
      if (fw.browser_features?.length) pairs.push(["Browser Features", fw.browser_features.join(", ")]);
      sec.appendChild(kvGrid(pairs));
      body.appendChild(sec);
    }

    const st = r.storage;
    if (st && (st.cookie_count || st.local_storage_keys?.length || st.session_storage_keys?.length)) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Storage"));
      const pairs = [["Cookies", String(st.cookie_count)]];
      if (st.local_storage_keys?.length) pairs.push(["localStorage Keys", String(st.local_storage_keys.length)]);
      if (st.session_storage_keys?.length) pairs.push(["sessionStorage Keys", String(st.session_storage_keys.length)]);
      sec.appendChild(kvGrid(pairs));
      body.appendChild(sec);
    }

    if (r.websockets?.length) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "WebSockets"));
      let rows = "";
      for (const ws of r.websockets) rows += `<tr><td>${esc(ws.url)}</td><td>${ws.frames_sent}</td><td>${ws.frames_received}</td></tr>`;
      sec.appendChild(el("table", { innerHTML: `<tr><th>URL</th><th>Sent</th><th>Received</th></tr>${rows}` }));
      body.appendChild(sec);
    }

    const c = r.console;
    if (c && (c.error_count || c.warning_count || c.uncaught_exceptions?.length)) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Console"));
      const pairs = [["Errors", String(c.error_count)], ["Warnings", String(c.warning_count)]];
      if (c.uncaught_exceptions?.length) pairs.push(["Uncaught Exceptions", String(c.uncaught_exceptions.length)]);
      sec.appendChild(kvGrid(pairs));
      if (c.errors?.length) {
        for (const err of c.errors.slice(0, 5))
          sec.appendChild(el("div", { className: "finding", style: "color:#f87171" }, `\u2022 ${err.slice(0, 120)}`));
      }
      body.appendChild(sec);
    }

    if (r.page_title || r.final_url || r.elapsed_ms) {
      const sec = el("div", { className: "sub-section" });
      sec.appendChild(el("h3", {}, "Page"));
      const pairs = [];
      if (r.page_title) pairs.push(["Page Title", r.page_title]);
      if (r.final_url) pairs.push(["Final URL", r.final_url]);
      if (r.elapsed_ms) pairs.push(["Browser Elapsed", `${r.elapsed_ms.toFixed(0)}ms`]);
      sec.appendChild(kvGrid(pairs));
      body.appendChild(sec);
    }
  });
}

/* ── Integrations Card ─────────────────────────────────── */
function buildIntegrations(integrations) {
  const card = el("div", { className: "card" });
  card.appendChild(el("h2", {}, "Integrations"));
  const list = el("div", { className: "integration-list" });
  for (const svc of integrations) list.appendChild(el("span", { className: "integration-tag" }, svc));
  card.appendChild(list);
  return card;
}

/* ── Error Card ────────────────────────────────────────── */
function buildErrorCard(title, error) {
  const card = el("div", { className: "card" });
  card.appendChild(el("h2", {}, title.charAt(0).toUpperCase() + title.slice(1)));
  card.appendChild(el("p", { className: "status-missing" }, error));
  return card;
}

/* ── Init ──────────────────────────────────────────────── */
showLanding();
