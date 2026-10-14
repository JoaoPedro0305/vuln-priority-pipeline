// Renders the dashboard from the JSON files written by `vulnprio export`.
// Data from outside sources (CVE names, vendors, summaries) only ever reaches the
// page through textContent, never as HTML.
"use strict";

const SVG = "http://www.w3.org/2000/svg";
const pct = (v, digits = 1) => (v == null ? "–" : `${(v * 100).toFixed(digits)}%`);
const int = new Intl.NumberFormat("en-US");
const day = (iso) => (iso ? iso.slice(0, 10) : "–");
// "Jenkins" + "Jenkins Command Line Interface" reads better without the repeat.
const productName = (r) =>
  [r.vendor && !(r.product || "").toLowerCase().startsWith(r.vendor.toLowerCase()) ? r.vendor : null, r.product]
    .filter(Boolean)
    .join(" ") || "–";

const STRATEGIES = {
  priority: { label: "This ranking", color: "--series-1" },
  epss: { label: "EPSS alone", color: "--series-2" },
  cvss: { label: "CVSS alone", color: "--series-3" },
  random: { label: "Random", color: "--series-muted", dashed: true },
  timeline_first: { label: "BOD 26-04 timeline first (dropped)" },
  track_star_first: { label: "Act, attend, track*, then EPSS (dropped)" },
};

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    // Through the CSSOM: the page's CSP blocks inline style attributes.
    else if (key === "background") node.style.background = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

function svg(tag, attrs = {}, text) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text != null) node.textContent = text;
  return node;
}

const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// Charts are drawn at the width they are shown at, so their text keeps its size
// on a phone, and drawn again when that width changes.
const chartWidth = (target) => Math.max(340, Math.min(720, Math.round(target.clientWidth || 720)));
const redraws = [];
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => redraws.forEach((draw) => draw()), 150);
});

async function load(name) {
  const response = await fetch(`data/${name}.json`, { cache: "no-cache" });
  if (!response.ok) throw new Error(`${name}.json: HTTP ${response.status}`);
  return response.json();
}

// --- tables ---------------------------------------------------------------------

function cveLink(id) {
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return document.createTextNode(id);
  return el("a", { href: `https://nvd.nist.gov/vuln/detail/${id}`, rel: "noopener noreferrer", text: id });
}

// columns: [{label, value(row) -> string|Node, class}]
function table(columns, rows, caption) {
  const head = el("tr", {}, ...columns.map((c) => el("th", { class: c.class || "", scope: "col", text: c.label })));
  const body = rows.map((row) =>
    el(
      "tr",
      { class: row._class || "" },
      ...columns.map((c) => {
        const value = c.value(row);
        const cell = el("td", { class: typeof c.class === "function" ? c.class(row) : c.class || "" });
        cell.append(value instanceof Node ? value : document.createTextNode(value ?? "–"));
        return cell;
      }),
    ),
  );
  return el("table", {}, caption ? el("caption", { text: caption }) : null, el("thead", {}, head), el("tbody", {}, ...body));
}

function fill(id, ...nodes) {
  const target = document.getElementById(id);
  target.replaceChildren(...nodes);
}

// --- tooltip --------------------------------------------------------------------

const tooltip = document.getElementById("tooltip");

function showTooltip(event, title, rows) {
  tooltip.replaceChildren(
    el("strong", { text: title }),
    ...rows.map(([color, label, value]) =>
      el("div", { class: "row" }, color ? el("span", { class: "swatch", background: color }) : null, el("span", { text: `${label}: ${value}` })),
    ),
  );
  tooltip.hidden = false;
  const x = Math.min(event.clientX + 14, window.innerWidth - tooltip.offsetWidth - 8);
  const y = Math.min(event.clientY + 14, window.innerHeight - tooltip.offsetHeight - 8);
  tooltip.style.left = `${Math.max(8, x)}px`;
  tooltip.style.top = `${Math.max(8, y)}px`;
}

const hideTooltip = () => (tooltip.hidden = true);

// --- charts ---------------------------------------------------------------------

function legend(items) {
  return el(
    "ul",
    { class: "legend" },
    ...items.map(({ label, color, line }) =>
      el("li", {}, el("span", { class: `key${line ? " line" : ""}`, background: color }), el("span", { text: label })),
    ),
  );
}

// Coverage (y) by monthly budget (x, log scale), one line per strategy.
function coverageChart(target, rows) {
  const shown = ["priority", "epss", "cvss", "random"];
  const budgets = [...new Set(rows.map((r) => r.budget))].sort((a, b) => a - b);
  const series = shown.map((key) => ({
    key,
    ...STRATEGIES[key],
    color: cssVar(STRATEGIES[key].color),
    points: budgets.map((b) => rows.find((r) => r.strategy === key && r.budget === b)),
  }));

  const W = chartWidth(target), H = W < 480 ? 300 : 340, m = { top: 12, right: W < 480 ? 104 : 128, bottom: 40, left: 44 };
  const iw = W - m.left - m.right, ih = H - m.top - m.bottom;
  const lx = (b) => Math.log10(b);
  const x0 = lx(budgets[0]), x1 = lx(budgets[budgets.length - 1]);
  const yMax = Math.min(1, Math.ceil(Math.max(...rows.filter((r) => shown.includes(r.strategy)).map((r) => r.coverage)) * 10) / 10);
  const x = (b) => m.left + ((lx(b) - x0) / (x1 - x0)) * iw;
  const y = (v) => m.top + ih - (v / yMax) * ih;

  const root = svg("svg", { viewBox: `0 0 ${W} ${H}` });
  const grid = svg("g", { class: "grid" });
  for (let v = 0; v <= yMax + 1e-9; v += 0.1) {
    grid.append(svg("line", { x1: m.left, x2: m.left + iw, y1: y(v), y2: y(v) }));
    grid.append(svg("text", { x: m.left - 8, y: y(v) + 4, "text-anchor": "end" }, `${Math.round(v * 100)}%`));
  }
  root.append(grid);
  root.append(svg("line", { class: "baseline", x1: m.left, x2: m.left + iw, y1: y(0), y2: y(0) }));
  const ticks = W < 480 ? [100, 1000, 10000, 50000] : [100, 500, 1000, 5000, 10000, 50000];
  for (const b of budgets.filter((b) => ticks.includes(b))) {
    root.append(svg("text", { x: x(b), y: H - m.bottom + 18, "text-anchor": "middle" }, int.format(b)));
  }
  root.append(svg("text", { x: m.left + iw / 2, y: H - 4, "text-anchor": "middle" }, "CVEs patched per month (log scale)"));

  // Lines, end labels in text colour with a short colour key beside them.
  const labelYs = [];
  for (const s of series) {
    const d = s.points.map((p, i) => `${i ? "L" : "M"}${x(p.budget).toFixed(1)},${y(p.coverage).toFixed(1)}`).join("");
    root.append(svg("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-dasharray": s.dashed ? "5 4" : "none" }));
    for (const p of s.points) {
      root.append(svg("circle", { cx: x(p.budget), cy: y(p.coverage), r: 4, fill: s.color, stroke: cssVar("--surface"), "stroke-width": 2 }));
    }
    const last = s.points[s.points.length - 1];
    labelYs.push({ s, y: y(last.coverage) });
  }
  // Spread end labels so they never overlap.
  labelYs.sort((a, b) => a.y - b.y);
  for (let i = 1; i < labelYs.length; i++) labelYs[i].y = Math.max(labelYs[i].y, labelYs[i - 1].y + 16);
  for (const { s, y: ly } of labelYs) {
    root.append(svg("line", { x1: m.left + iw + 10, x2: m.left + iw + 22, y1: ly, y2: ly, stroke: s.color, "stroke-width": 3, "stroke-linecap": "round" }));
    root.append(svg("text", { class: "label", x: m.left + iw + 28, y: ly + 4 }, s.label));
  }

  // Hover: snap to the nearest budget and list every strategy there.
  const cross = svg("line", { class: "crosshair", y1: m.top, y2: m.top + ih, visibility: "hidden" });
  root.append(cross);
  const hit = svg("rect", { x: m.left, y: m.top, width: iw, height: ih, fill: "transparent" });
  hit.addEventListener("pointermove", (event) => {
    const box = root.getBoundingClientRect();
    const px = ((event.clientX - box.left) / box.width) * W;
    const nearest = budgets.reduce((a, b) => (Math.abs(x(b) - px) < Math.abs(x(a) - px) ? b : a));
    cross.setAttribute("x1", x(nearest));
    cross.setAttribute("x2", x(nearest));
    cross.setAttribute("visibility", "visible");
    const share = rows.find((r) => r.budget === nearest).budget_share;
    showTooltip(event, `${int.format(nearest)} CVEs a month (${pct(share, 2)} of open CVEs)`,
      series.map((s) => [s.color, s.label, pct(s.points.find((p) => p.budget === nearest).coverage)]));
  });
  hit.addEventListener("pointerleave", () => { cross.setAttribute("visibility", "hidden"); hideTooltip(); });
  root.append(hit);

  target.replaceChildren(legend(series.map((s) => ({ label: s.label, color: s.color, line: true }))), root);
}

// Share of each year's CVEs by source of their CVSS v3 score, stacked to 100%.
function sourcesChart(target, rows) {
  const parts = [
    { key: "nvd", label: "NVD", color: cssVar("--series-1") },
    { key: "cna", label: "The CNA (often the vendor)", color: cssVar("--series-2") },
    { key: "other", label: "Others (e.g. CISA)", color: cssVar("--series-3") },
    { key: "none", label: "No v3 score", color: cssVar("--none") },
  ];
  const W = chartWidth(target), H = 280, m = { top: 8, right: 8, bottom: 30, left: 44 };
  const iw = W - m.left - m.right, ih = H - m.top - m.bottom;
  const band = iw / rows.length, bw = Math.min(46, band * 0.62);
  const y = (v) => m.top + ih - v * ih;

  const root = svg("svg", { viewBox: `0 0 ${W} ${H}` });
  for (const v of [0, 0.25, 0.5, 0.75, 1]) {
    root.append(svg("line", { class: "grid", x1: m.left, x2: m.left + iw, y1: y(v), y2: y(v), stroke: cssVar("--grid") }));
    root.append(svg("text", { x: m.left - 8, y: y(v) + 4, "text-anchor": "end" }, `${v * 100}%`));
  }
  rows.forEach((row, i) => {
    const cx = m.left + band * i + band / 2;
    const g = svg("g");
    let acc = 0;
    // Normalise: rounding can leave the four shares a hair off 100%.
    const total = parts.reduce((t, p) => t + (row[p.key] || 0), 0) || 1;
    for (const p of parts) {
      const share = (row[p.key] || 0) / total;
      if (share <= 0) continue;
      const top = y(acc + share), bottom = y(acc);
      const h = Math.max(0, bottom - top - 2); // 2px surface gap between segments
      g.append(svg("rect", { x: cx - bw / 2, y: top + 1, width: bw, height: h, rx: 2, fill: p.color }));
      acc += share;
    }
    const label = W < 480 ? `'${String(row.year).slice(2)}` : String(row.year);
    root.append(svg("text", { x: cx, y: H - 10, "text-anchor": "middle" }, label));
    const hit = svg("rect", { x: cx - band / 2, y: m.top, width: band, height: ih, fill: "transparent" });
    hit.addEventListener("pointermove", (event) =>
      showTooltip(event, `${row.year}: ${int.format(row.cves)} CVEs`, parts.map((p) => [p.color, p.label, pct(row[p.key], 0)])));
    hit.addEventListener("pointerleave", hideTooltip);
    g.append(hit);
    root.append(g);
  });
  target.replaceChildren(legend(parts), root);
}

// --- sections -------------------------------------------------------------------

function renderStatus(status) {
  fill("updated", document.createTextNode(
    `Data as of ${day(status.updated_at)}. ${int.format(status.cves)} published CVEs; KEV catalog ${status.kev_version} ` +
    `(${int.format(status.kev)} CVEs); EPSS scores of ${status.epss_date}; NVD changes through ${day(status.nvd_covered_until)}.`,
  ));
}

function renderBacktest(coverage, periods, reach) {
  if (!coverage.length) {
    fill("backtest-summary", document.createTextNode("The backtest has not run yet."));
    return;
  }
  const at = (strategy, budget) => coverage.find((r) => r.strategy === strategy && r.budget === budget);
  const share = at("priority", 1000).budget_share;
  fill("backtest-summary",
    document.createTextNode("Patching the 1,000 highest-CVSS CVEs each month would have caught "),
    el("strong", { class: "figure", text: pct(at("cvss", 1000).coverage) }),
    document.createTextNode(" of the vulnerabilities exploited the following month, barely better than picking at random. EPSS alone catches "),
    el("strong", { class: "figure", text: pct(at("epss", 1000).coverage) }),
    document.createTextNode(", and this ranking "),
    el("strong", { class: "figure", text: pct(at("priority", 1000).coverage) }),
    document.createTextNode(`, for the same effort: ${pct(share, 2)} of the open CVEs.`),
  );
  const first = coverage[0];
  fill("backtest-scope", document.createTextNode(`${first.cycles} monthly decisions, ${int.format(first.exploited)} later-exploited CVEs.`));
  const drawCoverage = () => coverageChart(document.getElementById("coverage-chart"), coverage);
  drawCoverage();
  redraws.push(drawCoverage);

  const budgets = [100, 500, 1000, 5000, 10000].filter((b) => at("priority", b));
  const strategies = Object.keys(STRATEGIES).filter((s) => at(s, 1000));
  fill("coverage-table", table(
    [{ label: "Strategy", value: (r) => STRATEGIES[r.s].label },
      ...budgets.map((b) => ({ label: `${int.format(b)} a month`, class: "num", value: (r) => pct(at(r.s, b).coverage) }))],
    strategies.map((s) => ({ s, _class: s === "priority" ? "ours" : "" })),
    "Share of next-month exploitation caught, by monthly budget",
  ));

  const periodNames = [...new Set(periods.map((p) => p.period))].sort(
    (a, b) => Number(b.startsWith("before")) - Number(a.startsWith("before")),
  );
  const inPeriod = (s, p) => periods.find((r) => r.strategy === s && r.period === p);
  fill("period-table", table(
    [{ label: "Strategy, 1,000 a month", value: (r) => STRATEGIES[r.s].label },
      ...periodNames.map((p) => ({ label: `${p} (${inPeriod("priority", p).exploited} exploited)`, class: "num", value: (r) => pct(inPeriod(r.s, p)?.coverage) }))],
    strategies.map((s) => ({ s, _class: s === "priority" ? "ours" : "" })),
    "The same, before and after 2025",
  ));

  const reachable = reach.find((r) => r.reach === "rankable")?.kev_additions || 0;
  const later = reach.find((r) => r.reach === "published after the decision date")?.kev_additions || 0;
  if (reachable + later) {
    fill("reach-note", document.createTextNode(
      `Besides those, ${int.format(later)} CVEs added to KEV in the same windows (${pct(later / (reachable + later), 0)}) ` +
      "were published after the decision date: a monthly patching cycle never sees them in time.",
    ));
  }
}

const PRIORITY_COLUMNS = [
  { label: "Rank", class: "num", value: (r) => int.format(r.priority_rank) },
  { label: "CVE", class: "cve", value: (r) => cveLink(r.cve_id) },
  { label: "Product", value: productName },
  {
    label: "Fix within",
    value: (r) => r.remediation.replace(" & forensic investigation", " + forensics"),
    class: (r) => `nowrap${r.remediation.startsWith("3 days") ? " urgent" : ""}`,
  },
  { label: "SSVC", value: (r) => r.ssvc_decision },
  { label: "Why", class: "why", value: (r) => r.priority_reason },
];

function renderPriorities(lists) {
  const show = (name) => {
    fill("priority-table", table(PRIORITY_COLUMNS, lists[name].slice(0, 25)));
    for (const button of document.querySelectorAll("[data-list]")) {
      button.setAttribute("aria-pressed", String(button.dataset.list === name));
    }
  };
  for (const button of document.querySelectorAll("[data-list]")) {
    button.addEventListener("click", () => show(button.dataset.list));
  }
  show("priorities");
}

function renderRecent(rows) {
  if (!rows.length) return;
  const highEpss = rows.filter((r) => (r.epss_percentile ?? 0) >= 0.9).length;
  fill("recent-summary", document.createTextNode(
    `${rows.length} CVEs entered CISA's catalog of exploited vulnerabilities in its last 60 days. ` +
    `${highEpss} of them sit in the top 10% of EPSS today.`,
  ));
  fill("recent-table", table(
    [
      { label: "Added", value: (r) => day(r.kev_date_added) },
      { label: "CVE", class: "cve", value: (r) => cveLink(r.cve_id) },
      { label: "Product", value: productName },
      { label: "Published", value: (r) => day(r.published) },
      { label: "CVSS", class: "num", value: (r) => (r.cvss_score == null ? "–" : r.cvss_score.toFixed(1)) },
      { label: "EPSS percentile", class: "num", value: (r) => pct(r.epss_percentile) },
      { label: "Ransomware", value: (r) => (r.kev_ransomware ? "known use" : "") },
    ],
    rows.slice(0, 30),
  ));
}

function renderSources(rows) {
  if (!rows.length) return;
  const latest = rows[rows.length - 1];
  const peak = rows.reduce((a, b) => (b.nvd > a.nvd ? b : a));
  fill("severity-summary", document.createTextNode(
    `In ${peak.year}, NVD's own analysts scored ${pct(peak.nvd, 0)} of new CVEs. In ${latest.year} they scored ` +
    `${pct(latest.nvd, 0)}; most scores now come from the vendor or project that published the CVE.`,
  ));
  const drawSources = () => sourcesChart(document.getElementById("sources-chart"), rows);
  drawSources();
  redraws.push(drawSources);
}

function renderAssets(assets, upgrades) {
  if (!assets.length) return;
  fill("assets-table", table(
    [
      { label: "System", value: (r) => r.asset },
      { label: "Internet-facing", value: (r) => r.publicly_exposed },
      { label: "Mission impact", value: (r) => r.mission_impact },
      { label: "Packages", class: "num", value: (r) => int.format(r.packages) },
      { label: "Vulnerable", class: "num", value: (r) => int.format(r.vulnerable_packages) },
      { label: "Flaws", class: "num", value: (r) => int.format(r.findings) },
      { label: "Fix within", value: (r) => (r.findings ? `${r.shortest_deadline_days} days` : "–") },
    ],
    assets,
  ));

  const byAsset = Map.groupBy ? Map.groupBy(upgrades, (u) => u.asset) : upgrades.reduce((m, u) => m.set(u.asset, [...(m.get(u.asset) || []), u]), new Map());
  const blocks = [];
  for (const [asset, items] of byAsset) {
    blocks.push(el("div", { class: "upgrade" },
      el("h3", { text: `${asset}: upgrades, most urgent first` }),
      el("ol", {}, ...items.map((u) =>
        el("li", {},
          el("span", { text: `${u.package} ${u.version} → ${u.upgrade_to || "no fixed version yet"}` }),
          el("div", { class: "detail", text:
            `${u.vulnerabilities} known ${u.vulnerabilities === 1 ? "flaw" : "flaws"}` +
            `${u.without_fix ? ` (${u.without_fix} without a fix)` : ""}` +
            `${u.is_direct ? "" : "; comes with another package"}; ${u.ssvc_decision}, ${u.deadline_days ? `within ${u.deadline_days} days` : "at the next upgrade"}; worst: ${u.most_urgent}` }),
        ))),
    ));
  }
  fill("upgrades", ...blocks);
}

async function main() {
  try {
    const [status, priorities, notYet, recent, coverage, periods, reach, sources, assets, upgrades] = await Promise.all(
      ["status", "priorities", "not_yet_exploited", "recent_kev", "backtest_coverage", "backtest_by_period", "backtest_reach",
        "cvss_sources", "assets", "upgrades"].map(load),
    );
    renderStatus(status);
    renderBacktest(coverage, periods, reach);
    renderPriorities({ priorities, not_yet_exploited: notYet });
    renderRecent(recent);
    renderSources(sources);
    renderAssets(assets, upgrades);
  } catch (error) {
    fill("updated", document.createTextNode(`The data could not be loaded (${error.message}).`));
  }
}

main();
