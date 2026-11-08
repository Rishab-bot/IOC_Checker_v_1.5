"use strict";

// Everything that comes from the server, an alert, AbuseIPDB or Gemini is placed with textContent,
// never innerHTML, so none of it can inject HTML or scripts into the page.

const state = {
  mode: "unknown",
  token: "",
  model: "",
  maxIps: 50,
  checkId: "",
  source: "",
  results: [],
  skipped: [],
  cut: 0,
  selected: null,
  insights: new Map(),   // "checkId|ip" -> deep analysis reply, kept for this page session
  pending: new Map(),    // "checkId|ip" -> true while a deep analysis is running
  failures: new Map(),   // "checkId|ip" -> error message from a failed deep analysis
};

const MAX_FILE_BYTES = 95 * 1024; // the server accepts 100 KB per request, including JSON overhead

const VERDICTS = {
  malicious: { label: "Malicious", icon: "i-octagon-x" },
  suspicious: { label: "Suspicious", icon: "i-triangle" },
  benign: { label: "Benign", icon: "i-shield-check" },
};

const ASSESSMENTS = {
  likely_malicious: { label: "Likely malicious", cls: "malicious", icon: "i-octagon-x" },
  suspicious: { label: "Suspicious", cls: "suspicious", icon: "i-triangle" },
  likely_benign: { label: "Likely benign", cls: "benign", icon: "i-shield-check" },
  inconclusive: { label: "Inconclusive", cls: "failed", icon: "i-slash" },
};

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;

const SAMPLES = {
  sentinel: {
    name: "Sentinel JSON example",
    text: JSON.stringify({
      source: "Microsoft Sentinel",
      alert_name: "Suspicious Network Communication",
      severity: "High",
      device: { hostname: "WS-FINANCE-024", private_ip: "192.168.10.24" },
      network_events: [
        { event_type: "C2 Communication", src_ip: "192.168.10.24", dest_ip: "185.220.101.5", dest_port: 443, protocol: "TCP", action: "Allowed", bytes_sent: 45231 },
        { event_type: "Malware Callback", src_ip: "192.168.10.24", dest_ip: "45.33.32.156", dest_port: 8080, protocol: "TCP", action: "Blocked" },
        { event_type: "Suspicious DNS Resolution", src_ip: "192.168.10.24", dest_ip: "91.219.236.222", dest_port: 53, protocol: "UDP", action: "Allowed" },
        { event_type: "Unusual External Connection", src_ip: "192.168.10.24", dest_ip: "103.86.96.100", dest_port: 443, protocol: "TCP", action: "Allowed" },
        { event_type: "Normal Web Browsing", src_ip: "192.168.10.24", dest_ip: "8.8.8.8", dest_port: 443, protocol: "TCP", action: "Allowed" },
      ],
    }, null, 2),
  },
  splunk: {
    name: "Splunk event example",
    text: [
      { time: 1794105240, host: "fw-edge-02", sourcetype: "pan:traffic", event: { action: "allowed", app: "ssh", src_ip: "10.20.4.17", dest_ip: "185.83.17.202", dest_port: 22, bytes_out: 18233, user: "svc-backup" } },
      { time: 1794105301, host: "fw-edge-02", sourcetype: "pan:traffic", event: { action: "allowed", app: "ssh", src_ip: "10.20.4.17", dest_ip: "45.83.17.9", dest_port: 22, bytes_out: 9120, user: "svc-backup" } },
      { time: 1794105377, host: "fw-edge-02", sourcetype: "pan:threat", event: { action: "alert", threat: "Brute Force SSH", src_ip: "193.83.64.9", dest_ip: "10.20.4.17", dest_port: 22 } },
    ].map((line) => JSON.stringify(line)).join("\n"),
  },
  qradar: {
    name: "QRadar log example",
    text: [
      "LEEF:2.0|IBM|QRadar|7.5|AuthenticationFailure|devTime=Nov 07 2026 02:14:31|src=91.83.17.141|dst=10.10.0.4|usrName=a.khan|proto=TCP|dstPort=443|sev=6",
      "LEEF:2.0|IBM|QRadar|7.5|AuthenticationFailure|devTime=Nov 07 2026 02:15:02|src=185.83.17.202|dst=10.10.0.4|usrName=a.khan|proto=TCP|dstPort=443|sev=6",
      "LEEF:2.0|IBM|QRadar|7.5|DNSQuery|devTime=Nov 07 2026 02:16:40|src=10.10.0.4|dst=1.1.1.1|proto=UDP|dstPort=53|sev=1",
    ].join("\n"),
  },
  firewall: {
    name: "Firewall log example",
    text: [
      "Nov  7 02:20:11 edge-fw kernel: DROP IN=eth0 SRC=52.0.0.13 DST=10.0.0.9 PROTO=TCP SPT=51544 DPT=3389",
      "Nov  7 02:20:14 edge-fw kernel: DROP IN=eth0 SRC=103.27.202.85 DST=10.0.0.9 PROTO=TCP SPT=40112 DPT=22",
      "Nov  7 02:20:19 edge-fw kernel: ACCEPT IN=eth0 SRC=141.98.10.42 DST=10.0.0.9 PROTO=TCP SPT=33051 DPT=443",
      "Nov  7 02:20:23 edge-fw kernel: DROP IN=eth0 SRC=77.83.36.66 DST=10.0.0.9 PROTO=UDP SPT=5060 DPT=5060",
      "Nov  7 02:20:30 edge-fw kernel: ACCEPT IN=eth1 SRC=192.168.1.20 DST=224.0.0.251 PROTO=UDP DPT=5353",
      "Nov  7 02:20:41 edge-fw kernel: parse warning: bad address 999.12.5.1 in rule 14",
    ].join("\n"),
  },
};

const $ = (id) => document.getElementById(id);

/** Create an element with an optional class and text. */
function make(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

/** Create an inline SVG icon that points at a symbol in the page's sprite. */
function icon(id, className = "icon") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#${id}`);
  svg.append(use);
  return svg;
}

/** Start a message with a capital letter. */
function capitalise(text) {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

/** Return the key under which a deep analysis for this IP in the current check is stored. */
function insightKey(ip) {
  return `${state.checkId}|${ip}`;
}

/** Link to the IP's page on AbuseIPDB. */
function abuseUrl(ip) {
  return `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
}

/** Build an external link icon to AbuseIPDB that does not trigger the row it sits in. */
function abuseLink(ip) {
  const link = make("a", "icon-link");
  link.href = abuseUrl(ip);
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.title = "Open on AbuseIPDB";
  link.append(icon("i-external"), make("span", "visually-hidden", `Open ${ip} on AbuseIPDB`));
  link.addEventListener("click", (event) => event.stopPropagation());
  return link;
}

/** Build a verdict chip from a check result: icon, word and colour together. */
function verdictChip(result, large = false) {
  const size = large ? " lg" : "";
  if (result.error) {
    const chip = make("span", `verdict v-failed${size}`);
    chip.append(icon("i-slash"), document.createTextNode("Failed"));
    return chip;
  }
  const info = VERDICTS[result.verdict] || { label: result.verdict, icon: "i-slash" };
  const chip = make("span", `verdict v-${result.verdict}${size}`);
  chip.append(icon(info.icon), document.createTextNode(info.label));
  return chip;
}

/** Build an assessment chip (likely malicious, suspicious, likely benign or inconclusive). */
function assessmentChip(value, large = false) {
  const info = ASSESSMENTS[value] || { label: value, cls: "failed", icon: "i-slash" };
  const chip = make("span", `verdict v-${info.cls}${large ? " lg" : ""}`);
  chip.append(icon(info.icon), document.createTextNode(info.label));
  return chip;
}

/** Return the CSS class that colours an AbuseIPDB score. */
function scoreClass(score) {
  if (typeof score !== "number") return "na";
  if (score >= 75) return "hi";
  if (score >= 25) return "mid";
  return "lo";
}

/** Format an ISO time as a short local date and time. */
function shortTime(iso) {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Turn true/false/null into "Yes", "No" or "Unknown". */
function yesNo(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "Unknown";
}

/** Add one label and value to a facts list, skipping empty values. */
function addFact(list, label, value, className) {
  if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) return;
  list.append(make("dt", null, label), make("dd", className, Array.isArray(value) ? value.join(", ") : String(value)));
}

/** Label for AI-written content: "AI · verify", or "Demo data" in demo mode. */
function aiTag() {
  return state.mode === "demo" ? make("span", "ai-tag demo", "Demo data") : make("span", "ai-tag", "AI · verify");
}

/** Return the check result for an IP. */
function resultFor(ip) {
  return state.results.find((result) => result.ip === ip) || null;
}

// ---------------------------------------------------------------- status

/** Ask the server for its mode and session token, and show demo or live clearly in the top bar. */
async function loadStatus() {
  try {
    const response = await fetch("/status");
    const data = await response.json();
    state.mode = data.mode === "live" ? "live" : "demo";
    state.token = data.insight_token || "";
    state.model = data.insight_model || "";
    state.maxIps = data.max_ips || 50;
  } catch {
    state.mode = "offline";
  }

  const mode = $("mode");
  mode.dataset.mode = state.mode;
  const label = (name, detail) => $("mode-label").replaceChildren(make("span", "mode-name", name), make("span", "mode-detail", ` · ${detail}`));
  if (state.mode === "live") {
    label("Live mode", "uses your API quota");
    mode.title = `Real AbuseIPDB and Gemini (${state.model}) calls`;
    $("cost-note").textContent = "Each public IP uses 1 AbuseIPDB lookup and 1 Gemini call";
  } else if (state.mode === "demo") {
    label("Demo mode", "made-up results");
    mode.title = "Nothing is sent to AbuseIPDB or Gemini";
    $("cost-note").textContent = "Demo mode: nothing is sent to AbuseIPDB or Gemini";
  } else {
    label("Offline", "start web_app.py");
    $("cost-note").textContent = "The IOC Checker server is not reachable";
  }
}

// ---------------------------------------------------------------- start screen: input tabs, upload, examples

/** Switch between the Paste payload and Upload file tabs. */
function showInputTab(name, focus = true) {
  for (const tab of ["paste", "upload"]) {
    const selected = tab === name;
    const button = $(`itab-${tab}`);
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
    $(`ipane-${tab}`).hidden = !selected;
    if (selected && focus) button.focus();
  }
}

/** Show or clear the error line under the alert box. */
function setFormError(message) {
  const line = $("form-error");
  line.textContent = message || "";
  line.hidden = !message;
}

/** Show which file or example filled the payload box. */
function setLoadedNote(text) {
  const note = $("loaded-note");
  if (!text) {
    note.hidden = true;
    return;
  }
  note.replaceChildren(icon("i-check"), document.createTextNode(text));
  note.hidden = false;
}

/** Read one dropped or chosen file as text into the payload box, refusing large or binary files. */
function readFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    setFormError(`${file.name} is ${Math.ceil(file.size / 1024)} KB; the limit is 95 KB. Paste just the relevant part of it instead.`);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || "");
    if (text.includes("\u0000")) {
      setFormError(`${file.name} does not look like a text file. Upload a .txt, .log, .json, .csv or .xml file.`);
      return;
    }
    $("payload").value = text;
    state.source = file.name;
    setFormError("");
    setLoadedNote(`Loaded ${file.name} (${Math.max(1, Math.round(file.size / 1024))} KB). Check it, then press Analyze.`);
    showInputTab("paste", false);
    $("payload").focus();
  };
  reader.onerror = () => setFormError(`Could not read ${file.name}.`);
  reader.readAsText(file);
}

// ---------------------------------------------------------------- check

/** Send the alert to the server, then show the results view. */
async function runCheck(event) {
  event.preventDefault();
  const text = $("payload").value.trim();
  if (!text) {
    setFormError("Paste an alert, upload a file or load an example first.");
    showInputTab("paste", false);
    $("payload").focus();
    return;
  }

  const button = $("analyze");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.querySelector("span").textContent = "Analyzing…";
  setFormError("");
  const started = performance.now();

  try {
    const response = await fetch("/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);

    state.checkId = data.check_id || "";
    state.results = data.results || [];
    state.skipped = data.skipped || [];
    state.cut = data.cut || 0;
    state.selected = state.results.length ? state.results[0].ip : null;
    state.insights.clear();
    state.pending.clear();
    state.failures.clear();
    state.seconds = (performance.now() - started) / 1000;
    state.counts = data.counts || { checked: state.results.length };
    if (!state.source) state.source = "Pasted alert";
    if (location.hash === "#/results") route();
    else location.hash = "#/results";
  } catch (err) {
    setFormError(`Check failed: ${err.message}. Is web_app.py still running?`);
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.querySelector("span").textContent = "Analyze";
  }
}

// ---------------------------------------------------------------- results view

/** Draw the whole results view: summary, table, skipped list and the triage panel. */
function renderResults() {
  const checked = state.counts ? state.counts.checked : state.results.length;
  $("results-source").textContent = `${state.source} · ${checked} public IP${checked === 1 ? "" : "s"} checked`;
  renderSummary();

  const body = $("results-body");
  body.replaceChildren();
  if (!state.results.length) {
    $("results-table").hidden = true;
    const empty = $("results-empty");
    empty.replaceChildren(
      make("p", "empty-title", "No public IPv4 addresses to check"),
      make("p", null, "Everything this alert mentioned was private, reserved or invalid, so nothing was sent to AbuseIPDB or Gemini. The skipped list below says why."),
    );
    empty.hidden = false;
  } else {
    $("results-table").hidden = false;
    $("results-empty").hidden = true;
    for (const result of state.results) body.append(resultRow(result));
  }
  $("results-hint").hidden = state.results.length < 2;
  renderSkipped();
  markSelection(false);
  renderPanel(false);
}

/** Show how the check went: counts by verdict, failures, skipped and cut addresses, and the time taken. */
function renderSummary() {
  const summary = $("summary");
  summary.replaceChildren();
  const counts = { malicious: 0, suspicious: 0, benign: 0, failed: 0 };
  for (const result of state.results) {
    if (result.error) counts.failed += 1;
    else if (counts[result.verdict] !== undefined) counts[result.verdict] += 1;
  }

  const checked = state.counts ? state.counts.checked : state.results.length;
  const seconds = state.seconds || 0;
  const extras = [`${state.skipped.length} skipped`];
  if (state.cut) extras.push(`${state.cut} over the ${state.maxIps}-IP limit`);

  const main = make("div", "summary-main");
  const mark = make("span", "summary-mark");
  mark.append(icon("i-check"));
  const text = make("div");
  text.append(
    make("p", "summary-title", checked ? "Analysis complete" : "No public IPs found"),
    make("p", "summary-sub", `${checked} checked in ${seconds < 0.1 ? "under 0.1" : seconds.toFixed(1)} s · ${extras.join(" · ")}`),
  );
  main.append(mark, text);

  const tally = make("ul", "tally");
  const items = [
    ["t-mal", "i-octagon-x", counts.malicious, "Malicious"],
    ["t-sus", "i-triangle", counts.suspicious, "Suspicious"],
    ["t-ben", "i-shield-check", counts.benign, "Benign"],
  ];
  if (counts.failed) items.push(["t-fail", "i-slash", counts.failed, "Failed"]);
  for (const [cls, iconId, count, label] of items) {
    const item = make("li", count ? cls : `${cls} zero`);
    item.append(icon(iconId), make("strong", null, String(count)), make("span", null, label));
    tally.append(item);
  }
  summary.append(main, tally);
}

/** Build one table row; the whole row selects the IP. */
function resultRow(result) {
  const row = make("tr");
  row.tabIndex = -1;
  row.dataset.ip = result.ip;
  row.setAttribute("aria-selected", "false");

  const ipCell = make("td");
  const ipWrap = make("div", "ip-cell");
  ipWrap.append(make("span", "ip", result.ip), abuseLink(result.ip));
  ipCell.append(ipWrap);

  const verdictCell = make("td");
  verdictCell.append(verdictChip(result));
  if (!result.error && result.severity) verdictCell.append(make("span", "severity", result.severity));

  const scoreCell = make("td", "num");
  scoreCell.append(make("span", `score ${scoreClass(result.score)}`, typeof result.score === "number" ? String(result.score) : "—"));

  const networkCell = make("td", "c-network");
  networkCell.append(make("span", "clip", [result.isp, result.country].filter(Boolean).join(" · ") || "—"));

  const summaryCell = make("td", "c-summary");
  const text = result.error || result.reason || "";
  const clip = make("span", "clip", text);
  clip.title = text;
  summaryCell.append(clip);

  const goCell = make("td", "c-go");
  goCell.append(icon("i-chevron-right"));

  row.append(ipCell, verdictCell, scoreCell, networkCell, summaryCell, goCell);
  row.addEventListener("click", () => selectRow(result.ip, { focus: true, open: true }));
  row.addEventListener("dblclick", () => openInvestigation(result.ip));
  return row;
}

/** Show the addresses that were skipped and why, folded away by default. */
function renderSkipped() {
  const box = $("skipped");
  const list = $("skipped-list");
  list.replaceChildren();
  if (!state.skipped.length && !state.cut) {
    box.hidden = true;
    return;
  }
  const parts = [`${state.skipped.length} skipped`];
  if (state.cut) parts.push(`${state.cut} not checked (over the ${state.maxIps}-IP limit)`);
  $("skipped-summary").textContent = parts.join(" · ");
  for (const [ip, reason] of state.skipped) {
    const item = make("li");
    item.append(make("span", "ip", ip), make("span", null, reason));
    list.append(item);
  }
  box.hidden = false;
}

/** Mark the selected row and make it the one Tab lands on. */
function markSelection(focus) {
  for (const row of $("results-body").querySelectorAll("tr[data-ip]")) {
    const isSelected = row.dataset.ip === state.selected;
    row.setAttribute("aria-selected", String(isSelected));
    row.tabIndex = isSelected ? 0 : -1;
    if (isSelected && focus) row.focus();
  }
}

/** Select a result and show it in the triage panel; on narrow screens open the sheet if asked. */
function selectRow(ip, { focus = false, open = false } = {}) {
  state.selected = ip;
  markSelection(focus);
  renderPanel(true);
  if (open) openSheet();
}

/** Move between rows with the arrow keys; Enter opens the investigation for the focused row. */
function onTableKey(event) {
  const rows = [...$("results-body").querySelectorAll("tr[data-ip]")];
  if (!rows.length) return;
  const index = rows.indexOf(document.activeElement);
  let next = null;
  if (event.key === "ArrowDown") next = rows[Math.min(index + 1, rows.length - 1)] || rows[0];
  else if (event.key === "ArrowUp") next = rows[Math.max(index - 1, 0)] || rows[0];
  else if (event.key === "Home") next = rows[0];
  else if (event.key === "End") next = rows[rows.length - 1];
  else if (event.key === "Enter" && index >= 0) {
    event.preventDefault();
    openInvestigation(rows[index].dataset.ip);
    return;
  } else if (event.key === " " && index >= 0) {
    event.preventDefault();
    selectRow(rows[index].dataset.ip, { focus: true, open: true });
    return;
  } else {
    return;
  }
  event.preventDefault();
  selectRow(next.dataset.ip, { focus: true });
}

/** True when the triage panel is shown as a sheet over the page (narrow screens). */
function isSheet() {
  return window.matchMedia("(max-width: 1100px)").matches;
}

/** Open the triage sheet on narrow screens and move focus into it. */
function openSheet() {
  if (!isSheet() || !state.selected) return;
  $("panel").classList.add("open");
  $("scrim").hidden = false;
  const close = $("panel").querySelector(".panel-close");
  if (close) close.focus();
}

/** Close the triage sheet and return focus to the selected row. */
function closeSheet() {
  if (!$("panel").classList.contains("open")) return;
  $("panel").classList.remove("open");
  $("scrim").hidden = true;
  const row = $("results-body").querySelector('tr[aria-selected="true"]');
  if (row) row.focus();
}

/** Draw the quick-triage panel: verdict, key facts, and the way into the full investigation. */
function renderPanel(animate) {
  const result = resultFor(state.selected);
  $("panel-empty").hidden = Boolean(result);
  const detail = $("panel-detail");
  detail.hidden = !result;
  detail.replaceChildren();
  if (!result) return;

  const insight = state.insights.get(insightKey(result.ip));

  const head = make("header", "panel-head");
  const titleRow = make("div", "panel-title-row");
  const close = make("button", "icon-btn panel-close");
  close.type = "button";
  close.title = "Close";
  close.append(icon("i-x"), make("span", "visually-hidden", "Close"));
  close.addEventListener("click", closeSheet);
  titleRow.append(make("h2", "panel-ip", result.ip), abuseLink(result.ip), close);
  const chips = make("div", "chip-row");
  chips.append(verdictChip(result));
  if (!result.error && result.severity) chips.append(make("span", "severity", `${result.severity} severity`));
  head.append(titleRow, make("p", "panel-sub", [result.isp, result.country].filter(Boolean).join(" · ") || (result.error ? "No AbuseIPDB data" : "Network unknown")), chips);

  const body = make("div", "panel-body");

  const verdictBlock = make("section", "block");
  const vTitle = make("h3", "block-title");
  vTitle.append(icon("i-shield"), document.createTextNode("Verdict"));
  if (!result.error) vTitle.append(aiTag());
  verdictBlock.append(vTitle, make("p", result.error ? "error-text" : "prose", result.error ? capitalise(result.error) : result.reason));
  body.append(verdictBlock);

  const facts = make("dl", "facts");
  addFact(facts, "Abuse confidence", typeof result.score === "number" ? `${result.score}%` : null);
  addFact(facts, "Reports (90 days)", result.reports);
  addFact(facts, "Last reported", shortTime(result.last_reported));
  if (typeof result.whitelisted === "boolean") addFact(facts, "Whitelisted", yesNo(result.whitelisted), result.whitelisted ? "ok" : "no");
  if (facts.childElementCount) body.append(facts);

  if (insight && insight.assessment && !insight.assessment.error) {
    const snippet = make("section", "snippet");
    const sTitle = make("h3", "block-title");
    sTitle.append(icon("i-spark"), document.createTextNode("Analyst assessment"), aiTag());
    const row = make("div", "chip-row");
    row.append(assessmentChip(insight.assessment.assessment), make("span", "severity", `${insight.assessment.confidence} confidence`));
    snippet.append(sTitle, row, make("p", "prose", insight.assessment.summary));
    body.append(snippet);
  }

  const cta = make("div", "cta");
  const open = make("button", "btn btn-primary");
  open.type = "button";
  open.append(icon("i-target"), document.createTextNode(insight ? "Open investigation" : "Investigate"), icon("i-arrow-right"));
  open.addEventListener("click", () => openInvestigation(result.ip));
  cta.append(open, make("p", "cta-note", insight
    ? "Deep analysis done for this IP; reopening it is free"
    : "Opens a full page for this IP. The deep analysis runs only when you start it there."));
  body.append(cta);

  detail.append(head, body);
  if (animate) {
    detail.classList.remove("settle");
    void detail.offsetWidth;
    detail.classList.add("settle");
  }
}

// ---------------------------------------------------------------- investigation view

/** Go to the full investigation page for one IP. */
function openInvestigation(ip) {
  closeSheet();
  state.selected = ip;
  location.hash = `#/investigate/${encodeURIComponent(ip)}`;
}

/** Step to the previous or next IP in the sorted results. */
function stepInvestigation(delta) {
  const index = state.results.findIndex((result) => result.ip === state.selected);
  const next = state.results[index + delta];
  if (next) openInvestigation(next.ip);
}

/** Build a card with a title, an icon and an optional AI label. */
function card(title, iconId, withAiTag, extraClass = "") {
  const section = make("section", `card ${extraClass}`.trim());
  const heading = make("h2", "card-title");
  heading.append(icon(iconId), document.createTextNode(title));
  if (withAiTag) heading.append(aiTag());
  section.append(heading);
  return section;
}

/** Build the start, progress or retry control for a deep analysis of one IP. */
function deepControl(ip) {
  const key = insightKey(ip);
  const wrap = make("div", "deep");
  if (state.pending.get(key)) {
    for (const width of ["w100", "w80", "w100", "w60"]) wrap.append(make("span", `skel ${width}`));
    wrap.append(make("p", "fineprint", "Gemini is assessing this IP… this can take up to a minute."));
    return wrap;
  }
  wrap.append(make("p", "prose", "Gemini reads the full AbuseIPDB record and the parts of this alert that mention the IP, then gives an assessment with evidence, harmless explanations, MITRE ATT&CK techniques, recommended actions and hunting queries."));
  if (state.failures.has(key)) wrap.append(make("p", "deep-error", `Deep analysis failed: ${state.failures.get(key)}`));
  const button = make("button", "btn btn-primary btn-lg");
  button.type = "button";
  button.append(icon("i-spark"), document.createTextNode(state.failures.has(key) ? "Try deep analysis again" : "Run deep analysis"));
  button.addEventListener("click", () => runInsight(ip));
  wrap.append(button, make("p", "fineprint", state.mode === "live"
    ? "Uses 1 AbuseIPDB lookup and 1 Gemini call. The result is kept while this page is open."
    : "Demo mode: made-up result, no API calls."));
  return wrap;
}

/** Draw the investigation page for the selected IP. */
function renderInvestigation() {
  const result = resultFor(state.selected);
  const bodyEl = $("inv-body");
  bodyEl.replaceChildren();
  if (!result) return;

  const index = state.results.indexOf(result);
  $("crumb-ip").textContent = result.ip;
  $("inv-position").textContent = `${index + 1} of ${state.results.length}`;
  $("inv-prev").disabled = index <= 0;
  $("inv-next").disabled = index >= state.results.length - 1;
  document.title = `${result.ip} · IOC Checker`;

  const insight = state.insights.get(insightKey(result.ip));
  const details = insight && insight.details && !insight.details.error ? insight.details : null;
  const assessment = insight && insight.assessment && !insight.assessment.error ? insight.assessment : null;

  // Header: the IP, where it lives, the verdict and the headline numbers.
  const head = make("header", "inv-head");
  const id = make("div", "inv-id");
  const ipRow = make("div", "inv-ip-row");
  ipRow.append(make("h1", "inv-ip", result.ip));
  ipRow.firstChild.id = "inv-ip";
  ipRow.append(abuseLink(result.ip));
  const where = details
    ? [details.isp, details.usage_type, details.country_name].filter(Boolean)
    : [result.isp, result.country].filter(Boolean);
  const chips = make("div", "chip-row");
  chips.append(verdictChip(result, true));
  if (!result.error && result.severity) chips.append(make("span", "severity", `${result.severity} severity`));
  if (details && details.is_tor) chips.append(make("span", "tag tor", "Tor exit node"));
  if (assessment) chips.append(assessmentChip(assessment.assessment, true));
  id.append(ipRow, make("p", "inv-sub", where.join(" · ") || "Network unknown"), chips);

  const numbers = make("ul", "inv-numbers");
  const score = details ? details.score : result.score;
  const reports = details ? details.reports : result.reports;
  const addNumber = (value, label, cls) => {
    if (value === null || value === undefined) return;
    const item = make("li");
    item.append(make("strong", cls, String(value)), make("span", null, label));
    numbers.append(item);
  };
  addNumber(typeof score === "number" ? `${score}%` : null, "Abuse confidence", `score ${scoreClass(score)}`);
  addNumber(reports, "Reports in 90 days");
  if (details) addNumber(details.distinct_reporters, "Distinct reporters");
  head.append(id, numbers);
  bodyEl.append(head);

  // Grid: assessment on the left, reputation on the right.
  const grid = make("div", "inv-grid");

  const assess = card("Analyst assessment", "i-spark", Boolean(assessment), "inv-assessment");
  if (assessment) {
    const row = make("div", "chip-row");
    row.append(assessmentChip(assessment.assessment, true), make("span", "severity", `${assessment.confidence} confidence`));
    assess.append(row, make("p", "assess-summary", assessment.summary));

    const columns = make("div", "two-col");
    for (const [title, items] of [["Evidence", assessment.evidence], ["Could it be harmless?", assessment.benign_explanations]]) {
      const col = make("div", "block");
      col.append(make("p", "sub-title", title));
      if (items && items.length) {
        const list = make("ul", "list");
        for (const item of items) list.append(make("li", null, item));
        col.append(list);
      } else {
        col.append(make("p", "prose", "None given."));
      }
      columns.append(col);
    }
    assess.append(columns);

    if (assessment.attack_techniques && assessment.attack_techniques.length) {
      const block = make("div", "block");
      const list = make("ul", "chips");
      for (const technique of assessment.attack_techniques) {
        const item = make("li");
        if (TECHNIQUE_ID.test(technique.id)) {
          const link = make("a");
          link.href = `https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}/`;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.append(make("span", "mitre-id", technique.id), document.createTextNode(technique.name));
          item.append(link);
        } else {
          item.textContent = `${technique.id} · ${technique.name}`;
        }
        list.append(item);
      }
      block.append(make("p", "sub-title", "MITRE ATT&CK techniques"), list);
      assess.append(block);
    }

    const columns2 = make("div", "two-col");
    const actions = make("div", "block");
    actions.append(make("p", "sub-title", "Recommended actions"));
    const actionList = make("ol", "list actions");
    for (const action of assessment.recommended_actions || []) actionList.append(make("li", null, action));
    actions.append(actionList.childElementCount ? actionList : make("p", "prose", "None given."));
    const pivots = make("div", "block");
    pivots.append(make("p", "sub-title", "Look into next"));
    const pivotList = make("ul", "list");
    for (const pivot of assessment.pivots || []) pivotList.append(make("li", null, pivot));
    pivots.append(pivotList.childElementCount ? pivotList : make("p", "prose", "None given."));
    columns2.append(actions, pivots);
    assess.append(columns2);
  } else {
    if (insight && insight.assessment && insight.assessment.error) {
      assess.append(make("p", "error-text", capitalise(insight.assessment.error)));
    }
    assess.append(deepControl(result.ip));
  }
  grid.append(assess);

  const side = make("div", "inv-side");
  const rep = card("AbuseIPDB", "i-shield", false);
  if (insight && insight.details && insight.details.error) rep.append(make("p", "error-text", `Detailed lookup failed: ${insight.details.error}`));
  const facts = make("dl", "facts");
  if (details) {
    addFact(facts, "Last reported", shortTime(details.last_reported));
    addFact(facts, "ISP", details.isp);
    addFact(facts, "Usage type", details.usage_type);
    addFact(facts, "Domain", details.domain);
    addFact(facts, "Hostnames", details.hostnames);
    addFact(facts, "Country", details.country_name ? `${details.country_name} (${details.country})` : details.country);
    addFact(facts, "Tor exit node", yesNo(details.is_tor), details.is_tor ? "yes" : "no");
    addFact(facts, "Whitelisted", yesNo(details.whitelisted), details.whitelisted ? "ok" : "no");
    addFact(facts, "Checks left today", details.checks_left_today);
  } else {
    addFact(facts, "Last reported", shortTime(result.last_reported));
    addFact(facts, "ISP", result.isp);
    addFact(facts, "Country", result.country);
    if (typeof result.whitelisted === "boolean") addFact(facts, "Whitelisted", yesNo(result.whitelisted), result.whitelisted ? "ok" : "no");
  }
  if (facts.childElementCount) rep.append(facts);
  if (!details) rep.append(make("p", "fineprint", "The deep analysis also loads usage type, domain, hostnames, Tor status, attack categories and the newest reports."));
  if (result.reason) {
    const verdictBlock = make("div", "block");
    const vt = make("p", "sub-title", "Quick verdict reason");
    verdictBlock.append(vt, make("p", "prose", result.reason));
    rep.append(verdictBlock);
  }
  side.append(rep);

  if (details && ((details.top_categories || []).length || (details.top_reporter_countries || []).length)) {
    const cats = card("Reported for", "i-list", false);
    const pairs = (items) => items.map(([name, count]) => make("li", null, `${name} · ${count}`));
    if ((details.top_categories || []).length) {
      const list = make("ul", "chips");
      list.append(...pairs(details.top_categories));
      cats.append(make("p", "sub-title", "Attack categories"), list);
    }
    if ((details.top_reporter_countries || []).length) {
      const list = make("ul", "chips");
      list.append(...pairs(details.top_reporter_countries));
      cats.append(make("p", "sub-title", "Reporter countries"), list);
    }
    side.append(cats);
  }

  if (insight) {
    const given = card("What Gemini was given", "i-layers", false);
    const excerpts = insight.alert_excerpts || [];
    let line;
    if (!insight.alert_found) line = "The AbuseIPDB record only: the original alert is no longer in memory.";
    else if (!excerpts.length) line = "The AbuseIPDB record only: no part of the alert mentions this IP.";
    else line = `The AbuseIPDB record and ${excerpts.length} part${excerpts.length === 1 ? "" : "s"} of the alert:`;
    given.append(make("p", "prose", line));
    if (excerpts.length) {
      const list = make("ul", "excerpts");
      for (const excerpt of excerpts) list.append(make("li", null, excerpt));
      given.append(list);
    }
    side.append(given);
  }
  grid.append(side);
  bodyEl.append(grid);

  // Full width: hunting queries, then recent reports.
  if (assessment) {
    const hunts = card("Hunting queries", "i-code", true);
    const queries = assessment.hunting_queries || [];
    if (queries.length) {
      const list = make("div", "hunts");
      for (const hunt of queries) list.append(huntBlock(hunt));
      hunts.append(list, make("p", "fineprint", "Written by Gemini. Check table and field names against your workspace before running."));
    } else {
      hunts.append(make("p", "prose", "Gemini did not suggest any hunting queries for this IP."));
    }
    bodyEl.append(hunts);
  }

  if (details) {
    const recent = details.recent_reports || [];
    const reportsCard = card(recent.length ? `Recent reports (newest ${recent.length})` : "Recent reports", "i-clock", false);
    if (recent.length) {
      const list = make("ul", "reports");
      for (const report of recent) {
        const item = make("li");
        const meta = make("div");
        meta.append(
          make("p", "meta", shortTime(report.reported_at)),
          make("p", "meta", [(report.categories || []).join(", "), report.reporter_country].filter(Boolean).join(" · ")),
        );
        item.append(meta, make("p", "comment", report.comment || "(no comment)"));
        list.append(item);
      }
      reportsCard.append(list, make("p", "fineprint", "Comments are written by AbuseIPDB users, are not verified, and are shown as plain text."));
    } else {
      reportsCard.append(make("p", "prose", "No reports in the last 90 days."));
    }
    bodyEl.append(reportsCard);
  }
}

/** Build one hunting query with its language and a copy button. */
function huntBlock(hunt) {
  const wrap = make("div", "hunt");
  const head = make("div", "hunt-head");
  const copy = make("button", "btn btn-quiet");
  copy.type = "button";
  copy.append(icon("i-copy"), document.createTextNode("Copy"));
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(hunt.query);
      copy.replaceChildren(icon("i-check"), document.createTextNode("Copied"));
    } catch {
      copy.replaceChildren(document.createTextNode("Copy failed"));
    }
  });
  head.append(make("span", "hunt-lang", hunt.language), copy);
  const pre = make("pre");
  pre.append(make("code", null, hunt.query));
  wrap.append(head, pre);
  return wrap;
}

/** Run the deep analysis for one IP once; the result is kept for this page session so reopening is free. */
async function runInsight(ip) {
  const key = insightKey(ip);
  if (state.pending.get(key) || state.insights.has(key)) return;
  state.pending.set(key, true);
  state.failures.delete(key);
  refresh();

  try {
    const response = await fetch("/insight", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, token: state.token, check: state.checkId }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    state.insights.set(key, data);
  } catch (err) {
    state.failures.set(key, err.message);
  } finally {
    state.pending.delete(key);
    refresh();
  }
}

/** Redraw whatever view is showing after data changed. */
function refresh() {
  const view = document.body.dataset.view;
  if (view === "investigate") renderInvestigation();
  else if (view === "results") renderPanel(false);
}

// ---------------------------------------------------------------- export

/** Make a value safe for one CSV cell, including against spreadsheet formula injection. */
function csvCell(value) {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

/** Return a timestamp like 20261108-143005 for file names. */
function stamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

/** Hand the browser a file to save, built in memory from the current results. */
function download(name, type, content) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = make("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Export the results as a CSV file. */
function exportCsv() {
  const columns = ["ip", "verdict", "severity", "score", "country", "isp", "reports", "last_reported", "reason", "error"];
  const lines = [columns.join(",")];
  for (const result of state.results) lines.push(columns.map((column) => csvCell(result[column])).join(","));
  download(`ioc-results-${stamp()}.csv`, "text/csv;charset=utf-8", `﻿${lines.join("\r\n")}\r\n`);
}

/** Export the results, skipped addresses and context as a JSON file. */
function exportJson() {
  const data = {
    exported_at: new Date().toISOString(),
    mode: state.mode,
    source: state.source,
    results: state.results,
    skipped: state.skipped.map(([ip, reason]) => ({ ip, reason })),
    cut: state.cut,
  };
  download(`ioc-results-${stamp()}.json`, "application/json", `${JSON.stringify(data, null, 2)}\n`);
}

// ---------------------------------------------------------------- start screen horizon

const horizon = { canvas: null, frame: 0, running: false, phase: 0 };

/** Draw the faint dot-field horizon at the bottom of the start screen. */
function drawHorizon() {
  const canvas = horizon.canvas;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);

  // Rows of dots that rise towards both edges, like the horizon in the mockup; brighter nearer the viewer.
  const rows = 26;
  const gap = Math.max(9, width / 160);
  for (let r = 0; r < rows; r += 1) {
    const depth = r / (rows - 1);
    const y0 = height * (0.18 + depth * 0.82);
    for (let x = 0; x <= width; x += gap) {
      const t = x / width;
      const edge = Math.pow(Math.abs(t - 0.5) * 2, 2.2);
      const swell = Math.sin(t * Math.PI * 2 + horizon.phase + depth * 1.6) * 18
        + Math.sin(t * Math.PI * 5 - horizon.phase * 0.7 + depth) * 7;
      const rise = edge * height * 0.55 * (1 - depth * 0.55);
      const y = y0 - rise - swell * (0.5 + edge);
      const alpha = (0.1 + depth * 0.5) * (0.25 + edge * 1.1);
      const size = 1.3 + depth * 1.2;
      ctx.fillStyle = `rgba(76, 155, 255, ${Math.min(alpha, 0.75).toFixed(3)})`;
      ctx.fillRect(x, y, size, size);
    }
  }
}

/** Animate the horizon slowly while the start screen is showing, unless reduced motion is preferred. */
function startHorizon() {
  horizon.canvas = horizon.canvas || $("horizon");
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  drawHorizon();
  if (still || horizon.running) return;
  horizon.running = true;
  let last = 0;
  const tick = (time) => {
    if (!horizon.running) return;
    if (time - last > 40) {
      horizon.phase += 0.012;
      drawHorizon();
      last = time;
    }
    horizon.frame = requestAnimationFrame(tick);
  };
  horizon.frame = requestAnimationFrame(tick);
}

/** Stop the horizon animation when the start screen is hidden. */
function stopHorizon() {
  horizon.running = false;
  cancelAnimationFrame(horizon.frame);
}

// ---------------------------------------------------------------- routing

/** Show the view named in the address bar: the start screen, the results, or one IP's investigation. */
function route() {
  const hash = location.hash || "#/";
  let view = "start";
  if (hash === "#/results" && state.results.length + state.skipped.length > 0) view = "results";
  if (hash.startsWith("#/investigate/")) {
    const ip = decodeURIComponent(hash.slice("#/investigate/".length));
    if (resultFor(ip)) {
      state.selected = ip;
      view = "investigate";
    } else if (state.results.length) {
      location.replace("#/results");
      return;
    }
  }
  if (view === "start" && hash !== "#/" && hash !== "") {
    location.replace("#/");
  }

  document.body.dataset.view = view;
  $("view-start").hidden = view !== "start";
  $("view-results").hidden = view !== "results";
  $("view-investigate").hidden = view !== "investigate";
  $("export").hidden = !state.results.length;
  $("nav-analyze").setAttribute("aria-current", view === "start" ? "page" : "false");
  $("panel").classList.remove("open");
  $("scrim").hidden = true;

  if (view === "start") {
    document.title = "IOC Checker";
    const resume = $("resume");
    resume.hidden = !state.results.length;
    $("resume-label").textContent = `Back to your last results (${state.results.length} IP${state.results.length === 1 ? "" : "s"})`;
    startHorizon();
  } else {
    stopHorizon();
  }
  if (view === "results") {
    document.title = "Results · IOC Checker";
    renderResults();
    window.scrollTo(0, 0);
    const row = $("results-body").querySelector('tr[aria-selected="true"]');
    if (row && document.activeElement === document.body) row.focus({ preventScroll: true });
  }
  if (view === "investigate") {
    renderInvestigation();
    window.scrollTo(0, 0);
    const heading = $("inv-ip");
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }
}

// ---------------------------------------------------------------- wiring

$("composer").addEventListener("submit", runCheck);
$("payload").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    $("composer").requestSubmit();
  }
});
$("payload").addEventListener("input", () => {
  state.source = "";
  setLoadedNote("");
});

for (const tab of ["paste", "upload"]) $(`itab-${tab}`).addEventListener("click", () => showInputTab(tab));
document.querySelector(".input-tabs").addEventListener("keydown", (event) => {
  if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
    event.preventDefault();
    showInputTab($("itab-paste").getAttribute("aria-selected") === "true" ? "upload" : "paste");
  }
});

const dropzone = $("dropzone");
$("file-input").addEventListener("change", (event) => readFile(event.target.files[0]));
dropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropzone.classList.add("over");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("over"));
dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropzone.classList.remove("over");
  readFile(event.dataTransfer.files[0]);
});

for (const chip of document.querySelectorAll("[data-sample]")) {
  chip.addEventListener("click", () => {
    const sample = SAMPLES[chip.dataset.sample];
    $("payload").value = sample.text;
    state.source = sample.name;
    setFormError("");
    setLoadedNote(`Loaded the ${sample.name.toLowerCase()} (synthetic data).`);
    showInputTab("paste", false);
    $("payload").focus();
  });
}

$("results-body").addEventListener("keydown", onTableKey);
$("scrim").addEventListener("click", closeSheet);
$("inv-prev").addEventListener("click", () => stepInvestigation(-1));
$("inv-next").addEventListener("click", () => stepInvestigation(1));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeSheet();
  const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
  if (document.body.dataset.view === "investigate" && !typing && !event.altKey && !event.ctrlKey && !event.metaKey) {
    if (event.key === "ArrowLeft") stepInvestigation(-1);
    if (event.key === "ArrowRight") stepInvestigation(1);
  }
});
$("export-csv").addEventListener("click", exportCsv);
$("export-json").addEventListener("click", exportJson);
window.addEventListener("hashchange", route);
window.addEventListener("resize", () => {
  if (document.body.dataset.view === "start") drawHorizon();
});

loadStatus();
route();
