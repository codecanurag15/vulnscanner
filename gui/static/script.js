const SEVERITY_COLOR = {
  Critical: "#ff5c5c",
  High: "#ff9f43",
  Moderate: "#ffd93d",
  Low: "#4ade80",
  Unknown: "#8891a7",
  None: "#8891a7",
};

const form = document.getElementById("scan-form");
const targetInput = document.getElementById("target");
const portsInput = document.getElementById("ports");
const apiKeyInput = document.getElementById("apikey");
const scanBtn = document.getElementById("scan-btn");
const toggleAdvanced = document.getElementById("toggle-advanced");
const advanced = document.getElementById("advanced");

const stepper = document.getElementById("stepper");
const progressWrap = document.getElementById("progress-wrap");
const progressBar = document.getElementById("progress-bar");
const progressText = document.getElementById("progress-text");
const logPanel = document.getElementById("log-panel");
const logBody = document.getElementById("log-body");

const results = document.getElementById("results");
const portRows = document.getElementById("port-rows");
const noPorts = document.getElementById("no-ports");
const findingsEl = document.getElementById("findings");
const noFindings = document.getElementById("no-findings");
const reportLink = document.getElementById("report-link");

const counters = {
  Critical: document.getElementById("n-critical"),
  High: document.getElementById("n-high"),
  Moderate: document.getElementById("n-moderate"),
  Low: document.getElementById("n-low"),
};
const nPorts = document.getElementById("n-ports");

toggleAdvanced.addEventListener("click", () => advanced.classList.toggle("hidden"));

function logLine(msg) {
  const row = document.createElement("div");
  row.className = "log-line";
  const t = new Date().toLocaleTimeString([], { hour12: false });
  row.innerHTML = `<span class="t">${t}</span>${msg}`;
  logBody.appendChild(row);
  logBody.scrollTop = logBody.scrollHeight;
}

function setStep(name, state) {
  const el = stepper.querySelector(`[data-step="${name}"]`);
  if (!el) return;
  el.classList.remove("active", "done");
  if (state) el.classList.add(state);
}

function resetUI() {
  [stepper, progressWrap, logPanel, results].forEach((el) => el.classList.remove("hidden"));
  logBody.innerHTML = "";
  portRows.innerHTML = "";
  findingsEl.innerHTML = "";
  noPorts.classList.add("hidden");
  noFindings.classList.add("hidden");
  reportLink.classList.add("hidden");
  Object.values(counters).forEach((el) => (el.textContent = "0"));
  nPorts.textContent = "0";
  ["resolve", "ports", "cve", "report"].forEach((s) => setStep(s, null));
  progressBar.style.width = "0%";
  progressText.textContent = "0 / 0";
}

function addPortRow(d) {
  const tr = document.createElement("tr");
  const product = [d.product, d.version].filter(Boolean).join(" ") || "—";
  tr.innerHTML = `
    <td class="mono">${d.port}</td>
    <td>${escapeHtml(d.service || "")}</td>
    <td class="mono">${escapeHtml(product)}</td>
    <td class="banner-cell mono">${escapeHtml((d.banner || "").replace(/[\r\n]+/g, " "))}</td>`;
  portRows.appendChild(tr);
  nPorts.textContent = String(portRows.children.length);
}

function addFinding(f) {
  const color = SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.Unknown;
  const isCve = (f.cve_id || "").startsWith("CVE-");
  const url = isCve ? `https://nvd.nist.gov/vuln/detail/${f.cve_id}` : "#";
  const div = document.createElement("div");
  div.className = "finding";
  div.style.borderLeftColor = color;
  div.innerHTML = `
    <div class="finding-head">
      <a class="cve-id" href="${url}" target="_blank" rel="noopener">${escapeHtml(f.cve_id)}</a>
      <span class="pill" style="background:${color}22;color:${color};border-color:${color}88">${escapeHtml(f.severity)}</span>
      <span class="score mono">${Number(f.cvss_score).toFixed(1)}</span>
      <span class="finding-meta mono">
        <span class="chip">port ${escapeHtml(String(f.port ?? ""))}</span>
        <span class="chip">${escapeHtml(f.service || "")}</span>
        <span class="chip">published ${escapeHtml(f.published || "—")}</span>
      </span>
    </div>
    <p class="finding-desc">${escapeHtml(f.description || "No description available.")}</p>`;
  findingsEl.appendChild(div);

  if (counters[f.severity]) {
    counters[f.severity].textContent = String(Number(counters[f.severity].textContent) + 1);
  }
}

function escapeHtml(str) {
  const d = document.createElement("div");
  d.textContent = str == null ? "" : str;
  return d.innerHTML;
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;

  resetUI();
  scanBtn.disabled = true;
  scanBtn.querySelector(".btn-label").textContent = "Scanning…";
  logLine(`Starting scan of <b>${escapeHtml(target)}</b>`);
  setStep("resolve", "active");

  const params = new URLSearchParams({ target });
  if (portsInput.value.trim()) params.set("ports", portsInput.value.trim());
  if (apiKeyInput.value.trim()) params.set("api_key", apiKeyInput.value.trim());

  const es = new EventSource(`/scan?${params.toString()}`);
  let portTotal = 0;
  let cveTotal = 0;

  es.addEventListener("log", (e) => logLine(JSON.parse(e.data).msg));

  es.addEventListener("resolved", (e) => {
    const d = JSON.parse(e.data);
    portTotal = d.port_total;
    logLine(`Resolved to <b>${escapeHtml(d.ip)}</b> — scanning ${d.port_total} ports`);
    setStep("resolve", "done");
    setStep("ports", "active");
  });

  es.addEventListener("port_found", (e) => {
    addPortRow(JSON.parse(e.data));
  });

  es.addEventListener("progress", (e) => {
    const d = JSON.parse(e.data);
    const pct = d.total ? Math.round((d.done / d.total) * 100) : 0;
    progressBar.style.width = `${pct}%`;
    progressText.textContent = `${d.done} / ${d.total}`;
    if (d.phase === "ports" && d.done === d.total) {
      setStep("ports", "done");
      setStep("cve", "active");
      logLine(`Port scan complete — matching services against NVD`);
    }
    if (d.phase === "cve") cveTotal = d.total;
  });

  es.addEventListener("cve_found", (e) => {
    addFinding(JSON.parse(e.data));
  });

  es.addEventListener("done", (e) => {
    const d = JSON.parse(e.data);
    setStep("cve", "done");
    setStep("report", "done");
    if (portRows.children.length === 0) noPorts.classList.remove("hidden");
    if (findingsEl.children.length === 0) noFindings.classList.remove("hidden");
    logLine(`Done in ${d.duration}s — ${d.open_ports} open port(s), ${d.cve_count} CVE(s) matched`);
    reportLink.href = `/reports/${d.report_file}`;
    reportLink.classList.remove("hidden");
    scanBtn.disabled = false;
    scanBtn.querySelector(".btn-label").textContent = "Run scan";
    es.close();
  });

  es.addEventListener("error", (e) => {
    let msg = "Connection to scanner lost.";
    try { msg = JSON.parse(e.data).msg || msg; } catch (_) {}
    logLine(`<span style="color:#ff5c5c">Error: ${escapeHtml(msg)}</span>`);
    scanBtn.disabled = false;
    scanBtn.querySelector(".btn-label").textContent = "Run scan";
    es.close();
  });
});
