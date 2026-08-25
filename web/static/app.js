const apiBase = window.location.port === "18081" ? `${window.location.protocol}//${window.location.hostname}:18080` : "";

const loginScreen = document.querySelector("#loginScreen");
const loginForm = document.querySelector("#loginForm");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const loginButton = document.querySelector("#loginButton");
const loginStatus = document.querySelector("#loginStatus");
const availability = document.querySelector("#availability");
const availabilityText = document.querySelector("#availabilityText");
const appScreen = document.querySelector("#appScreen");
const sidebar = document.querySelector("#sidebar");
const primaryNav = document.querySelector("#primaryNav");
const pageTitle = document.querySelector("#pageTitle");
const pageRefresh = document.querySelector("#pageRefresh");
const viewRoot = document.querySelector("#viewRoot");
const noticeStack = document.querySelector("#noticeStack");
const overlay = document.querySelector("#overlay");
const dialog = document.querySelector("#dialog");
const dialogHeader = document.querySelector("#dialogHeader");
const dialogTitle = document.querySelector("#dialogTitle");
const dialogBody = document.querySelector("#dialogBody");
const backupFileInput = document.querySelector("#backupFileInput");

const DEFAULT_THEME = { dark: "#000000", light: "#ffffff", accent: "#00a8ff" };
const NAV_KEYS = ["dashboard", "connections", "clients", "analytics", "register", "settings"];
const VIEW_TITLES = {
  dashboard: "DASHBOARD",
  connections: "CONNECTIONS",
  clients: "CLIENTS",
  analytics: "ANALYTICS",
  register: "REGISTER",
  settings: "SETTINGS",
  documentation: "DOCUMENTATION",
};
const STORAGE = {
  theme: "loki-watcher.theme",
  sidebarAuto: "loki-watcher.sidebar-auto",
  navigation: "loki-watcher.navigation",
  metrics: "loki-watcher.dashboard-metrics",
};

const state = {
  activeView: "dashboard",
  connections: [],
  clients: [],
  analyticsReports: [],
  analyticsHasMore: false,
  analyticsNextBeforeId: null,
  analyticsType: "",
  analyticsClientId: "",
  registerEntries: [],
  registerQuery: "",
  settings: null,
  audit: [],
  auditHasMore: false,
  auditNextBeforeId: null,
  serverRelease: null,
  serverUpdateJob: null,
  serverUpdatePolling: false,
  dialogResolve: null,
  draggingNav: null,
  draggingMetric: null,
  suppressNavigation: false,
};

function readStoredJson(key, fallback) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "null");
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function escapeHtml(value) {
  const text = value === null || value === undefined || value === "" ? "—" : String(value);
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttribute(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = Number(value || 0);
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatPercent(value) {
  return value === null || value === undefined ? "—" : `${value}%`;
}

function formatDuration(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  if (seconds < 60) return `${Math.round(seconds)} sec`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(seconds % 3600 === 0 ? 0 : 1)} h`;
}

function formatPlatform(value) {
  if (value === "windows") return "Windows";
  if (value === "android") return "Android";
  return value || "unknown";
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const part = (number) => String(number).padStart(2, "0");
  return `${part(date.getDate())}.${part(date.getMonth() + 1)}.${date.getFullYear()} ${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

function property(name, value) {
  return `<div class="property"><span class="property-name">${escapeHtml(name)}</span><span class="property-value">${escapeHtml(value)}</span></div>`;
}

function authHeader() {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username && !password) return {};
  const encoded = new TextEncoder().encode(`${username}:${password}`);
  return { Authorization: `Basic ${btoa(String.fromCharCode(...encoded))}` };
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    cache: "no-store",
    headers: { ...(options.headers || {}), ...authHeader() },
  });
  if (response.status === 401) {
    showLogin("Incorrect login or password. Check the credentials and try again.");
    throw new Error("Authentication required");
  }
  return response;
}

async function apiJson(path, options = {}) {
  const response = await apiFetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || `Request failed with status ${response.status}`);
  }
  return body;
}

function updateLoginButton() {
  loginButton.disabled = !usernameInput.value.trim() || !passwordInput.value || loginButton.classList.contains("pending");
}

function setAvailability(availableState) {
  availability.classList.toggle("unavailable", !availableState);
  availabilityText.textContent = availableState ? "AVAILABLE" : "UNAVAILABLE";
}

async function checkAvailability() {
  try {
    const response = await fetch(`${apiBase}/health`, { cache: "no-store" });
    setAvailability(response.ok);
  } catch {
    setAvailability(false);
  }
}

function showLogin(message = "") {
  appScreen.classList.add("hidden");
  loginScreen.classList.remove("hidden");
  loginStatus.textContent = message;
  loginButton.classList.remove("pending");
  loginButton.textContent = "Sign in";
  updateLoginButton();
  (message ? passwordInput : usernameInput).focus();
}

function showApp() {
  loginScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
  loginStatus.textContent = "";
  applySidebarPreference();
}

async function signIn(event) {
  event.preventDefault();
  if (!loginForm.reportValidity() || loginButton.classList.contains("pending")) return;
  loginButton.classList.add("pending");
  loginButton.disabled = true;
  loginButton.textContent = "Signing in...";
  loginStatus.textContent = "";
  try {
    await apiJson("/api/v1/dashboard");
    showApp();
    await navigate("dashboard", { force: true });
  } catch (error) {
    if (!loginStatus.textContent) loginStatus.textContent = error.message;
  } finally {
    loginButton.classList.remove("pending");
    loginButton.textContent = "Sign in";
    updateLoginButton();
  }
}

function showNotice(message, type = "info") {
  while (noticeStack.children.length >= 5) noticeStack.firstElementChild.remove();
  const notice = document.createElement("div");
  notice.className = `notice ${type}`;
  notice.innerHTML = `<span>${escapeHtml(message)}</span><button type="button" aria-label="Dismiss notification">×</button>`;
  notice.querySelector("button").addEventListener("click", () => notice.remove());
  noticeStack.appendChild(notice);
  applySmartHover(notice);
  window.setTimeout(() => notice.remove(), type === "error" ? 8000 : 4500);
}

function applyTheme(theme, persist = false) {
  const normalized = {
    dark: theme.dark || DEFAULT_THEME.dark,
    light: theme.light || DEFAULT_THEME.light,
    accent: theme.accent || DEFAULT_THEME.accent,
  };
  document.documentElement.style.setProperty("--dark", normalized.dark);
  document.documentElement.style.setProperty("--light", normalized.light);
  document.documentElement.style.setProperty("--accent", normalized.accent);
  if (persist) localStorage.setItem(STORAGE.theme, JSON.stringify(normalized));
}

function sidebarAutoEnabled() {
  return localStorage.getItem(STORAGE.sidebarAuto) !== "false";
}

function applySidebarPreference() {
  document.body.classList.toggle("sidebar-fixed", !sidebarAutoEnabled());
}

function applySmartHover(root = document) {
  root.querySelectorAll("button, .button-like, .metric-card").forEach((element) => {
    element.classList.add("smart-hover");
    const rect = element.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const grow = Math.min(rect.width, rect.height) * .05;
    element.style.setProperty("--hover-scale-x", String((rect.width + grow) / rect.width));
    element.style.setProperty("--hover-scale-y", String((rect.height + grow) / rect.height));
  });
}

function closeDialog(result = false) {
  overlay.classList.add("hidden");
  dialog.removeAttribute("style");
  const resolver = state.dialogResolve;
  state.dialogResolve = null;
  if (resolver) resolver(result);
}

function openDialog(title, content) {
  if (state.dialogResolve) closeDialog(false);
  dialog.removeAttribute("style");
  dialogTitle.textContent = title;
  dialogBody.innerHTML = content;
  overlay.classList.remove("hidden");
  applySmartHover(dialogBody);
  const firstControl = dialogBody.querySelector("input, textarea, select, button");
  if (firstControl) window.setTimeout(() => firstControl.focus(), 0);
}

function confirmAction({ title, copy, confirmLabel = "Delete" }) {
  openDialog(title, `
    <div class="confirmation-copy">${copy}</div>
    <div class="dialog-actions">
      <button id="confirmDialogAction" class="danger-action" type="button">${escapeHtml(confirmLabel)}</button>
      <button id="cancelDialogAction" type="button">Cancel</button>
    </div>
  `);
  return new Promise((resolve) => {
    state.dialogResolve = resolve;
    document.querySelector("#confirmDialogAction").addEventListener("click", () => closeDialog(true));
    document.querySelector("#cancelDialogAction").addEventListener("click", () => closeDialog(false));
  });
}

async function navigate(view, options = {}) {
  if (!VIEW_TITLES[view]) return;
  if (state.suppressNavigation && !options.force) return;
  state.activeView = view;
  pageTitle.textContent = VIEW_TITLES[view];
  pageRefresh.classList.toggle("hidden", view === "documentation");
  primaryNav.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  sidebar.classList.remove("open");
  viewRoot.innerHTML = `<div class="outer-workspace"><div class="workspace-content"><p class="muted">Loading ${escapeHtml(view)}...</p></div></div>`;
  try {
    if (view === "dashboard") await loadDashboardView();
    if (view === "connections") await loadConnectionsView();
    if (view === "clients") await loadClientsView();
    if (view === "analytics") await loadAnalyticsView();
    if (view === "register") await loadRegisterView();
    if (view === "settings") await loadSettingsView();
    if (view === "documentation") renderDocumentationView();
    applySmartHover(viewRoot);
  } catch (error) {
    viewRoot.innerHTML = `<div class="outer-workspace"><div class="workspace-content"><p class="inline-error">${escapeHtml(error.message)}. Refresh the view or check Watcher availability.</p></div></div>`;
    showNotice(`${VIEW_TITLES[view]} could not be loaded: ${error.message}`, "error");
  }
}

function orderedItems(items, storageKey, canonicalKeys) {
  const stored = readStoredJson(storageKey, []);
  if (!Array.isArray(stored)) return items;
  const valid = stored.filter((key) => canonicalKeys.includes(key));
  canonicalKeys.forEach((key) => { if (!valid.includes(key)) valid.push(key); });
  return [...items].sort((a, b) => valid.indexOf(a.key) - valid.indexOf(b.key));
}

function metricCard(metric) {
  const meta = metric.meta ? `<div class="metric-meta">${metric.meta.map(([name, value]) => `<span>${escapeHtml(name)}</span><span>${escapeHtml(value)}</span>`).join("")}</div>` : "";
  return `<article class="metric-card" draggable="true" tabindex="0" data-metric="${escapeHtml(metric.key)}"><span class="metric-label">${escapeHtml(metric.label)}</span><strong class="metric-value">${escapeHtml(metric.value)}</strong>${meta}</article>`;
}

async function loadDashboardView() {
  const data = await apiJson("/api/v1/dashboard");
  const system = data.system || {};
  const ram = system.ram || {};
  const disk = system.disk || {};
  const metrics = orderedItems([
    { key: "cpu", label: "CPU", value: formatPercent(system.cpuUsagePercent), meta: [["Source", "system load"]] },
    { key: "ram", label: "RAM", value: formatPercent(ram.percent), meta: [["Used", formatBytes(ram.usedBytes)], ["Total", formatBytes(ram.totalBytes)]] },
    { key: "disk", label: "Disk", value: formatPercent(disk.percent), meta: [["Used", formatBytes(disk.usedBytes)], ["Total", formatBytes(disk.totalBytes)]] },
    { key: "clients", label: "Activated clients", value: system.activatedClients ?? system.installedClients ?? 0, meta: [["Heartbeat", formatDuration(system.heartbeatIntervalSeconds)], ["Online window", formatDuration(system.onlineWindowSeconds)]] },
    { key: "connections", label: "Issued connections", value: system.issuedConnections ?? 0, meta: [["Source", "Watcher register"]] },
    { key: "traffic", label: "Connected-device network activity", value: formatBytes(system.totalTrafficBytes), meta: [["Scope", "All network adapters while clients report connected"]] },
  ], STORAGE.metrics, ["cpu", "ram", "disk", "clients", "connections", "traffic"]);
  viewRoot.innerHTML = `
    <section class="outer-workspace">
      <div class="workspace-toolbar"><span class="toolbar-title">System metrics</span><span class="muted">Drag metrics to change their order</span></div>
      <div class="workspace-content"><div id="metricGrid" class="metric-grid">${metrics.map(metricCard).join("")}</div></div>
    </section>
  `;
  setupMetricReordering();
}

function setupMetricReordering() {
  const grid = document.querySelector("#metricGrid");
  grid.querySelectorAll(".metric-card").forEach((card) => {
    card.addEventListener("dragstart", () => {
      state.draggingMetric = card;
      card.classList.add("dragging");
    });
    card.addEventListener("dragover", (event) => {
      event.preventDefault();
      if (!state.draggingMetric || state.draggingMetric === card) return;
      grid.querySelectorAll(".metric-card").forEach((item) => item.classList.remove("insert-before", "insert-after"));
      const before = event.clientX < card.getBoundingClientRect().left + card.getBoundingClientRect().width / 2;
      card.classList.add(before ? "insert-before" : "insert-after");
    });
    card.addEventListener("drop", (event) => {
      event.preventDefault();
      if (!state.draggingMetric || state.draggingMetric === card) return;
      const before = card.classList.contains("insert-before");
      grid.insertBefore(state.draggingMetric, before ? card : card.nextSibling);
      localStorage.setItem(STORAGE.metrics, JSON.stringify([...grid.children].map((item) => item.dataset.metric)));
      showNotice("Dashboard metric order saved", "success");
    });
    card.addEventListener("dragend", () => {
      grid.querySelectorAll(".metric-card").forEach((item) => item.classList.remove("dragging", "insert-before", "insert-after"));
      state.draggingMetric = null;
    });
  });
}

function configurationLines(configurations) {
  if (!Array.isArray(configurations) || !configurations.length) return `<p class="empty-state">No inner configurations registered.</p>`;
  return `<div class="configuration-list">${configurations.map((value) => `<code class="configuration-line">${escapeHtml(value)}</code>`).join("")}</div>`;
}

function issuedConnectionCard(item) {
  const encodedId = encodeURIComponent(item.id);
  const innerCount = Array.isArray(item.configurations) ? item.configurations.length : 0;
  const sources = Array.isArray(item.sources) ? item.sources : [];
  const pasarSource = sources.find((source) => source.provider === "pasarguard");
  const canReset = Boolean(pasarSource?.external_user_id);
  const sourceSummary = sources
    .filter((source) => source.provider !== "direct" || source.configurations?.length)
    .map((source) => source.provider === "direct" ? "direct VLESS" : source.provider)
    .join(", ") || "not configured";
  return `
    <details class="entity-card">
      <summary><span class="entity-title">${escapeHtml(item.id)}</span><span class="entity-summary-meta">${innerCount} inner · ${escapeHtml(sourceSummary)}</span><span class="status-tag ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span></summary>
      <div class="entity-body">
        <div class="property-grid">
          ${property("Permanent ID", item.id)}
          <div class="property"><span class="property-name">Cake Proxy subscription URL</span><span class="property-value"><a href="${escapeHtml(item.public_subscription_url)}" target="_blank" rel="noreferrer">${escapeHtml(item.public_subscription_url)}</a></span></div>
          ${property("Sources", sourceSummary)}
          ${property("PasarGuard user ID", pasarSource?.external_user_id)}
          ${property("PasarGuard username", pasarSource?.external_username)}
          ${property("Revision", item.revision)}
          ${property("Provisioning", item.provisioning_state || "active")}
          ${property("Provider error", item.provider_error)}
          ${property("Last scan", formatDate(item.last_scan_at))}
          ${property("Scan status", item.last_scan_status || "not scanned")}
          ${property("Scan result", item.last_scan_message || "Waiting for the scheduled or manual scan")}
          ${property("Created", formatDate(item.created_at))}
          ${property("Subscription renewal date", item.subscription_renewal_date)}
          <label class="toggle-row"><span>Track subscription</span><input type="checkbox" data-track-subscription="${encodedId}" ${item.track_subscription ? "checked" : ""}></label>
        </div>
        <h3 class="subheading">Inner connections</h3>
        ${configurationLines(item.configurations)}
        <div class="entity-actions">
          <button type="button" data-copy-connection-url="${encodedId}">Copy Cake Proxy URL</button>
          <button class="accent-action" type="button" data-set-connection="${encodedId}">Set new connection</button>
          <button type="button" data-rescan-connection="${encodedId}">Check all sources</button>
          ${canReset ? `<button class="danger-action" type="button" data-reset-connection="${encodedId}">Reset</button>` : ""}
          <button type="button" data-edit-connection="${encodedId}">Edit</button>
          <button class="danger-action" type="button" data-delete-connection="${encodedId}">Delete</button>
        </div>
      </div>
    </details>`;
}

function clientInventory(connections) {
  if (!Array.isArray(connections) || !connections.length) return `<p class="empty-state">No sanitized connection inventory reported.</p>`;
  return `<div class="configuration-list">${connections.map((item) => `<div class="configuration-line">${escapeHtml(item.name || "Connection")} · ${escapeHtml(item.protocol)} · ${escapeHtml(item.host)}:${escapeHtml(item.port)} · ${escapeHtml(item.security)}</div>`).join("")}</div>`;
}

function clientCard(client) {
  const encodedId = encodeURIComponent(client.client_id);
  return `
    <details class="entity-card">
      <summary><span class="entity-title">${escapeHtml(client.display_id)}</span><span class="entity-summary-meta">${escapeHtml(client.username || client.machine_name)}</span><span class="status-tag ${client.online ? "online" : "offline"}">${client.online ? "online" : "offline"}</span></summary>
      <div class="entity-body">
        <div class="property-grid">
          ${property("Client ID", client.display_id)}
          ${property("Platform", formatPlatform(client.platform))}
          ${property("OS user", client.username)}
          ${property("Machine", client.machine_name)}
          ${property("Original IP", client.original_ip)}
          ${property("Last IP", client.last_ip)}
          ${property("Region", client.region)}
          ${property("Provider", client.provider)}
          ${property("Version", client.app_version)}
          ${property("Proxy at last contact", client.status)}
          ${property("Routing", client.routing_mode)}
          ${property("Connected-device network activity", formatBytes(client.total_traffic_bytes))}
          ${property("Traffic metering", client.traffic_metering_mode)}
          ${property("Last seen", formatDate(client.last_seen_at))}
          ${property("Log upload consent", client.logs_upload_enabled)}
          ${property("Auto updates", client.auto_updates_enabled)}
        </div>
        <h3 class="subheading">Reported connections</h3>
        ${clientInventory(client.connections)}
        <div class="entity-actions">
          <button type="button" data-client-events="${encodedId}">Load event stream</button>
          <button type="button" data-client-collect="${encodedId}">Collect now</button>
          <button type="button" data-client-updates="${encodedId}">Check updates</button>
          <button type="button" data-client-logs="${encodedId}">Download logs</button>
          <button class="danger-action" type="button" data-client-delete="${encodedId}">Delete client</button>
        </div>
        <div class="client-events" data-events-for="${encodedId}"></div>
      </div>
    </details>`;
}

async function loadConnectionsView() {
  const connectionsData = await apiJson("/api/v1/connections");
  state.connections = connectionsData.connections || [];
  viewRoot.innerHTML = `
    <section class="outer-workspace">
      <div class="workspace-toolbar">
        <span class="toolbar-title">Issued connections</span>
        <span class="muted">${state.connections.length} registered</span>
        <div class="toolbar-actions"><button id="addConnection" class="accent-action" type="button">Add connection</button></div>
      </div>
      <div class="workspace-content">
        <div class="entity-list">${state.connections.map(issuedConnectionCard).join("") || `<p class="empty-state">No issued connections yet. Add the first subscription record.</p>`}</div>
      </div>
    </section>`;
  bindIssuedConnectionActions();
}

async function loadClientsView() {
  const clientsData = await apiJson("/api/v1/clients");
  state.clients = clientsData.clients || [];
  viewRoot.innerHTML = `
    <section class="outer-workspace">
      <div class="workspace-toolbar"><span class="toolbar-title">Activated clients</span><span class="muted">${state.clients.length} registered</span></div>
      <div class="workspace-content"><div class="entity-list">${state.clients.map(clientCard).join("") || `<p class="empty-state">No activated clients have reported telemetry yet.</p>`}</div></div>
    </section>`;
  bindClientActions();
}

function analyticsTypeLabel(value) {
  if (value === "fail_analytics") return "Fail analytics";
  if (value === "full_analytics") return "Full analytics";
  return value || "Analytics";
}

function analyticsRows() {
  if (!state.analyticsReports.length) return `<p class="empty-state">No retained analytics reports match the current filters.</p>`;
  return state.analyticsReports.map((report) => {
    const summary = report.summary || {};
    const detail = summary.reasonCode || summary.outcome || summary.profileName || report.status || "Recorded";
    return `<article class="analytics-row">
      <div class="analytics-main"><span class="analytics-type">${escapeHtml(analyticsTypeLabel(report.report_type))}</span><strong>${escapeHtml(report.client_display_id || report.client_id)}</strong><span>${escapeHtml(detail)}</span></div>
      <div class="analytics-meta"><span>${escapeHtml(formatDate(report.occurred_at))}</span><span>${escapeHtml(formatBytes(report.payload_bytes))}</span><span>${escapeHtml(report.client_machine_name)}</span></div>
      <button type="button" data-analytics-report="${escapeAttribute(encodeURIComponent(report.report_id))}">View JSON</button>
    </article>`;
  }).join("");
}

function renderAnalyticsView(retention = null) {
  const clientOptions = state.clients.map((client) => `<option value="${escapeAttribute(client.client_id)}" ${state.analyticsClientId === client.client_id ? "selected" : ""}>${escapeHtml(client.display_id || client.client_id)}</option>`).join("");
  viewRoot.innerHTML = `
    <section class="outer-workspace">
      <div class="workspace-toolbar analytics-toolbar">
        <span class="toolbar-title">Client analytics</span>
        <label class="compact-field"><span>Type</span><select id="analyticsType"><option value="">All analytics</option><option value="fail_analytics" ${state.analyticsType === "fail_analytics" ? "selected" : ""}>Fail analytics</option><option value="full_analytics" ${state.analyticsType === "full_analytics" ? "selected" : ""}>Full analytics</option></select></label>
        <label class="compact-field"><span>Client</span><select id="analyticsClient"><option value="">All clients</option>${clientOptions}</select></label>
        <button id="applyAnalyticsFilters" type="button">Apply</button>
        <span class="muted">${retention ? `${retention.days} days · ${formatBytes(retention.maxBytes)} cap` : "bounded retention"}</span>
      </div>
      <div class="workspace-content"><div class="analytics-list">${analyticsRows()}</div>${state.analyticsHasMore ? `<div class="list-footer"><button id="loadOlderAnalytics" type="button">Load older reports</button></div>` : ""}</div>
    </section>`;
  document.querySelector("#applyAnalyticsFilters").addEventListener("click", async () => {
    state.analyticsType = document.querySelector("#analyticsType").value;
    state.analyticsClientId = document.querySelector("#analyticsClient").value;
    await loadAnalyticsView();
    applySmartHover(viewRoot);
  });
  document.querySelector("#loadOlderAnalytics")?.addEventListener("click", async () => {
    await loadAnalyticsView({ append: true });
    applySmartHover(viewRoot);
  });
  viewRoot.querySelectorAll("[data-analytics-report]").forEach((button) => button.addEventListener("click", () => openAnalyticsReport(decodeURIComponent(button.dataset.analyticsReport))));
}

async function loadAnalyticsView({ append = false } = {}) {
  if (!state.clients.length) {
    const clientsData = await apiJson("/api/v1/clients");
    state.clients = clientsData.clients || [];
  }
  const query = new URLSearchParams({ limit: "100" });
  if (state.analyticsType) query.set("type", state.analyticsType);
  if (state.analyticsClientId) query.set("clientId", state.analyticsClientId);
  if (append && state.analyticsNextBeforeId) query.set("beforeId", String(state.analyticsNextBeforeId));
  const data = await apiJson(`/api/v1/analytics?${query}`);
  state.analyticsReports = append ? [...state.analyticsReports, ...(data.reports || [])] : (data.reports || []);
  state.analyticsHasMore = Boolean(data.hasMore);
  state.analyticsNextBeforeId = data.nextBeforeId || null;
  renderAnalyticsView(data.retention || null);
}

async function openAnalyticsReport(reportId) {
  try {
    const data = await apiJson(`/api/v1/analytics/${encodeURIComponent(reportId)}`);
    const report = data.report || {};
    const json = JSON.stringify(report.payload || {}, null, 2);
    openDialog(analyticsTypeLabel(report.report_type), `<div class="analytics-detail-head">${property("Client", report.client_display_id || report.client_id)}${property("Occurred", formatDate(report.occurred_at))}${property("Status", report.status)}</div><pre class="analytics-json">${escapeHtml(json)}</pre><div class="dialog-actions"><button id="downloadAnalyticsJson" type="button">Download JSON</button><button id="closeAnalyticsDetail" type="button">Close</button></div>`);
    document.querySelector("#closeAnalyticsDetail").addEventListener("click", () => closeDialog());
    document.querySelector("#downloadAnalyticsJson").addEventListener("click", () => {
      const blob = new Blob([json], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${report.report_type || "analytics"}-${report.report_id || "report"}.json`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(link.href), 0);
    });
  } catch (error) {
    showNotice(`Analytics report could not be loaded: ${error.message}`, "error");
  }
}

function connectionForm(item = null) {
  const directSource = (item?.sources || []).find((source) => source.provider === "direct");
  const configurations = Array.isArray(directSource?.configurations) ? directSource.configurations.join("\n") : "";
  return `
    <form id="connectionForm" class="dialog-form">
      <label class="field"><span>Permanent ID</span><input name="id" value="${escapeAttribute(item?.id)}" placeholder="Generated automatically when empty" ${item ? "disabled" : ""}></label>
      <label class="field"><span>Status</span><select name="status">${["active", "disabled"].map((status) => `<option value="${status}" ${item?.status === status ? "selected" : ""}>${status}</option>`).join("")}</select></label>
      <label class="field"><span>Subscription renewal date</span><input name="subscriptionRenewalDate" type="date" value="${escapeAttribute(item?.subscription_renewal_date || new Date().toISOString().slice(0, 10))}" required></label>
      <label class="toggle-row"><span>Track subscription</span><input name="trackSubscription" type="checkbox" ${item?.track_subscription !== false ? "checked" : ""}></label>
      <label class="field"><span>Direct VLESS connections · one URI per line</span><textarea name="configurations" placeholder="vless://…">${escapeAttribute(configurations)}</textarea></label>
      <p class="muted">A direct VLESS URI can always be pasted here. To create connections through an integration, save the card and choose “Set new connection”.</p>
      <div class="dialog-actions"><button class="accent-action" type="submit">${item ? "Save" : "Create connection"}</button><button id="cancelConnectionForm" type="button">Cancel</button></div>
    </form>`;
}

function openConnectionEditor(item = null) {
  openDialog(item ? "Edit connection" : "Add connection", connectionForm(item));
  const form = document.querySelector("#connectionForm");
  document.querySelector("#cancelConnectionForm").addEventListener("click", () => closeDialog());
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    submit.textContent = item ? "Saving..." : "Creating...";
    const formData = new FormData(form);
    const payload = {
      id: item?.id || String(formData.get("id") || "").trim(),
      verifyTls: true,
      status: String(formData.get("status") || "active"),
      subscriptionRenewalDate: String(formData.get("subscriptionRenewalDate") || ""),
      trackSubscription: form.elements.trackSubscription.checked,
      configurations: String(formData.get("configurations") || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    };
    try {
      await apiJson(item ? `/api/v1/connections/${encodeURIComponent(item.id)}` : "/api/v1/connections", {
        method: item ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      closeDialog();
      showNotice(item ? "Connection updated" : "Connection created", "success");
      await loadConnectionsView();
      applySmartHover(viewRoot);
    } catch (error) {
      submit.disabled = false;
      submit.textContent = item ? "Save" : "Create connection";
      showNotice(`Connection was not saved: ${error.message}`, "error");
    }
  });
}

function openConnectionMethodEditor(id) {
  openDialog("Set new connection", `
    <form id="connectionMethodForm" class="dialog-form">
      <label class="field"><span>Method</span><select name="method"><option value="pasarguard">PasarGuard</option></select></label>
      <p class="muted">Watcher reads the PasarGuard machine-interface address, template and API key from Register, creates the upstream user and imports its links.</p>
      <div class="dialog-actions"><button class="accent-action" type="submit">Create</button><button id="cancelConnectionMethod" type="button">Cancel</button></div>
    </form>`);
  const form = document.querySelector("#connectionMethodForm");
  document.querySelector("#cancelConnectionMethod").addEventListener("click", () => closeDialog());
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    submit.textContent = "Creating...";
    try {
      await apiJson(`/api/v1/connections/${encodeURIComponent(id)}/pasarguard/provision`, { method: "POST" });
      closeDialog();
      showNotice("PasarGuard connection created and imported", "success");
      await loadConnectionsView();
      applySmartHover(viewRoot);
    } catch (error) {
      submit.disabled = false;
      submit.textContent = "Create";
      showNotice(`PasarGuard provisioning failed: ${error.message}`, "error");
    }
  });
}

function bindIssuedConnectionActions() {
  document.querySelector("#addConnection").addEventListener("click", () => openConnectionEditor());
  viewRoot.querySelectorAll("[data-copy-connection-url]").forEach((button) => button.addEventListener("click", async () => {
    const id = decodeURIComponent(button.dataset.copyConnectionUrl);
    const connection = state.connections.find((item) => item.id === id);
    if (!connection?.public_subscription_url) {
      showNotice("Cake Proxy subscription URL is unavailable", "error");
      return;
    }
    try {
      await navigator.clipboard.writeText(connection.public_subscription_url);
      showNotice("Cake Proxy subscription URL copied", "success");
    } catch {
      showNotice("Browser did not allow clipboard access; copy the URL from the card", "error");
    }
  }));
  viewRoot.querySelectorAll("[data-set-connection]").forEach((button) => button.addEventListener("click", () => {
    openConnectionMethodEditor(decodeURIComponent(button.dataset.setConnection));
  }));
  viewRoot.querySelectorAll("[data-track-subscription]").forEach((checkbox) => checkbox.addEventListener("change", async () => {
    const id = decodeURIComponent(checkbox.dataset.trackSubscription);
    const connection = state.connections.find((item) => item.id === id);
    const directSource = (connection?.sources || []).find((source) => source.provider === "direct");
    const requested = checkbox.checked;
    checkbox.disabled = true;
    try {
      await apiJson(`/api/v1/connections/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: connection.status,
          verifyTls: Boolean(connection.verify_tls),
          configurations: directSource?.configurations || [],
          subscriptionRenewalDate: connection.subscription_renewal_date,
          trackSubscription: requested,
        }),
      });
      connection.track_subscription = requested;
      showNotice(requested ? "Subscription tracking enabled" : "Subscription tracking disabled", "success");
    } catch (error) {
      checkbox.checked = !requested;
      showNotice(`Subscription tracking was not changed: ${error.message}`, "error");
    } finally {
      checkbox.disabled = false;
    }
  }));
  viewRoot.querySelectorAll("[data-reset-connection]").forEach((button) => button.addEventListener("click", async () => {
    const id = decodeURIComponent(button.dataset.resetConnection);
    const confirmed = await confirmAction({
      title: "Reset PasarGuard connection",
      copy: `<p>PasarGuard will rotate credentials for <strong>${escapeHtml(id)}</strong>. The permanent ID and Watcher subscription URL will stay unchanged.</p><p>Previously issued upstream credentials will stop working.</p>`,
    });
    if (!confirmed) return;
    button.disabled = true;
    button.textContent = "Resetting...";
    try {
      await apiJson(`/api/v1/connections/${encodeURIComponent(id)}/pasarguard/reset`, { method: "POST" });
      showNotice("PasarGuard credentials rotated; Watcher subscription refreshed", "success");
      await loadConnectionsView();
      applySmartHover(viewRoot);
    } catch (error) {
      button.disabled = false;
      button.textContent = "Reset";
      showNotice(`PasarGuard reset failed: ${error.message}`, "error");
    }
  }));
  viewRoot.querySelectorAll("[data-rescan-connection]").forEach((button) => button.addEventListener("click", async () => {
    const id = decodeURIComponent(button.dataset.rescanConnection);
    const original = button.textContent;
    button.disabled = true;
    button.textContent = "Scanning...";
    try {
      const result = await apiJson(`/api/v1/connections/${encodeURIComponent(id)}/scan`, { method: "POST" });
      showNotice(`Subscription scan stored ${result.count || 0} inner connections`, "success");
      await loadConnectionsView();
      applySmartHover(viewRoot);
    } catch (error) {
      button.disabled = false;
      button.textContent = original;
      showNotice(`Subscription scan failed: ${error.message}`, "error");
    }
  }));
  viewRoot.querySelectorAll("[data-edit-connection]").forEach((button) => button.addEventListener("click", () => {
    const id = decodeURIComponent(button.dataset.editConnection);
    openConnectionEditor(state.connections.find((item) => item.id === id));
  }));
  viewRoot.querySelectorAll("[data-delete-connection]").forEach((button) => button.addEventListener("click", async () => {
    const id = decodeURIComponent(button.dataset.deleteConnection);
    const confirmed = await confirmAction({
      title: "Delete issued connection",
      copy: `<p><strong>${escapeHtml(id)}</strong> will be removed from Watcher globally.</p><p>The external subscription and servers remain installed and are not modified. No client identity is deny-listed. This cannot be reversed unless restored from a backup.</p>`,
    });
    if (!confirmed) return;
    try {
      await apiJson(`/api/v1/connections/${encodeURIComponent(id)}`, { method: "DELETE" });
      showNotice("Issued connection deleted", "success");
      await loadConnectionsView();
      applySmartHover(viewRoot);
    } catch (error) {
      showNotice(`Connection was not deleted: ${error.message}`, "error");
    }
  }));
}

function bindClientActions() {
  viewRoot.querySelectorAll("[data-client-events]").forEach((button) => button.addEventListener("click", () => loadClientEvents(decodeURIComponent(button.dataset.clientEvents), button)));
  viewRoot.querySelectorAll("[data-client-collect]").forEach((button) => button.addEventListener("click", () => runClientCommand(button, decodeURIComponent(button.dataset.clientCollect), "collect-now")));
  viewRoot.querySelectorAll("[data-client-updates]").forEach((button) => button.addEventListener("click", () => runClientCommand(button, decodeURIComponent(button.dataset.clientUpdates), "check_updates")));
  viewRoot.querySelectorAll("[data-client-logs]").forEach((button) => button.addEventListener("click", () => downloadFile(`/api/v1/clients/${encodeURIComponent(decodeURIComponent(button.dataset.clientLogs))}/logs.zip`, "client-logs.zip", "Client logs archive prepared")));
  viewRoot.querySelectorAll("[data-client-delete]").forEach((button) => button.addEventListener("click", () => deleteClient(decodeURIComponent(button.dataset.clientDelete))));
}

async function loadClientEvents(clientId, button) {
  button.disabled = true;
  button.textContent = "Loading...";
  try {
    const data = await apiJson(`/api/v1/clients/${encodeURIComponent(clientId)}`);
    const target = viewRoot.querySelector(`[data-events-for="${CSS.escape(encodeURIComponent(clientId))}"]`);
    const events = data.events || [];
    target.innerHTML = `<h3 class="subheading">Event stream</h3><div class="event-stream">${events.map((event) => `<div class="event-line"><span>${escapeHtml(formatDate(event.created_at))}</span><span>${escapeHtml(event.type)}</span><span>${escapeHtml(event.status)}</span><span>${escapeHtml(event.message)}</span></div>`).join("") || `<p class="empty-state">No retained events.</p>`}</div>`;
    button.textContent = "Reload event stream";
  } catch (error) {
    showNotice(`Client events could not be loaded: ${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
}

async function runClientCommand(button, clientId, command) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Queuing...";
  try {
    if (command === "collect-now") {
      await apiJson(`/api/v1/commands/${encodeURIComponent(clientId)}/collect-now`, { method: "POST" });
    } else {
      await apiJson(`/api/v1/commands/${encodeURIComponent(clientId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: command }),
      });
    }
    showNotice("Client command queued", "success");
  } catch (error) {
    showNotice(`Command was not queued: ${error.message}`, "error");
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function deleteClient(clientId) {
  const client = state.clients.find((item) => item.client_id === clientId);
  const confirmed = await confirmAction({
    title: "Delete client",
    copy: `<p><strong>${escapeHtml(client?.display_id || clientId)}</strong> will be removed from Watcher with its retained events and queued commands.</p><p>The Windows client remains installed externally. Its identity is not deny-listed and it can enroll again. Restore is possible only from a backup.</p>`,
  });
  if (!confirmed) return;
  try {
    await apiJson(`/api/v1/clients/${encodeURIComponent(clientId)}`, { method: "DELETE" });
    showNotice("Client deleted from Watcher", "success");
    await loadClientsView();
    applySmartHover(viewRoot);
  } catch (error) {
    showNotice(`Client was not deleted: ${error.message}`, "error");
  }
}

function registerRows() {
  const query = state.registerQuery.trim().toLowerCase();
  const entries = state.registerEntries.filter((entry) => !query || [entry.key, entry.value, entry.description].some((value) => String(value || "").toLowerCase().includes(query)));
  if (!entries.length) return `<p class="empty-state">No register values match the current search.</p>`;
  return entries.map((entry) => {
    const encodedKey = encodeURIComponent(entry.key);
    const displayValue = entry.secret ? (entry.configured ? "Configured · hidden" : "Not configured") : entry.value;
    return `<div class="register-row"><code class="register-key">${escapeHtml(entry.key)}</code><span class="register-value">${escapeHtml(displayValue)}</span><span class="register-description">${escapeHtml(entry.description)}</span><span class="row-actions"><button type="button" data-edit-register="${encodedKey}">Edit</button><button class="danger-action" type="button" data-delete-register="${encodedKey}">Delete</button></span></div>`;
  }).join("");
}

async function loadRegisterView() {
  const data = await apiJson("/api/v1/register");
  state.registerEntries = data.entries || [];
  state.registerQuery = "";
  viewRoot.innerHTML = `
    <section class="outer-workspace">
      <div class="register-toolbar"><label class="search-unit"><span>Search</span><input id="registerSearch" aria-label="Search register" placeholder="Key, value or description"></label><button id="addRegisterEntry" class="accent-action" type="button">Add value</button></div>
      <div id="registerList" class="register-list">${registerRows()}</div>
    </section>`;
  bindRegisterActions();
}

function refreshRegisterRows() {
  document.querySelector("#registerList").innerHTML = registerRows();
  bindRegisterRowActions();
  applySmartHover(document.querySelector("#registerList"));
}

function bindRegisterActions() {
  document.querySelector("#registerSearch").addEventListener("input", (event) => {
    state.registerQuery = event.target.value;
    refreshRegisterRows();
  });
  document.querySelector("#addRegisterEntry").addEventListener("click", () => openRegisterEditor());
  bindRegisterRowActions();
}

function bindRegisterRowActions() {
  viewRoot.querySelectorAll("[data-edit-register]").forEach((button) => button.addEventListener("click", () => {
    const key = decodeURIComponent(button.dataset.editRegister);
    openRegisterEditor(state.registerEntries.find((entry) => entry.key === key));
  }));
  viewRoot.querySelectorAll("[data-delete-register]").forEach((button) => button.addEventListener("click", () => deleteRegisterEntry(decodeURIComponent(button.dataset.deleteRegister))));
}

function openRegisterEditor(entry = null) {
  const secret = Boolean(entry?.secret);
  openDialog(entry ? "Edit register value" : "Add register value", `
    <form id="registerForm" class="dialog-form">
      <label class="field"><span>Key</span><input name="key" value="${escapeAttribute(entry?.key)}" placeholder="group.name" pattern="[A-Za-z0-9_.-]+" required ${entry ? "disabled" : ""}></label>
      ${secret
        ? `<label class="field"><span>Secret value</span><input name="value" type="password" autocomplete="new-password" placeholder="${entry.configured ? "Leave blank to keep the current key" : "Enter API key"}"></label>
           <label class="toggle-row"><span>Clear the stored secret</span><input name="clearSecret" type="checkbox"></label>`
        : `<label class="field"><span>Value</span><textarea name="value" placeholder="Value">${escapeAttribute(entry?.value)}</textarea></label>`}
      <label class="field"><span>Description</span><textarea name="description" placeholder="What this value controls">${escapeAttribute(entry?.description)}</textarea></label>
      <div class="dialog-actions"><button class="accent-action" type="submit">${entry ? "Save" : "Create"}</button><button id="cancelRegisterForm" type="button">Cancel</button></div>
    </form>`);
  document.querySelector("#cancelRegisterForm").addEventListener("click", () => closeDialog());
  document.querySelector("#registerForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    submit.textContent = "Saving...";
    const formData = new FormData(form);
    const value = String(formData.get("value") || "");
    const clearSecret = Boolean(form.elements.clearSecret?.checked);
    const payload = {
      key: String(formData.get("key") || entry?.key || "").trim(),
      value,
      description: String(formData.get("description") || "").trim(),
      preserveSecret: secret && !value && !clearSecret,
      clearSecret,
    };
    try {
      await apiJson(entry ? `/api/v1/register/${encodeURIComponent(entry.key)}` : "/api/v1/register", {
        method: entry ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      closeDialog();
      showNotice(entry ? "Register value updated" : "Register value created", "success");
      await loadRegisterView();
      applySmartHover(viewRoot);
    } catch (error) {
      submit.disabled = false;
      submit.textContent = entry ? "Save" : "Create";
      showNotice(`Register value was not saved: ${error.message}`, "error");
    }
  });
}

async function deleteRegisterEntry(key) {
  const confirmed = await confirmAction({
    title: "Delete register value",
    copy: `<p><strong>${escapeHtml(key)}</strong> will be removed from Watcher globally.</p><p>External services are not changed. The key is not deny-listed. The action can only be reversed by recreating the value or restoring a backup.</p>`,
  });
  if (!confirmed) return;
  try {
    await apiJson(`/api/v1/register/${encodeURIComponent(key)}`, { method: "DELETE" });
    showNotice("Register value deleted", "success");
    await loadRegisterView();
    applySmartHover(viewRoot);
  } catch (error) {
    showNotice(`Register value was not deleted: ${error.message}`, "error");
  }
}

function auditRows(events) {
  if (!events.length) return `<p class="empty-state">No administrative actions recorded yet.</p>`;
  return events.map((event) => `<div class="audit-row"><span class="status-${event.status === "success" ? "success" : "error"}">${escapeHtml(event.status)}</span><span>${escapeHtml(event.action)}</span><span class="audit-target">${escapeHtml(event.target)}</span><span class="audit-actor">${escapeHtml(event.actor)}</span><time class="audit-time">${escapeHtml(formatDate(event.created_at))}</time></div>`).join("");
}

function serverUpdateJobMarkup(job) {
  if (!job) return `<p class="empty-state">No persisted server-update job has been started.</p>`;
  const backup = job.backupSha256 ? `${String(job.backupSha256).slice(0, 16)}…` : "waiting";
  return `<div class="property-grid update-job-grid">
    ${property("Job ID", job.jobId)}
    ${property("State", job.state)}
    ${property("Requested version", job.requestedVersion)}
    ${property("Backup checksum", backup)}
    ${property("Policy source", job.policySource)}
    ${property("Updated", formatDate(job.updatedAt))}
  </div><p class="muted update-job-message">${escapeHtml(job.message)}</p>`;
}

function serverReleaseMarkup(releaseCheck, updates) {
  const daemon = updates.daemon || {};
  const release = releaseCheck?.availableRelease || null;
  const repository = releaseCheck?.policy?.repository || updates.serverRepository;
  const selfUpdate = daemon.latestSelfUpdateJob || null;
  return `<div class="property-grid">
    ${property("Installed version", releaseCheck?.installed?.version || updates.installedVersion)}
    ${property("Available version", release?.version || "not checked")}
    ${property("Repository from Register", repository)}
    ${property("Policy source", releaseCheck?.policy?.source || "not loaded")}
    ${property("Updater version", daemon.updaterVersion)}
    ${property("Updater state", daemon.available ? (daemon.busy ? "busy" : "available") : "unavailable")}
    ${property("Last self-update", selfUpdate ? `${selfUpdate.state} · ${selfUpdate.releaseVersion}` : "none")}
  </div>`;
}

async function loadSettingsView() {
  const [settings, audit] = await Promise.all([apiJson("/api/v1/settings"), apiJson("/api/v1/audit?limit=200")]);
  state.settings = settings;
  state.audit = audit.events || [];
  state.auditHasMore = Boolean(audit.hasMore);
  state.auditNextBeforeId = audit.nextBeforeId;
  const theme = readStoredJson(STORAGE.theme, DEFAULT_THEME);
  const retention = settings.retention || {};
  const backup = settings.backup || {};
  const connections = settings.connections || {};
  const clients = settings.clients || {};
  const updates = settings.updates || {};
  if (!state.serverUpdateJob && updates.daemon?.latestJob) state.serverUpdateJob = updates.daemon.latestJob;
  viewRoot.innerHTML = `
    <div class="settings-stack">
      <section class="settings-section">
        <header class="settings-header"><h2>Appearance</h2><p>Browser-specific visual and navigation preferences.</p></header>
        <div class="settings-content">
          <div class="settings-group"><h3>Color correction</h3><div class="color-controls">
            <label class="field"><span>Dark</span><input id="themeDark" type="color" value="${escapeHtml(theme.dark)}"></label>
            <label class="field"><span>Light</span><input id="themeLight" type="color" value="${escapeHtml(theme.light)}"></label>
            <label class="field"><span>Accent</span><input id="themeAccent" type="color" value="${escapeHtml(theme.accent)}"></label>
          </div><div class="dialog-actions"><button id="applyTheme" class="accent-action" type="button">Apply colors</button><button id="resetTheme" type="button">Reset</button></div></div>
          <div class="settings-group"><h3>Left menu</h3><label class="toggle-row"><span>Auto open and hide sidebar on mouse hover</span><input id="sidebarAuto" type="checkbox" ${sidebarAutoEnabled() ? "checked" : ""}></label><p class="muted">When disabled, the 242 px menu remains fixed on wide screens.</p></div>
        </div>
      </section>
      <section class="settings-section">
        <header class="settings-header"><h2>Security</h2><p>Single-operator access.</p></header>
        <div class="settings-content">
          <form id="passwordChangeForm" class="password-change-form">
            <div class="password-grid">
              <label class="field"><span>Current password</span><input name="currentPassword" type="password" autocomplete="current-password" required></label>
              <label class="field"><span>New password</span><input name="newPassword" type="password" autocomplete="new-password" minlength="12" required></label>
              <label class="field"><span>Repeat new password</span><input name="repeatPassword" type="password" autocomplete="new-password" minlength="12" required></label>
            </div>
            <div class="settings-form-actions"><button class="accent-action" type="submit">Change password</button></div>
          </form>
        </div>
      </section>
      <section class="settings-section">
        <header class="settings-header"><h2>Connections</h2><p>Automatic subscription refresh and PasarGuard integration.</p></header>
        <div class="settings-content">
          <form id="connectionSettingsForm" class="settings-inline-form">
            <label class="field"><span>Scan interval · minutes</span><input name="scanIntervalMinutes" type="number" min="1" max="15" step="1" value="${escapeAttribute(connections.scanIntervalMinutes ?? 15)}" required></label>
            <button class="accent-action" type="submit">Save cooldown</button>
          </form>
          <p class="muted">Watcher checks all sources of every active connection at least once every 15 minutes. Each connection card also has an immediate “Check all sources” action.</p>
          <div class="property-grid">
            ${property("PasarGuard domain", connections.pasarguard?.baseUrl || "Not configured in Register")}
            ${property("User template ID", connections.pasarguard?.userTemplateId || "Not configured in Register")}
            ${property("API key", connections.pasarguard?.apiKeyConfigured ? "configured in Register · hidden" : "not configured")}
            ${property("Future client heartbeat", `${clients.heartbeatIntervalSeconds ?? 60} seconds`)}
          </div>
          <p class="muted">Edit <code>pasarguard.base_url</code>, <code>pasarguard.user_template_id</code>, the write-only <code>pasarguard.api_key</code>, <code>watcher.public_sni</code> and <code>clients.heartbeat_interval_seconds</code> in Register. Public URLs are derived as <code>https://&lt;watcher.public_sni&gt;</code>.</p>
        </div>
      </section>
      <section class="settings-section">
        <header class="settings-header"><h2>Release</h2><p>Installed identity and local-update trust boundary.</p></header>
        <div class="settings-content">
          <div id="serverReleaseSummary">${serverReleaseMarkup(state.serverRelease, updates)}</div>
          <form id="serverUpdateForm" class="settings-inline-form">
            <label class="field"><span>Exact stable version</span><input name="version" type="text" inputmode="numeric" pattern="[0-9]+\\.[0-9]+\\.[0-9]+" placeholder="X.Y.Z" value="${escapeAttribute(state.serverRelease?.availableRelease?.version || "")}" required></label>
            <button id="checkServerRelease" type="button" ${updates.releaseCheckEnabled === false ? "disabled" : ""}>Check release</button>
            <button id="installServerRelease" class="accent-action" type="submit" ${updates.webInstallEnabled && !updates.daemon?.busy ? "" : "disabled"}>Install update</button>
          </form>
          <div id="serverUpdateJob" class="settings-group update-job-panel">
            <h3>Persisted update job</h3>
            ${serverUpdateJobMarkup(state.serverUpdateJob)}
          </div>
          <p class="muted">${escapeHtml(updates.webInstallReason)} The API can submit only an exact version and request ID. Repository paths come from Register; the daemon independently reloads policy, creates an encrypted backup, resolves immutable artifacts and owns Docker/rollback.</p>
        </div>
      </section>
      <section class="settings-section">
        <header class="settings-header"><h2>Backup</h2><p>Create or restore a complete SQLite system snapshot.</p></header>
        <div class="settings-content">
          <div class="settings-group"><h3>Encrypted system snapshot</h3><div class="dialog-actions"><button id="downloadBackup" class="accent-action" type="button">Download backup</button><button id="restoreBackup" type="button">Restore backup</button></div><p class="muted">${escapeHtml(backup.encryption)} format v${escapeHtml(backup.formatVersion)}; complete ${escapeHtml(backup.restoreMode)} restore. The external recovery key is required and never included. Limits: ${escapeHtml(formatBytes(backup.maxUploadBytes))} compressed, ${escapeHtml(formatBytes(backup.maxUncompressedBytes))} uncompressed, ${escapeHtml(backup.maxMemberCount)} members.</p></div>
        </div>
      </section>
      <section class="settings-section">
        <header class="settings-header"><h2>Logger</h2><p>Compact administrative action stream.</p><button id="downloadLogs" class="header-action compact-action" type="button">Download Logs Zip</button></header>
        <div class="settings-content">
          <p class="muted">Watcher retains log payloads and core telemetry for ${escapeHtml(retention.telemetryDays)} days; optional log-line retention is ${escapeHtml(retention.logDays)} days. Audit is capped at ${escapeHtml(retention.auditMaxEntries)} entries, ${escapeHtml(retention.auditRetentionDays)} days and ${escapeHtml(formatBytes(retention.auditMaxBytes))}. Container output rotates across ${escapeHtml(retention.containerFileCount)} × ${escapeHtml(formatBytes(retention.containerFileBytes))} files (${escapeHtml(formatBytes(retention.containerTotalBytes))} total). Export is limited to ${escapeHtml(formatBytes(retention.exportMaxCompressedBytes))} compressed, ${escapeHtml(formatBytes(retention.exportMaxUncompressedBytes))} uncompressed and ${escapeHtml(retention.exportMaxSeconds)} seconds. The strictest applicable limit wins.</p>
          <div id="loggerStream" class="logger-stream">${auditRows(state.audit)}</div>
          <div class="settings-form-actions"><button id="loadOlderAudit" type="button" ${state.auditHasMore ? "" : "disabled"}>${state.auditHasMore ? "Load older events" : "End of retained audit"}</button></div>
        </div>
      </section>
    </div>`;
  bindSettingsActions();
}

function bindSettingsActions() {
  ["themeDark", "themeLight", "themeAccent"].forEach((id) => document.querySelector(`#${id}`).addEventListener("input", () => applyTheme({ dark: document.querySelector("#themeDark").value, light: document.querySelector("#themeLight").value, accent: document.querySelector("#themeAccent").value })));
  document.querySelector("#applyTheme").addEventListener("click", () => {
    applyTheme({ dark: document.querySelector("#themeDark").value, light: document.querySelector("#themeLight").value, accent: document.querySelector("#themeAccent").value }, true);
    showNotice("Appearance colors saved", "success");
  });
  document.querySelector("#resetTheme").addEventListener("click", () => {
    applyTheme(DEFAULT_THEME, true);
    document.querySelector("#themeDark").value = DEFAULT_THEME.dark;
    document.querySelector("#themeLight").value = DEFAULT_THEME.light;
    document.querySelector("#themeAccent").value = DEFAULT_THEME.accent;
    showNotice("Appearance colors reset", "success");
  });
  document.querySelector("#sidebarAuto").addEventListener("change", (event) => {
    localStorage.setItem(STORAGE.sidebarAuto, String(event.target.checked));
    applySidebarPreference();
    showNotice("Sidebar mode saved", "success");
  });
  document.querySelector("#passwordChangeForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const submit = form.querySelector("button[type=submit]");
    const formData = new FormData(form);
    const payload = {
      currentPassword: String(formData.get("currentPassword") || ""),
      newPassword: String(formData.get("newPassword") || ""),
      repeatPassword: String(formData.get("repeatPassword") || ""),
    };
    if (payload.newPassword !== payload.repeatPassword) {
      showNotice("New passwords do not match", "error");
      return;
    }
    submit.disabled = true;
    submit.textContent = "Changing...";
    try {
      await apiJson("/api/v1/settings/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      passwordInput.value = payload.newPassword;
      form.reset();
      showNotice("Password changed", "success");
    } catch (error) {
      showNotice(`Password was not changed: ${error.message}`, "error");
    } finally {
      submit.disabled = false;
      submit.textContent = "Change password";
    }
  });
  document.querySelector("#connectionSettingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.reportValidity()) return;
    const submit = form.querySelector("button[type=submit]");
    const scanIntervalMinutes = Number(form.elements.scanIntervalMinutes.value);
    submit.disabled = true;
    submit.textContent = "Saving...";
    try {
      const result = await apiJson("/api/v1/settings/connections", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanIntervalMinutes }),
      });
      form.elements.scanIntervalMinutes.value = result.scanIntervalMinutes;
      showNotice("Connection scan interval saved", "success");
    } catch (error) {
      showNotice(`Connection settings were not saved: ${error.message}`, "error");
    } finally {
      submit.disabled = false;
      submit.textContent = "Save cooldown";
    }
  });
  document.querySelector("#checkServerRelease").addEventListener("click", checkServerRelease);
  document.querySelector("#serverUpdateForm").addEventListener("submit", startServerUpdate);
  document.querySelector("#downloadBackup").addEventListener("click", (event) => downloadFile("/api/v1/backups/download", "loki-watcher-backup.zip", "Backup archive prepared", event.currentTarget));
  document.querySelector("#restoreBackup").addEventListener("click", () => backupFileInput.click());
  document.querySelector("#downloadLogs").addEventListener("click", (event) => downloadFile("/api/v1/logs/download", "loki-watcher-logs.zip", "Logs archive prepared", event.currentTarget));
  document.querySelector("#loadOlderAudit").addEventListener("click", async (event) => {
    if (!state.auditHasMore || !state.auditNextBeforeId) return;
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "Loading...";
    try {
      const page = await apiJson(`/api/v1/audit?limit=200&beforeId=${encodeURIComponent(state.auditNextBeforeId)}`);
      state.audit.push(...(page.events || []));
      state.auditHasMore = Boolean(page.hasMore);
      state.auditNextBeforeId = page.nextBeforeId;
      document.querySelector("#loggerStream").innerHTML = auditRows(state.audit);
      button.disabled = !state.auditHasMore;
      button.textContent = state.auditHasMore ? "Load older events" : "End of retained audit";
    } catch (error) {
      button.disabled = false;
      button.textContent = "Load older events";
      showNotice(`Older audit events could not be loaded: ${error.message}`, "error");
    }
  });
}

async function checkServerRelease(event) {
  const button = event.currentTarget;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Checking...";
  try {
    state.serverRelease = await apiJson("/api/v1/server-updates/check");
    const updates = state.settings?.updates || {};
    document.querySelector("#serverReleaseSummary").innerHTML = serverReleaseMarkup(state.serverRelease, updates);
    const versionInput = document.querySelector("#serverUpdateForm input[name=version]");
    versionInput.value = state.serverRelease.availableRelease?.version || "";
    showNotice(state.serverRelease.updateAvailable ? "Watcher update is available" : "Watcher is already on the newest stable release", "success");
  } catch (error) {
    showNotice(`Release check failed: ${error.message}`, "error");
  } finally {
    button.disabled = state.settings?.updates?.releaseCheckEnabled === false;
    button.textContent = original;
  }
}

async function startServerUpdate(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const version = form.elements.version.value.trim();
  const confirmed = await confirmAction({
    title: "Install Watcher server update",
    copy: `<p>Install exact stable version <strong>${escapeHtml(version)}</strong>?</p><p>The privileged daemon will create and persist an encrypted backup before release resolution, pull immutable images, replace the registered Watcher project and roll runtime plus data back if health fails. The dashboard may be temporarily unavailable while containers are replaced.</p>`,
    confirmLabel: "Install update",
  });
  if (!confirmed) return;
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  button.textContent = "Submitting...";
  const requestId = `web-${crypto.randomUUID()}`;
  try {
    const result = await apiJson("/api/v1/server-updates/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version, requestId }),
    });
    state.serverUpdateJob = result.job;
    document.querySelector("#serverUpdateJob").innerHTML = `<h3>Persisted update job</h3>${serverUpdateJobMarkup(state.serverUpdateJob)}`;
    showNotice(result.idempotent ? "Existing update job loaded" : "Update job accepted", "success");
    pollServerUpdateJob(requestId);
  } catch (error) {
    button.disabled = false;
    showNotice(`Update request failed: ${error.message}`, "error");
  } finally {
    button.textContent = "Install update";
  }
}

async function pollServerUpdateJob(requestId) {
  if (state.serverUpdatePolling) return;
  state.serverUpdatePolling = true;
  const terminal = new Set(["COMPLETED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED"]);
  let transientFailures = 0;
  try {
    for (let attempt = 0; attempt < 300; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
      try {
        const job = await apiJson(`/api/v1/server-updates/jobs/${encodeURIComponent(requestId)}`);
        transientFailures = 0;
        state.serverUpdateJob = job;
        const panel = document.querySelector("#serverUpdateJob");
        if (panel) panel.innerHTML = `<h3>Persisted update job</h3>${serverUpdateJobMarkup(job)}`;
        if (terminal.has(job.state)) {
          const type = job.state === "COMPLETED" ? "success" : "error";
          showNotice(`Server update finished: ${job.state}`, type);
          const button = document.querySelector("#installServerRelease");
          if (button) button.disabled = false;
          return;
        }
      } catch {
        transientFailures += 1;
        const panel = document.querySelector("#serverUpdateJob .update-job-message");
        if (panel) panel.textContent = "Watcher is temporarily unreachable while the updater replaces containers; polling persisted state continues.";
        if (transientFailures > 45) throw new Error("Updater status remained unreachable after container replacement");
      }
    }
    throw new Error("Update job exceeded the UI polling window");
  } catch (error) {
    showNotice(`Update status polling stopped: ${error.message}`, "error");
  } finally {
    state.serverUpdatePolling = false;
    const button = document.querySelector("#installServerRelease");
    if (button) button.disabled = false;
  }
}

async function downloadFile(path, fallbackName, successMessage, button = null) {
  const original = button?.textContent;
  if (button) { button.disabled = true; button.textContent = "Preparing..."; }
  try {
    const response = await apiFetch(path);
    if (!response.ok) throw new Error(`Download failed with status ${response.status}`);
    const blob = await response.blob();
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="([^"]+)"/i);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = match ? match[1] : fallbackName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(link.href);
    showNotice(successMessage, "success");
  } catch (error) {
    showNotice(`${successMessage} failed: ${error.message}`, "error");
  } finally {
    if (button) { button.disabled = false; button.textContent = original; }
  }
}

async function restoreBackup(file) {
  backupFileInput.value = "";
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".zip")) {
    showNotice("Select a ZIP backup archive and try again", "error");
    return;
  }
  const confirmed = await confirmAction({
    title: "Restore system snapshot",
    confirmLabel: "Restore",
    copy: `<p><strong>${escapeHtml(file.name)}</strong> will globally replace Watcher server data.</p><p>Installed external clients and proxy servers remain untouched. Client identities are not deny-listed. The operation can be reversed only if you first download the current backup.</p>`,
  });
  if (!confirmed) return;
  showNotice("Backup restore started", "info");
  try {
    const response = await apiFetch("/api/v1/backups/upload", { method: "POST", headers: { "Content-Type": "application/zip" }, body: file });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Restore failed with status ${response.status}`);
    showNotice("Backup restored", "success");
    await navigate("settings", { force: true });
  } catch (error) {
    showNotice(`Backup was not restored: ${error.message}`, "error");
  }
}

const documentationSections = [
  { id: "analytics-guide", title: "Analytics reports", body: `<p>Analytics stores two client-generated JSON report types: <strong>Fail analytics</strong> for failed background connection checks and <strong>Full analytics</strong> for the scheduled normal Traffic Lab pipeline.</p><ul><li>Use the Analytics menu under Clients to filter reports by type or client, inspect the retained JSON and download one report.</li><li>Reports are accepted through the signed <code>POST /api/v1/analytics/batch</code> endpoint. The client removes a local outbox item only after its report ID is acknowledged.</li><li>Dashboard reads use <code>GET /api/v1/analytics</code> and <code>GET /api/v1/analytics/{reportId}</code>.</li><li>Retention uses the strictest of the configured 30-day default and global byte cap.</li></ul><div class="doc-note">Heartbeat is intentionally excluded from Analytics. Online/offline state remains on the client card in Clients.</div>` },
  { id: "overview", title: "Overview and boundaries", body: `<p>Cake Proxy Watcher is the operator control plane for Windows and Android client enrollment, telemetry, issued subscription records, update metadata, mutable key/value records and recovery.</p><ul><li>The API stores operational state in SQLite.</li><li>The web container serves the dashboard; a separately managed production reverse proxy routes dashboard and API traffic.</li><li>The worker applies retention rules; the backup service creates periodic snapshots.</li></ul><div class="doc-note">Watcher is not in the client traffic path. An enrolled client and its already installed proxy configuration keep working if the API, dashboard or subscription scanner is unavailable. Reports and commands resume when Watcher returns.</div>` },
  { id: "quick-start", title: "Quick start", body: `<p>Open the dashboard address, enter the operator username and password, then use the left menu. Dashboard is the system summary; Connections contains stable client-facing subscriptions and their sources; Clients contains enrolled installations; Register contains mutable values; Settings contains appearance, password, connection scan interval, backups and logs.</p><h3>Navigation</h3><ul><li>Drag main menu items to save their order in this browser.</li><li>Use Documentation and Log out at the bottom of the sidebar.</li><li>The refresh action reloads only the current view.</li></ul>` },
  { id: "dashboard-guide", title: "Dashboard metrics", body: `<p>Dashboard reports API-host CPU load, RAM and disk utilization, activated client count, issued connection count and cumulative connected-device network activity reported by clients.</p><ul><li>Activated clients are unique enrolled client identities.</li><li>The online window is derived from the heartbeat interval in Register with retry tolerance.</li><li>Traffic is total activity across active device adapters while the client reports connected; it is not an exact Xray or proxy byte counter.</li><li>Issued connections are rows in the Watcher connection register.</li><li>Drag metric cards to save a browser-specific order.</li></ul>` },
  { id: "connections-guide", title: "Connections, PasarGuard and scheduled refresh", body: `<p>A connection has a permanent ID, creation and update timestamps, one opaque Cake Proxy subscription URL and one or more sources. Its origin is derived as <code>https://&lt;watcher.public_sni&gt;</code>. There is no manual/PasarGuard connection type split. Direct VLESS URIs can always be pasted while editing a connection; integrations are added from “Set new connection”.</p><h3>PasarGuard workflow</h3><ol><li>Configure <code>pasarguard.base_url</code>, <code>pasarguard.user_template_id</code> and the write-only <code>pasarguard.api_key</code> in Register.</li><li>Create a connection, open its card and select Set new connection → PasarGuard.</li><li>Watcher calls the registered machine interface, creates the upstream user with the permanent ID and caches its returned links.</li><li>Give consumers the Cake Proxy URL, not the upstream URL. Reset rotates upstream credentials while preserving the permanent ID and Cake Proxy URL.</li></ol><h3>Refresh</h3><p>Watcher refreshes and aggregates every active source at least once every 15 minutes. “Check all sources” performs the same operation immediately. If a source is unavailable, its last working values remain available and the connection is marked degraded.</p><div class="doc-note">The Cake Proxy URL is a machine subscription endpoint: it returns Base64 by default and one URI per line with <code>?format=raw</code>. Treat the opaque token as a secret.</div>` },
  { id: "clients-guide", title: "Clients, enrollment and offline behavior", body: `<p>A client creates a random 32-byte secret and sends a signed enrollment request containing its client ID, display ID and device inventory. The server accepts the first enrollment and will not replace an existing secret with a different one. Later telemetry, command polling and update-state reports use HMAC-SHA256 signatures over method, path, timestamp and body hash.</p><h3>Client card</h3><ul><li>The platform is reported as Windows or Android. Every heartbeat refreshes the device/app version, proxy state, routing, sanitized connection inventory, log consent and connected-device network counter.</li><li>Original IP is the first enrollment address; Last IP, region and provider describe the latest authenticated client contact.</li><li>Proxy state and inventory are the latest reported snapshot. The separate online badge is based on Last seen and the Register heartbeat interval.</li><li>Load event stream reads retained telemetry; Collect now and Check updates enqueue commands.</li><li>Deleting a card removes server-side events and commands. It does not uninstall, revoke or block the client application; the client can enroll again after its server record is removed.</li></ul><h3>When Watcher is down</h3><p>The client continues its local proxy lifecycle. Telemetry is retried through its bounded local queue and commands wait until communication is restored, preventing Watcher downtime from becoming a connectivity outage.</p>` },
  { id: "register-guide", title: "Register", body: `<p>Register contains only runtime values that may legitimately change. Secret rows are write-only in the dashboard: their value is stored in the database but API responses expose only configured/not configured.</p><ul><li><code>github.repository</code> is the client release repository in strict <code>owner/repository</code> form, normally <code>psewdon1m-loki/client</code>. Clients receive this repository on enrollment and every heartbeat; do not enter a browser URL or append <code>.git</code>.</li><li><code>updates.manifest_public_key_pem</code> optionally enables mandatory RSA/SHA-256 verification of <code>manifest.json.sig</code>.</li><li><code>watcher.public_sni</code> is the public hostname; Watcher derives every public URL as HTTPS from it.</li><li><code>watcher.server_repository</code> is the single repository for Watcher server releases and updater self-update artifacts.</li><li><code>pasarguard.base_url</code> is the path-free HTTP(S) API origin; <code>pasarguard.user_template_id</code> is the numeric template; <code>pasarguard.api_key</code> is the masked integration secret.</li><li><code>clients.heartbeat_interval_seconds</code> defines the future normal client heartbeat, command-poll and telemetry contact interval; the server constrains it to 15–86400 seconds.</li></ul><p><code>latest</code>, <code>stable</code> and the expected rule-set IDs are internal invariants rather than editable Register values. Rule-set IDs tell the update-manifest builder which named ZIP assets to discover and expose to Windows clients.</p>` },
  { id: "settings-guide", title: "Settings", body: `<h3>Appearance and Security</h3><p>Colors/sidebar behavior are browser-local. Security contains only password change; it takes effect immediately and stores only a salted PBKDF2 hash override.</p><h3>Connections and Release</h3><p>The connection scan interval accepts 1–15 minutes, so background checks can never be less frequent than required. PasarGuard status shows the Register domain/template and only whether the server secret exists—it never exposes that secret. Release shows installed/available versions, Register repository policy, local updater availability, current persisted job and rollback outcome.</p><h3>Backup and Logger</h3><p>Backup uses complete replace semantics and requires explicit confirmation. Logger loads 200 bounded audit rows initially, supports cursor-based older pages and produces a sanitized, manifested ZIP export.</p>` },
  { id: "observability-guide", title: "Observability, audit and log export", body: `<p>Operational container output, transactional audit events and client telemetry have separate retention boundaries. Container JSON logs rotate at 3 × 10 MiB for API/web and 2 × 5 MiB for worker/backup.</p><ul><li>Audit events contain a unique event ID, UTC time, outcome/severity, actor and target types, request ID, transport method, bounded context and optional structured error.</li><li>Recursive central redaction removes passwords, tokens, authorization/cookie values, private keys, subscription tokens and credential-bearing connection URIs before export.</li><li>Audit retention uses the strictest of 10,000 entries, 30 days and 64 MiB.</li><li>The ZIP is generated incrementally in a private spool. It contains manifest.json, the complete retained audit/telemetry stream in events.jsonl, errors.json and README.txt, and is bounded by compressed, uncompressed and duration limits.</li></ul><div class="doc-note">The log-download audit event is recorded after the archive snapshot; manifest.json states its cutoff and that the export event is intentionally not included.</div>` },
  { id: "updates-guide", title: "CI, releases and local updates", body: `<h3>Client updates</h3><p>The public manifest endpoint combines client release metadata, installer/rule-set assets and Watcher routing information. GitHub failures do not block dashboard login because the last cached snapshot is used.</p><h3>Watcher server releases</h3><p>Pull requests and main pushes run tests, syntax checks, Compose validation and container health smoke tests. Stable <code>vX.Y.Z</code> tags build API/web/worker images once, publish them by immutable OCI digest with SBOM/provenance, smoke those exact digests and emit a checksummed release bundle and narrow manifest. CI actions, Python wheels and the container base are immutable-reference pinned.</p><h3>Host updater</h3><p>Production install registers Watcher with one root-owned systemd daemon. API connects only to its mode-0660 Unix socket and submits an exact version plus request ID; it never receives Docker access. The daemon reloads the root profile and Register/LKG repository policy, creates and checksums an encrypted backup, resolves the release independently, verifies the exact bundle/Compose/images/minimum updater, pulls before mutation and performs health-gated runtime plus data rollback. Persisted jobs distinguish <code>FAILED</code>, <code>ROLLED_BACK</code> and <code>ROLLBACK_FAILED</code>; interrupted jobs are reconciled and state retention is 20 entries/30 days.</p><h3>Commands</h3><p><code>sudo vpn-enus-watcher update-check</code>, <code>update --version X.Y.Z</code> and <code>update-job ID</code> use the same daemon. Explicit <code>updater-self-update --release-version X.Y.Z</code> runs a separate transient systemd helper, keeps the previous updater, restarts/polls socket health and restores/restarts the previous files on failure.</p><div class="doc-note">The server release manifest checksum binds bytes but is not an asymmetric publisher signature. GitHub HTTPS/repository controls and immutable image digests remain the publisher trust boundary.</div>` },
  { id: "privacy-retention", title: "Privacy and retention", body: `<p>Watcher collects operational data required for fleet support: client/display identifiers, client-generated authentication secret, device and app metadata, reported connection status and sanitized connection inventory, cumulative/delta traffic counters, timestamps, source address with derived region/provider, update state and bounded event payloads.</p><ul><li>Core telemetry and optional log payloads are retained for 30 days by default; one batch is limited to 200 events and one stored event to 64 KiB.</li><li>Administrative audit data is limited by age, entry count and total encoded size; the strictest limit wins.</li><li>Client records, issued subscriptions and Register values remain until an operator deletes or restores them.</li><li>Subscription URLs/tokens and enrollment secrets exist in the live database but are centrally redacted from logs. In backup archives they exist only inside AES-GCM ciphertext.</li><li>Password replacements are stored only as salted PBKDF2 hashes. Neither <code>.env</code> nor the external backup key is included in backups.</li></ul><div class="doc-note">A deployment operator is responsible for TLS termination, recovery-key escrow, restricted backup access and an appropriate public privacy notice.</div>` },
  { id: "backup-recovery", title: "Backup and recovery", body: `<p>Manual and scheduled backups use the same format-v2 recovery contract: manifest.json, encrypted data/watcher.db.enc and README.txt. AES-256-GCM protects state; manifest HMAC, per-member SHA-256, uncompressed size and table record counts are verified before mutation.</p><ul><li>Compressed, uncompressed, per-member, member-count, duplicate-name, traversal, link and compression-ratio limits are enforced.</li><li>Restore is complete replacement. It validates schema, SQLite integrity, foreign keys and all record counts first, then creates and verifies a fresh encrypted pre-restore snapshot.</li><li>SQLite backup applies the staged database transactionally. Failure or failed health invariants restores the pre-restore database.</li><li>The external <code>LOKI_WATCHER_BACKUP_ENCRYPTION_KEY</code> is required in disaster recovery and is never stored in the archive.</li><li>Scheduled archives are bounded by 30 days, the newest 20 files and a 2 GiB directory budget.</li></ul>` },
  { id: "pasarguard-api", title: "PasarGuard and public subscription API", body: `<div class="doc-table-wrap"><table><thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead><tbody><tr><td>GET</td><td><code>/sub/{opaque-token}</code></td><td>Stable Base64 machine subscription. <code>?format=raw</code> returns one inner URI per line; <code>?format=json</code> returns the Loki client metadata and configurations.</td></tr><tr><td>POST</td><td><code>/api/v1/client/connections/initialize</code></td><td>Signed and idempotent client initialization: allocate a connection, provision PasarGuard and return the stable subscription URL.</td></tr><tr><td>POST</td><td><code>/api/v1/connections/{id}/pasarguard/provision</code></td><td>Add or refresh the PasarGuard source for an existing connection.</td></tr><tr><td>POST</td><td><code>/api/v1/connections/{id}/pasarguard/reset</code></td><td>Rotate upstream credentials while preserving the Watcher identity and URL.</td></tr><tr><td>POST</td><td><code>/api/v1/connections/{id}/scan</code></td><td>Refresh and aggregate every active source while retaining last-good data on failure.</td></tr></tbody></table></div><p>Dashboard operations use operator authentication. Client initialization uses the enrolled client's HMAC identity. Watcher sends the PasarGuard API key only to the exact registered origin. Public subscription tokens are bearer credentials.</p>` },
  { id: "api-reference", title: "API reference", body: `<div class="doc-table-wrap"><table><thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead><tbody><tr><td>GET</td><td><code>/health</code></td><td>Service health without dashboard authentication.</td></tr><tr><td>GET</td><td><code>/api/v1/dashboard</code></td><td>Host and fleet metrics.</td></tr><tr><td>GET</td><td><code>/api/v1/clients[/id]</code></td><td>Client list or detail and retained events.</td></tr><tr><td>POST</td><td><code>/api/v1/enroll</code></td><td>Signed client enrollment and current Register-driven contact interval.</td></tr><tr><td>POST</td><td><code>/api/v1/client/connections/initialize</code></td><td>Signed, idempotent managed-connection creation for an enrolled client.</td></tr><tr><td>POST</td><td><code>/api/v1/telemetry/batch</code></td><td>Signed client telemetry batch.</td></tr><tr><td>GET/POST</td><td><code>/api/v1/commands/id</code></td><td>Signed client polling or operator command creation.</td></tr><tr><td>GET/POST/PUT/DELETE</td><td><code>/api/v1/connections</code></td><td>Connection CRUD; direct VLESS values are part of the base connection.</td></tr><tr><td>GET/POST/PUT/DELETE</td><td><code>/api/v1/register</code></td><td>Key/value Register CRUD.</td></tr><tr><td>GET</td><td><code>/api/v1/settings</code></td><td>Safe dashboard settings snapshot.</td></tr><tr><td>GET/POST</td><td><code>/api/v1/server-updates/check|jobs</code></td><td>Informational release discovery and exact-version handoff to the host updater.</td></tr><tr><td>GET</td><td><code>/api/v1/updater/policy</code></td><td>Local-control-token-only checksummed repository policy for the registered updater.</td></tr><tr><td>PUT</td><td><code>/api/v1/settings/connections</code></td><td>Save the mandatory 1–15 minute scan interval.</td></tr><tr><td>POST</td><td><code>/api/v1/settings/password</code></td><td>Change operator password.</td></tr><tr><td>GET/POST</td><td><code>/api/v1/backups/download|upload</code></td><td>Download or restore database backup.</td></tr><tr><td>GET</td><td><code>/api/v1/audit</code></td><td>Administrative audit stream.</td></tr></tbody></table></div><p>Dashboard routes use HTTP Basic authentication. Client routes use timestamped HMAC signatures and reject requests outside the allowed clock-skew window. The private updater policy route requires the local service token and is intended only for the registered loopback updater.</p>` },
  { id: "deployment-guide", title: "Bootstrap and deployment", body: `<p>Production uses one immutable-revision HTTPS bootstrap command. It asks for the operator username, hidden password and public SNI (or accepts their environment variables for automation), installs supported prerequisites, creates the protected configuration, starts the exact release and waits for health.</p><ul><li>Bootstrap selects the highest stable non-draft semantic release, validates manifest role/tag/version, allow-listed hosts, bundle size/SHA-256 and safe archive paths, and refuses to overwrite an existing install.</li><li>Prepare generates recovery and local-control secrets without printing them and writes mode-0600 configuration.</li><li>Install rejects placeholders, weak passwords, non-HTTPS public URLs, invalid ports and mutable images; it installs/health-checks the restricted root updater service, registers Watcher with its own token, validates Compose, pulls exact digests, starts detached and gates success on bounded loopback health.</li><li>Containers run as non-root, drop all capabilities, set no-new-privileges, use read-only root filesystems/tmpfs and bind application ports to loopback. Production nginx remains host-managed and must pass a separate certificate/HTTPS health check.</li><li>For source development, use <code>docker compose up -d --build</code>. Foreground <code>docker compose up</code> intentionally remains attached. A Windows source stack intentionally reports the Linux host updater as unavailable.</li></ul>` },
  { id: "troubleshooting", title: "Troubleshooting", body: `<h3>Login button or authentication</h3><p>Verify API health, use the configured username/password and reload after a deployment so the browser receives the latest JavaScript. After password change, the current dashboard session switches to the new credential automatically.</p><h3>Subscription has too few inner connections</h3><p>Run a manual rescan, inspect Last scan and Scan result, then confirm the response contains supported URI schemes. Base64 padding and JSON nesting are handled automatically. A TLS error applies only when verification is enabled for that row.</p><h3>Client appears offline</h3><p>Check the client's clock, HMAC secret continuity and API reachability. Already configured proxy traffic can still work while telemetry is offline.</p><h3>Stack seems stuck after startup</h3><p>If the terminal shows “Attaching to …”, Compose is running in foreground mode, not hung. Use <code>docker compose up -d</code> for detached operation.</p>` },
];

function renderDocumentationView() {
  viewRoot.innerHTML = `
    <section class="documentation-workspace">
      <aside class="documentation-nav"><div class="documentation-nav-inner"><label class="search-unit"><span>Search</span><input id="documentationSearch" aria-label="Search documentation" placeholder="Section or text"></label><nav id="documentationLinks" class="documentation-links"><strong>Watcher guide</strong>${documentationSections.map((section) => `<a href="#${section.id}">${escapeHtml(section.title)}</a>`).join("")}</nav></div></aside>
      <article class="documentation-article"><header class="documentation-intro"><span class="kicker">Cake Proxy Watcher</span><h2>Operator documentation</h2><p>Complete operational reference for the Watcher control plane.</p></header><div id="documentationSections">${documentationSections.map((section) => `<section id="${section.id}" class="doc-section" data-doc-text="${escapeHtml(`${section.title} ${section.body.replace(/<[^>]*>/g, " ")}`.toLowerCase())}"><h2>${escapeHtml(section.title)}</h2>${section.body}</section>`).join("")}</div><p id="documentationEmpty" class="empty-state hidden">No documentation sections match this search.</p></article>
    </section>`;
  document.querySelector("#documentationSearch").addEventListener("input", (event) => {
    const query = event.target.value.trim().toLowerCase();
    let visible = 0;
    document.querySelectorAll(".doc-section").forEach((section) => {
      const matches = !query || section.dataset.docText.includes(query);
      section.classList.toggle("hidden", !matches);
      const link = document.querySelector(`#documentationLinks a[href="#${section.id}"]`);
      if (link) link.classList.toggle("hidden", !matches);
      if (matches) visible += 1;
    });
    document.querySelector("#documentationEmpty").classList.toggle("hidden", visible > 0);
  });
}

function restoreNavigationOrder() {
  const stored = readStoredJson(STORAGE.navigation, NAV_KEYS);
  const storedValid = Array.isArray(stored) && stored.length === NAV_KEYS.length && NAV_KEYS.every((key) => stored.includes(key));
  const valid = storedValid ? stored : [...NAV_KEYS];
  valid.forEach((key) => {
    const item = primaryNav.querySelector(`[data-view="${key}"]`);
    if (item) primaryNav.appendChild(item);
  });
  updateNavigationPositions();
}

function updateNavigationPositions() {
  primaryNav.querySelectorAll(".nav-item").forEach((item, index) => {
    item.querySelector(".nav-position").textContent = String(index + 1).padStart(2, "0");
  });
}

function setupNavigation() {
  primaryNav.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => navigate(item.dataset.view));
    item.addEventListener("dragstart", () => {
      state.draggingNav = item;
      state.suppressNavigation = true;
      item.classList.add("dragging");
    });
    item.addEventListener("dragover", (event) => {
      event.preventDefault();
      if (!state.draggingNav || state.draggingNav === item) return;
      primaryNav.querySelectorAll(".nav-item").forEach((row) => row.classList.remove("insert-before", "insert-after"));
      const before = event.clientY < item.getBoundingClientRect().top + item.getBoundingClientRect().height / 2;
      item.classList.add(before ? "insert-before" : "insert-after");
    });
    item.addEventListener("drop", (event) => {
      event.preventDefault();
      if (!state.draggingNav || state.draggingNav === item) return;
      primaryNav.insertBefore(state.draggingNav, item.classList.contains("insert-before") ? item : item.nextSibling);
      updateNavigationPositions();
      localStorage.setItem(STORAGE.navigation, JSON.stringify([...primaryNav.children].map((row) => row.dataset.view)));
      showNotice("Navigation order saved", "success");
    });
    item.addEventListener("dragend", () => {
      primaryNav.querySelectorAll(".nav-item").forEach((row) => row.classList.remove("dragging", "insert-before", "insert-after"));
      state.draggingNav = null;
      window.setTimeout(() => { state.suppressNavigation = false; }, 0);
    });
  });
}

function setupDialogDragging() {
  let dragState = null;
  dialogHeader.addEventListener("pointerdown", (event) => {
    if (event.target.closest("button")) return;
    const rect = dialog.getBoundingClientRect();
    dragState = { offsetX: event.clientX - rect.left, offsetY: event.clientY - rect.top };
    dialogHeader.setPointerCapture(event.pointerId);
  });
  dialogHeader.addEventListener("pointermove", (event) => {
    if (!dragState) return;
    const maxLeft = Math.max(8, window.innerWidth - dialog.offsetWidth - 8);
    const maxTop = Math.max(8, window.innerHeight - dialog.offsetHeight - 8);
    dialog.style.position = "fixed";
    dialog.style.left = `${Math.min(maxLeft, Math.max(8, event.clientX - dragState.offsetX))}px`;
    dialog.style.top = `${Math.min(maxTop, Math.max(8, event.clientY - dragState.offsetY))}px`;
  });
  dialogHeader.addEventListener("pointerup", (event) => {
    if (dragState) dialogHeader.releasePointerCapture(event.pointerId);
    dragState = null;
  });
}

loginForm.addEventListener("submit", signIn);
usernameInput.addEventListener("input", updateLoginButton);
passwordInput.addEventListener("input", updateLoginButton);
pageRefresh.addEventListener("click", () => navigate(state.activeView, { force: true }));
document.querySelector("#documentationButton").addEventListener("click", () => navigate("documentation"));
document.querySelector("#logoutButton").addEventListener("click", () => {
  usernameInput.value = "";
  passwordInput.value = "";
  sidebar.classList.remove("open");
  showLogin();
  showNotice("Logged out", "info");
});
document.querySelector("#mobileMenuButton").addEventListener("click", () => sidebar.classList.toggle("open"));
document.querySelector("#dialogClose").addEventListener("click", () => closeDialog());
overlay.addEventListener("click", (event) => { if (event.target === overlay) closeDialog(); });
backupFileInput.addEventListener("change", () => restoreBackup(backupFileInput.files[0]));
document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !overlay.classList.contains("hidden")) closeDialog(); });

applyTheme(readStoredJson(STORAGE.theme, DEFAULT_THEME));
applySidebarPreference();
restoreNavigationOrder();
setupNavigation();
setupDialogDragging();
applySmartHover(document);
loginForm.reset();
usernameInput.value = "";
passwordInput.value = "";
updateLoginButton();
showLogin();
checkAvailability();
window.setInterval(checkAvailability, 5000);
