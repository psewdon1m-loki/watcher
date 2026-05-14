const api = window.location.port === "18081" ? "http://127.0.0.1:18080" : "";
const loginScreen = document.querySelector("#loginScreen");
const appScreen = document.querySelector("#appScreen");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const loginButton = document.querySelector("#login");
const loginStatus = document.querySelector("#loginStatus");
const refreshButton = document.querySelector("#refresh");
const requestDataButton = document.querySelector("#requestData");
const downloadBackupButton = document.querySelector("#downloadBackup");
const uploadBackupInput = document.querySelector("#uploadBackup");
const statusNode = document.querySelector("#status");
const dashboardNode = document.querySelector("#dashboard");
const updatesNode = document.querySelector("#updates");
const clientsNode = document.querySelector("#clients");
const detailNode = document.querySelector("#detail");
const contextMenu = document.querySelector("#contextMenu");
const deleteClientButton = document.querySelector("#deleteClient");
let contextClientId = null;

function clearStoredAuth() {
  localStorage.removeItem("lokiWatcherUser");
  localStorage.removeItem("lokiWatcherPassword");
}

function escapeHtml(text) {
  const value = text === null || text === undefined || text === "" ? "-" : String(text);
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function bytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let current = Number(value || 0);
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  return `${current.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function percent(value) {
  return value === null || value === undefined ? "-" : `${value}%`;
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><span>${escapeHtml(value)}</span></div>`;
}

function optionalMetric(label, value) {
  return value === null || value === undefined || value === "" ? "" : metric(label, value);
}

function countList(items, emptyText = "no data") {
  if (!Array.isArray(items) || items.length === 0) {
    return `<p class="empty small">${escapeHtml(emptyText)}</p>`;
  }
  return items.map((item) => metric(item.value, item.count)).join("");
}

function authHeader() {
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username && !password) {
    return {};
  }
  return { Authorization: `Basic ${btoa(`${username}:${password}`)}` };
}

function showLogin(message = "") {
  loginScreen.classList.remove("hidden");
  appScreen.classList.add("hidden");
  loginStatus.textContent = message;
  loginStatus.classList.toggle("error", Boolean(message));
}

function showApp() {
  loginScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
  loginStatus.textContent = "";
}

async function apiFetch(path, options = {}) {
  const headers = { ...(options.headers || {}), ...authHeader() };
  const response = await fetch(`${api}${path}`, { ...options, headers });
  if (response.status === 401) {
    passwordInput.value = "";
    showLogin("wrong username or password");
    passwordInput.focus();
    throw new Error("wrong username or password");
  }
  return response;
}

function renderDashboard(data) {
  const system = data.system || {};
  const ram = system.ram || {};
  const disk = system.disk || {};
  dashboardNode.innerHTML = `
    <article>
      <strong>Total Traffic</strong>
      <span>${escapeHtml(bytes(system.totalTrafficBytes))}</span>
    </article>
    <article>
      <strong>CPU Usage</strong>
      <span>${escapeHtml(percent(system.cpuUsagePercent))}</span>
    </article>
    <article>
      <strong>RAM Usage</strong>
      ${metric("used", bytes(ram.usedBytes))}
      ${metric("total", bytes(ram.totalBytes))}
      ${metric("percent", percent(ram.percent))}
    </article>
    <article>
      <strong>Server Disk</strong>
      ${metric("used", bytes(disk.usedBytes))}
      ${metric("total", bytes(disk.totalBytes))}
      ${metric("percent", percent(disk.percent))}
    </article>
    <article>
      <strong>Installed Clients</strong>
      <span>${escapeHtml(system.installedClients || 0)}</span>
    </article>
  `;
}

function renderUpdates(updates) {
  const watcher = updates.watcher || {};
  const installer = updates.installer || {};
  const ruleSets = Array.isArray(updates.ruleSets) ? updates.ruleSets : [];
  updatesNode.innerHTML = `
    <div class="infoGrid">
      ${metric("client version", updates.version)}
      ${metric("channel", updates.channel)}
      ${metric("published", updates.publishedAt)}
      ${metric("github repo", updates.githubRepository)}
      ${metric("github release", updates.githubRelease)}
      ${metric("installer sha256", installer.sha256)}
      ${metric("watcher endpoint", watcher.endpoint)}
      ${metric("watcher sni", watcher.sni)}
    </div>
    <h3>rule sets</h3>
    <section class="ruleSets">
      ${ruleSets.map((ruleSet) => `
        <article>
          <strong>${escapeHtml(ruleSet.id)}</strong>
          ${metric("status", ruleSet.status)}
          ${metric("version", ruleSet.version)}
          ${optionalMetric("sha256", ruleSet.sha256)}
          ${optionalMetric("url", ruleSet.url)}
        </article>
      `).join("") || `<p class="empty">no rule sets</p>`}
    </section>
  `;
}

function renderClients(clients) {
  detailNode.classList.add("hidden");
  clientsNode.classList.remove("hidden");
  if (!Array.isArray(clients) || clients.length === 0) {
    clientsNode.innerHTML = `<p class="empty">no clients yet</p>`;
    return;
  }
  clientsNode.innerHTML = clients.map((client) => `
    <article class="card" data-client="${escapeHtml(client.client_id)}">
      <strong>${escapeHtml(client.display_id)}</strong>
      ${metric("user", client.username)}
      ${metric("connection", client.status)}
      ${metric("reachability", client.reachability_status)}
      ${metric("version", client.app_version)}
      ${metric("routing", client.routing_mode)}
      ${metric("auto updates", client.auto_updates_enabled)}
      ${metric("logs upload", client.logs_upload_enabled)}
      ${metric("traffic", bytes(client.total_traffic_bytes))}
    </article>
  `).join("");

  document.querySelectorAll(".card").forEach((card) => {
    card.addEventListener("click", () => loadDetail(card.dataset.client));
    card.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      contextClientId = card.dataset.client;
      contextMenu.style.left = `${event.clientX}px`;
      contextMenu.style.top = `${event.clientY}px`;
      contextMenu.classList.remove("hidden");
    });
  });
}

function renderConnections(connections) {
  if (!Array.isArray(connections) || connections.length === 0) {
    return `<p class="empty small">no connections reported</p>`;
  }
  return `<section class="connectionList">${connections.map((connection) => `
    <article>
      <strong>${escapeHtml(connection.name)}</strong>
      ${metric("protocol", connection.protocol)}
      ${metric("host", connection.host)}
      ${metric("port", connection.port)}
      ${metric("security", connection.security)}
      ${metric("sni", connection.sni)}
    </article>
  `).join("")}</section>`;
}

function eventText(event) {
  let payload = {};
  try {
    payload = JSON.parse(event.payload_json || "{}");
  } catch {
    payload = {};
  }
  const logLines = Array.isArray(payload.logLines) && payload.logLines.length > 0
    ? `\n\n${payload.logLines.join("\n")}`
    : "";
  return `${event.created_at} [${event.type}] ${event.status}
traffic total: ${bytes(event.traffic_total_bytes)}
traffic delta: ${bytes(event.traffic_delta_bytes)}
${event.message || ""}${logLines}`;
}

function renderLogBlock(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return `<p class="empty">no logs yet</p>`;
  }
  return `<pre class="logBlock">${escapeHtml(events.map(eventText).join("\n\n"))}</pre>`;
}

async function loadDetail(clientId) {
  hideContextMenu();
  const response = await apiFetch(`/api/v1/clients/${clientId}`);
  const data = await response.json();
  const client = data.client || {};
  const events = data.events || [];
  clientsNode.classList.add("hidden");
  detailNode.classList.remove("hidden");
  detailNode.innerHTML = `
    <div class="detailTop">
      <button id="back">back</button>
      <button id="collect">collect status/logs now</button>
      <button id="checkUpdates">check updates</button>
    </div>
    <h2>${escapeHtml(client.display_id)}</h2>
    <section class="infoGrid">
      ${metric("client id", client.display_id)}
      ${metric("user", client.username)}
      ${metric("original ip", client.original_ip)}
      ${metric("region", client.region)}
      ${metric("provider", client.provider)}
      ${metric("version", client.app_version)}
      ${metric("auto updates", client.auto_updates_enabled)}
      ${metric("logs upload", client.logs_upload_enabled)}
      ${metric("connection", client.status)}
      ${metric("reachability", client.reachability_status)}
      ${metric("routing", client.routing_mode)}
      ${metric("update report", client.update_report_status)}
      ${metric("last update", client.update_last_seen_at)}
      ${metric("update message", client.update_last_check_message)}
      ${metric("manifest", client.update_manifest_url)}
      ${metric("traffic", bytes(client.total_traffic_bytes))}
      ${metric("last seen", client.last_seen_at)}
    </section>
    <h3>connections</h3>
    ${renderConnections(client.connections)}
    <section class="logsPanel">
      <div class="logsHeader">
        <h3>logs</h3>
        <button id="downloadClientLogs" type="button">download logs zip</button>
      </div>
      <details open>
        <summary>show log stream</summary>
        ${renderLogBlock(events)}
      </details>
    </section>
  `;
  document.querySelector("#back").addEventListener("click", () => {
    detailNode.classList.add("hidden");
    clientsNode.classList.remove("hidden");
  });
  document.querySelector("#collect").addEventListener("click", () => apiFetch(`/api/v1/commands/${clientId}/collect-now`, { method: "POST" }));
  document.querySelector("#checkUpdates").addEventListener("click", () => apiFetch(`/api/v1/commands/${clientId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "check_updates" }),
  }));
  document.querySelector("#downloadClientLogs").addEventListener("click", () => downloadClientLogs(clientId));
}

async function downloadClientLogs(clientId) {
  statusNode.textContent = "creating client logs zip...";
  statusNode.classList.remove("error");
  const response = await apiFetch(`/api/v1/clients/${clientId}/logs.zip`);
  if (!response.ok) {
    statusNode.textContent = `client logs failed: ${response.status}`;
    statusNode.classList.add("error");
    return;
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/i);
  const fileName = match ? match[1] : "client-logs.zip";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  statusNode.textContent = "client logs zip created";
}

async function loadDashboard() {
  const fromLogin = !loginScreen.classList.contains("hidden");
  statusNode.textContent = "loading...";
  statusNode.classList.remove("error");
  const response = await apiFetch("/api/v1/dashboard");
  if (!response.ok) {
    const message = `dashboard failed: ${response.status}`;
    statusNode.textContent = message;
    statusNode.classList.add("error");
    if (fromLogin) {
      showLogin(message);
    }
    return;
  }
  showApp();
  const data = await response.json();
  renderDashboard(data);
  renderUpdates(data.updates || {});
  renderClients(data.clients || []);
  statusNode.textContent = "loaded";
}

async function requestData() {
  statusNode.textContent = "requesting client update checks...";
  statusNode.classList.remove("error");
  requestDataButton.disabled = true;
  try {
    const response = await apiFetch("/api/v1/request-data", { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      statusNode.textContent = body.error || `request failed: ${response.status}`;
      statusNode.classList.add("error");
      return;
    }
    const skipped = Array.isArray(body.skipped) ? body.skipped.length : 0;
    const message = `queued ${body.queued || 0} update checks${skipped ? `, skipped ${skipped} offline` : ""}`;
    await loadDashboard();
    statusNode.textContent = message;
  } finally {
    requestDataButton.disabled = false;
  }
}

async function downloadBackup() {
  statusNode.textContent = "creating backup...";
  const response = await apiFetch("/api/v1/backups/download");
  if (!response.ok) {
    statusNode.textContent = "backup download failed";
    statusNode.classList.add("error");
    return;
  }
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/i);
  const fileName = match ? match[1] : "loki-watcher-backup.zip";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  statusNode.textContent = "backup created";
}

async function uploadBackup(file) {
  if (!file || !window.confirm("restore this backup and replace server data?")) {
    uploadBackupInput.value = "";
    return;
  }
  statusNode.textContent = "restoring backup...";
  const response = await apiFetch("/api/v1/backups/upload", {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: file,
  });
  uploadBackupInput.value = "";
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    statusNode.textContent = body.error || "backup restore failed";
    statusNode.classList.add("error");
    return;
  }
  await loadDashboard();
  statusNode.textContent = "backup restored";
}

function hideContextMenu() {
  contextMenu.classList.add("hidden");
  contextClientId = null;
}

deleteClientButton.addEventListener("click", async () => {
  if (!contextClientId) {
    return;
  }
  const clientId = contextClientId;
  hideContextMenu();
  if (!window.confirm("delete this client from watcher?")) {
    return;
  }
  await apiFetch(`/api/v1/clients/${clientId}`, { method: "DELETE" });
  await loadDashboard();
});

loginButton.addEventListener("click", loadDashboard);
refreshButton.addEventListener("click", loadDashboard);
requestDataButton.addEventListener("click", requestData);
downloadBackupButton.addEventListener("click", downloadBackup);
uploadBackupInput.addEventListener("change", () => uploadBackup(uploadBackupInput.files[0]));
document.addEventListener("click", hideContextMenu);
document.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    loadDashboard();
  }
  if (event.key === "Escape") {
    hideContextMenu();
  }
});

clearStoredAuth();
usernameInput.value = "";
passwordInput.value = "";
showLogin();
usernameInput.focus();
