const api = "http://127.0.0.1:18080";
const dashboardNode = document.querySelector("#dashboard");
const clientSectionNode = document.querySelector("#clientSection");
const clientsNode = document.querySelector("#clients");
const detailNode = document.querySelector("#detail");
const dashboardTab = document.querySelector("#dashboardTab");
const clientsTab = document.querySelector("#clientsTab");
const refreshButton = document.querySelector("#refresh");
const downloadBackupButton = document.querySelector("#downloadBackup");
const uploadBackupInput = document.querySelector("#uploadBackup");
const backupStatus = document.querySelector("#backupStatus");
const contextMenu = document.querySelector("#contextMenu");
const deleteClientButton = document.querySelector("#deleteClient");
let contextClientId = null;

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

function value(text) {
  return text === null || text === undefined || text === "" ? "-" : text;
}

function escapeHtml(text) {
  return String(value(text))
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function metric(label, metricValue) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><span>${escapeHtml(metricValue)}</span></div>`;
}

function setBackupStatus(text, ok = true) {
  backupStatus.textContent = text;
  backupStatus.classList.toggle("error", !ok);
}

function showSection(name) {
  hideContextMenu();
  const isDashboard = name === "dashboard";
  dashboardNode.classList.toggle("hidden", !isDashboard);
  clientSectionNode.classList.toggle("hidden", isDashboard);
  dashboardTab.classList.toggle("active", isDashboard);
  clientsTab.classList.toggle("active", !isDashboard);
  if (!isDashboard) {
    loadClients().catch((error) => {
      clientsNode.innerHTML = `<p class="empty">${escapeHtml(error.message)}</p>`;
    });
  }
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
      ${metric("network", connection.network)}
      ${metric("security", connection.security)}
      ${metric("sni", connection.sni)}
      ${metric("subscription", connection.fromSubscription ? "yes" : "no")}
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
routing: ${value(payload.routingMode)}
traffic total: ${bytes(event.traffic_total_bytes)}
traffic delta: ${bytes(event.traffic_delta_bytes)}
${event.message || ""}${logLines}`;
}

function hideContextMenu() {
  contextMenu.classList.add("hidden");
  contextClientId = null;
}

async function loadClients() {
  hideContextMenu();
  detailNode.classList.add("hidden");
  clientsNode.classList.remove("hidden");
  const response = await fetch(`${api}/api/v1/clients`);
  const data = await response.json();
  const clients = data.clients || [];
  if (clients.length === 0) {
    clientsNode.innerHTML = `<p class="empty">no clients yet</p>`;
    return;
  }

  clientsNode.innerHTML = clients.map((client) => `
    <article class="card" data-client="${escapeHtml(client.client_id)}">
      <strong>${escapeHtml(client.display_id)}</strong>
      ${metric("user", client.username)}
      ${metric("connection", client.status)}
      ${metric("reachability", client.reachability_status)}
      ${metric("routing", client.routing_mode)}
      ${metric("region", client.region)}
      ${metric("ip", client.original_ip)}
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

async function loadDetail(clientId) {
  hideContextMenu();
  const response = await fetch(`${api}/api/v1/clients/${clientId}`);
  const data = await response.json();
  const client = data.client;
  const events = data.events || [];
  clientsNode.classList.add("hidden");
  detailNode.classList.remove("hidden");
  detailNode.innerHTML = `
    <div class="detailTop">
      <button id="back">back</button>
      <button id="collect">collect status/logs now</button>
    </div>
    <h2>${escapeHtml(client.display_id)}</h2>
    <section class="infoGrid">
      ${metric("user", client.username)}
      ${metric("machine", client.machine_name)}
      ${metric("connection", client.status)}
      ${metric("reachability", client.reachability_status)}
      ${metric("routing", client.routing_mode)}
      ${metric("region", client.region)}
      ${metric("ip", client.original_ip)}
      ${metric("traffic", bytes(client.total_traffic_bytes))}
      ${metric("installed", client.installed_at)}
      ${metric("last seen", client.last_seen_at)}
      ${metric("app version", client.app_version)}
      ${metric("os", client.os)}
      ${metric("windows", client.windows_version)}
    </section>
    <h3>connections</h3>
    ${renderConnections(client.connections)}
    <h3>logs</h3>
    ${events.map((event) => `<pre class="log">${escapeHtml(eventText(event))}</pre>`).join("") || `<p class="empty">no logs yet</p>`}
  `;
  document.querySelector("#back").addEventListener("click", loadClients);
  document.querySelector("#collect").addEventListener("click", async () => {
    await fetch(`${api}/api/v1/commands/${clientId}/collect-now`, { method: "POST" });
  });
}

async function downloadBackup() {
  setBackupStatus("preparing backup...");
  const response = await fetch(`${api}/api/v1/backups/download`);
  if (!response.ok) {
    setBackupStatus("backup download failed", false);
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
  setBackupStatus("backup downloaded");
}

async function uploadBackup(file) {
  if (!file) {
    return;
  }

  if (!window.confirm("restore this backup and replace watcher data?")) {
    uploadBackupInput.value = "";
    return;
  }

  setBackupStatus("restoring backup...");
  const response = await fetch(`${api}/api/v1/backups/upload`, {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: file,
  });
  uploadBackupInput.value = "";
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    setBackupStatus(body.error || "backup restore failed", false);
    return;
  }

  setBackupStatus("backup restored");
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

  const response = await fetch(`${api}/api/v1/clients/${clientId}`, { method: "DELETE" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    window.alert(body.error || "delete failed");
    return;
  }

  await loadClients();
});

dashboardTab.addEventListener("click", () => showSection("dashboard"));
clientsTab.addEventListener("click", () => showSection("clients"));
refreshButton.addEventListener("click", loadClients);
downloadBackupButton.addEventListener("click", downloadBackup);
uploadBackupInput.addEventListener("change", () => uploadBackup(uploadBackupInput.files[0]));
document.addEventListener("click", hideContextMenu);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    hideContextMenu();
  }
});
