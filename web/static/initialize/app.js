const initializeButton = document.querySelector("#initializeButton");
const statusText = document.querySelector("#statusText");
const copyFallback = document.querySelector("#copyFallback");
const buttonLabel = initializeButton.querySelector(".button-label");
const manualCopy = document.querySelector("#manualCopy");
const manualLinks = document.querySelector("#manualLinks");

const API_PATH = "/api/v1/public/connections/initialize";
const REQUEST_STORAGE_KEY = "cake-project.initialization-request";

let cachedVlessText = "";
let requestPending = false;

function setStatus(message, state = "") {
  statusText.dataset.state = state;
  statusText.textContent = message;
}

function setManualFallback(text = "") {
  manualLinks.value = text;
  manualCopy.classList.toggle("hidden", !text);
}

function randomRequestId() {
  if (!window.crypto?.getRandomValues) {
    throw new Error("secure_context_required");
  }
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function pendingRequestId() {
  try {
    const saved = sessionStorage.getItem(REQUEST_STORAGE_KEY) || "";
    if (/^[0-9a-f]{32}$/.test(saved)) return saved;
    const created = randomRequestId();
    sessionStorage.setItem(REQUEST_STORAGE_KEY, created);
    return created;
  } catch {
    return randomRequestId();
  }
}

function clearPendingRequestId() {
  try {
    sessionStorage.removeItem(REQUEST_STORAGE_KEY);
  } catch {
    // The request key is never required after a successful response.
  }
}

function validateVlessLinks(value) {
  if (!Array.isArray(value) || !value.length) throw new Error("no_vless_links");
  const links = value.map((item) => String(item).trim());
  if (links.some((item) => !/^vless:\/\//i.test(item))) throw new Error("invalid_vless_response");
  return links;
}

async function initializeConnection(requestId) {
  const response = await fetch(API_PATH, {
    method: "POST",
    cache: "no-store",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestId }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `request_failed_${response.status}`);
    error.status = response.status;
    throw error;
  }
  const links = validateVlessLinks(payload.vlessLinks);
  return { links, count: links.length };
}

function startGestureClipboardWrite(textPromise) {
  if (!navigator.clipboard?.write || !window.ClipboardItem) return null;
  try {
    const item = new ClipboardItem({
      "text/plain": textPromise.then((text) => new Blob([text], { type: "text/plain" })),
    });
    return navigator.clipboard.write([item]).then(() => true, () => false);
  } catch {
    return null;
  }
}

function legacyCopy(text) {
  const activeElement = document.activeElement;
  copyFallback.value = text;
  copyFallback.focus({ preventScroll: true });
  copyFallback.select();
  copyFallback.setSelectionRange(0, text.length);
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  }
  copyFallback.value = "";
  if (activeElement instanceof HTMLElement) activeElement.focus({ preventScroll: true });
  return copied;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Older iOS/WebView builds may still support the selection-based fallback.
    }
  }
  return legacyCopy(text);
}

function readableError(error) {
  const messages = {
    public_initialization_rate_limited: "Слишком много новых подключений. Попробуйте ещё раз через час.",
    pasarguard_unavailable: "Pasar Guard временно недоступен. Повторите попытку позже.",
    pasarguard_subscription_contains_no_vless: "В полученной подписке нет VLESS-ссылок.",
    no_vless_links: "Watcher не вернул VLESS-ссылки.",
    invalid_vless_response: "Watcher вернул данные в неожиданном формате.",
    secure_context_required: "Откройте страницу по защищённому HTTPS-адресу.",
  };
  return messages[error.message] || "Не удалось создать подключение. Повторите попытку.";
}

async function handleInitialization() {
  if (requestPending) return;

  if (cachedVlessText) {
    const copied = await copyText(cachedVlessText);
    setManualFallback(copied ? "" : cachedVlessText);
    setStatus(
      copied ? "VLESS-ссылки снова скопированы." : "Браузер не разрешил копирование. Разрешите доступ к буферу и нажмите ещё раз.",
      copied ? "success" : "error",
    );
    return;
  }

  requestPending = true;
  initializeButton.disabled = true;
  buttonLabel.textContent = "Создаём подключение…";
  setStatus("Создаём пользователя в Pasar Guard и импортируем подключения…");

  let clipboardAttempt = null;
  try {
    const requestId = pendingRequestId();
    const resultPromise = initializeConnection(requestId);
    const textPromise = resultPromise.then((result) => result.links.join("\n"));
    clipboardAttempt = startGestureClipboardWrite(textPromise);

    const result = await resultPromise;
    cachedVlessText = result.links.join("\n");
    clearPendingRequestId();

    let copied = clipboardAttempt ? await clipboardAttempt : false;
    if (!copied) copied = await copyText(cachedVlessText);
    setManualFallback(copied ? "" : cachedVlessText);

    buttonLabel.textContent = "Скопировать VLESS ещё раз";
    setStatus(
      copied
        ? `Готово: ${result.count} VLESS-${result.count === 1 ? "ссылка скопирована" : "ссылок скопировано"}.`
        : `Подключение готово (${result.count}). Нажмите кнопку ещё раз, чтобы скопировать VLESS-ссылки.`,
      copied ? "success" : "error",
    );
  } catch (error) {
    if (clipboardAttempt) await clipboardAttempt;
    buttonLabel.textContent = "Повторить инициализацию";
    setStatus(readableError(error), "error");
  } finally {
    requestPending = false;
    initializeButton.disabled = false;
  }
}

initializeButton.addEventListener("click", handleInitialization);
