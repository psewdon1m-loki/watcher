const initializeButton = document.querySelector("#initializeButton");
const statusText = document.querySelector("#statusText");
const copyFallback = document.querySelector("#copyFallback");
const buttonLabel = initializeButton.querySelector(".button-label");
const manualCopy = document.querySelector("#manualCopy");
const manualLinks = document.querySelector("#manualLinks");
const designTime = document.querySelector("#designTime");
const cakeBurstButton = document.querySelector("#cakeBurstButton");
const cakeParticles = document.querySelector("#cakeParticles");

const API_PATH = "/api/v1/public/connections/initialize";
const REQUEST_STORAGE_KEY = "cake-project.initialization-request";

let cachedVlessText = "";
let requestPending = false;
let cakeBurstActive = false;
let cakeBurstFrame = 0;

const designTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "long",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

const accessibleTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "long",
  timeStyle: "medium",
});

function updateDesignTime() {
  const now = new Date();
  const parts = Object.fromEntries(
    designTimeFormatter.formatToParts(now).map(({ type, value }) => [type, value]),
  );
  designTime.textContent = `${parts.day} ${parts.month.toUpperCase()} ${parts.year} ${parts.hour}-${parts.minute}-${parts.second}`;
  designTime.dateTime = now.toISOString();
  designTime.setAttribute("aria-label", accessibleTimeFormatter.format(now));
}

updateDesignTime();
window.setInterval(updateDesignTime, 1000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) updateDesignTime();
});

function randomBetween(minimum, maximum) {
  return minimum + Math.random() * (maximum - minimum);
}

function finishCakeBurst() {
  window.cancelAnimationFrame(cakeBurstFrame);
  cakeParticles.replaceChildren();
  cakeBurstButton.disabled = false;
  cakeBurstButton.removeAttribute("aria-busy");
  cakeBurstActive = false;
}

function startCakeBurst() {
  if (cakeBurstActive) return;

  cakeBurstActive = true;
  cakeBurstButton.disabled = true;
  cakeBurstButton.setAttribute("aria-busy", "true");

  const sourceRect = cakeBurstButton.getBoundingClientRect();
  const particleCount = Math.floor(randomBetween(1, 11));
  const maximumSize = sourceRect.width * 0.5;
  const minimumSize = Math.min(maximumSize, Math.max(18, sourceRect.width * 0.12));
  const particles = [];

  for (let index = 0; index < particleCount; index += 1) {
    const size = randomBetween(minimumSize, maximumSize);
    const direction = Math.random() < 0.5 ? -1 : 1;
    const particle = document.createElement("img");
    particle.className = "cake-particle";
    particle.src = "favicon.png?v=2";
    particle.alt = "";
    particle.draggable = false;
    particle.width = Math.round(size);
    particle.height = Math.round(size);
    cakeParticles.append(particle);

    particles.push({
      element: particle,
      size,
      x: sourceRect.left + sourceRect.width / 2 - size / 2 + randomBetween(-12, 12),
      y: sourceRect.top + sourceRect.height / 2 - size / 2 + randomBetween(-8, 8),
      velocityX: direction * randomBetween(90, 310),
      velocityY: randomBetween(-530, -280),
      gravity: randomBetween(760, 1080),
      rotation: randomBetween(-35, 35),
      rotationSpeed: randomBetween(-300, 300),
      alive: true,
    });
  }

  let previousTimestamp;
  let elapsed = 0;

  function animateCakeBurst(timestamp) {
    if (previousTimestamp === undefined) previousTimestamp = timestamp;
    const delta = Math.min((timestamp - previousTimestamp) / 1000, 0.034);
    previousTimestamp = timestamp;
    elapsed += delta;
    let liveParticles = 0;

    for (const particle of particles) {
      if (!particle.alive) continue;

      particle.velocityY += particle.gravity * delta;
      particle.x += particle.velocityX * delta;
      particle.y += particle.velocityY * delta;
      particle.rotation += particle.rotationSpeed * delta;

      const fadeStart = window.innerHeight * 0.72;
      const remainingFall = Math.max(window.innerHeight + particle.size - fadeStart, 1);
      const opacity = particle.y > fadeStart
        ? Math.max(0, 1 - (particle.y - fadeStart) / remainingFall)
        : 1;

      particle.element.style.opacity = String(opacity);
      particle.element.style.transform = `translate3d(${particle.x}px, ${particle.y}px, 0) rotate(${particle.rotation}deg)`;

      if (particle.y > window.innerHeight + particle.size || elapsed > 5.5) {
        particle.alive = false;
        particle.element.remove();
      } else {
        liveParticles += 1;
      }
    }

    if (liveParticles > 0) {
      cakeBurstFrame = window.requestAnimationFrame(animateCakeBurst);
    } else {
      finishCakeBurst();
    }
  }

  cakeBurstFrame = window.requestAnimationFrame(animateCakeBurst);
}

cakeBurstButton.addEventListener("click", startCakeBurst);
window.addEventListener("pagehide", finishCakeBurst);

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
