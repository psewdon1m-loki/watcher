const initializeButton = document.querySelector("#initializeButton");
const statusText = document.querySelector("#statusText");
const copyFallback = document.querySelector("#copyFallback");
const buttonLabel = initializeButton.querySelector(".button-label");
const manualCopy = document.querySelector("#manualCopy");
const manualLinks = document.querySelector("#manualLinks");
const designTime = document.querySelector("#designTime");
const cakeBurstButton = document.querySelector("#cakeBurstButton");
const cakeParticles = document.querySelector("#cakeParticles");
const paymentPage = document.querySelector("#paymentPage");
const appsPage = document.querySelector("#appsPage");
const connectionButton = document.querySelector("#connectionButton");
const platformButtons = [...document.querySelectorAll(".platform-button")];
const platformDescription = document.querySelector("#platformDescription");
const subscriptionDescription = document.querySelector("#subscriptionDescription");
const downloadButton = document.querySelector("#downloadButton");
const languageButtons = [...document.querySelectorAll("[data-language]")];
const pageSections = [...document.querySelectorAll(".page-section")];
const descriptionMeta = document.querySelector('meta[name="description"]');
const pageRail = document.querySelector(".page-rail");

const API_PATH = "/api/v1/public/connections/initialize";
const REQUEST_STORAGE_KEY = "cake-project.initialization-request";
const LANGUAGE_STORAGE_KEY = "cake-project.language";

let cachedVlessText = "";
let requestPending = false;
let cakeBurstActive = false;
let cakeBurstFrame = 0;
let currentLanguage = "ru";
let currentPlatform = "ios";
let currentButtonLabelKey = "initialize";
let currentStatus = { key: "statusReady", state: "", variables: {} };
let wheelLocked = false;
let wheelUnlockTimer = 0;
let railTransitionTimer = 0;
let designTimeFormatter;
let accessibleTimeFormatter;

const translations = {
  ru: {
    title: "Cake Project — инициализация",
    description: "Cake Project — безопасные и быстрые VLESS-соединения в одно нажатие.",
    channel: "Защищённый канал",
    cakeAria: "Запустить анимацию тортика",
    personalEyebrow: "Персональное подключение / 1",
    heroTitle: "Быстрое и безопасное<br>proxy соединение",
    heroIntro: "Cake Project предлагает безопасные и стабильные VLESS-соединения. Инициализация<br class=\"desktop-break\"> создаст для Вас персональное подключение и сразу скопирует его в буфер обмена<br class=\"desktop-break\"> Вашего устройства.",
    initializeAreaAria: "Инициализация подключения",
    initialize: "Инициализация",
    initializePending: "Создаём подключение…",
    initializeRetry: "Повторить инициализацию",
    manualLabel: "VLESS-ссылки для ручного копирования",
    manualHint: "Если браузер блокирует буфер обмена, выделите текст и выберите «Копировать».",
    connection: "Подключение",
    paymentEyebrow: "Безопасная оплата / 2",
    paymentTitle: "Своевременная оплата за услуги<br>обеспечит стабильность<br>подключений",
    paymentIntro: "Cake Project не является коммерческим проектом, однако финансовая помощь наших<br class=\"desktop-break\"> пользователей позволяет поддерживать инфраструктуру сети и работоспособность<br class=\"desktop-break\"> соединений.",
    platformGroupAria: "Выбор платформы",
    stableEyebrow: "Стабильное подключение / 3",
    installTitle: "1. Установка приложения",
    subscriptionTitle: "2. Добавление подписки",
    download: "Скачать",
    languageAria: "Выбор языка",
    statusReady: "Готово к созданию персонального подключения.",
    statusCopiedAgain: "VLESS-ссылки снова скопированы.",
    statusCopyDenied: "Браузер не разрешил копирование. Разрешите доступ к буферу и нажмите ещё раз.",
    statusCreating: "Создаём пользователя в Pasar Guard и импортируем подключения…",
    statusReadyNotCopied: ({ count }) => `Подключение готово (${count}). Нажмите кнопку ещё раз, чтобы скопировать VLESS-ссылки.`,
    statusCopied: ({ count }) => count === 1 ? "Готово: VLESS-ссылка скопирована." : `Готово: VLESS-ссылки скопированы (${count}).`,
    statusGenericError: "Не удалось создать подключение. Повторите попытку.",
    subscriptionDescription: ({ appName }) => `В Вашем буфере обмена уже сохранены подключения. Откройте ${appName}, нажмите «+» для добавления нового подключения и выберите «Импорт из буфера обмена». При необходимости Вы можете заново скопировать ссылки кнопкой «Инициализация» выше.`,
    errors: {
      public_initialization_rate_limited: "Слишком много новых подключений. Попробуйте ещё раз через час.",
      pasarguard_unavailable: "Pasar Guard временно недоступен. Повторите попытку позже.",
      pasarguard_subscription_contains_no_vless: "В полученной подписке нет VLESS-ссылок.",
      no_vless_links: "Watcher не вернул VLESS-ссылки.",
      invalid_vless_response: "Watcher вернул данные в неожиданном формате.",
      secure_context_required: "Откройте страницу по защищённому HTTPS-адресу.",
    },
    platforms: {
      ios: { appName: "Incy", description: "Для iPhone установите приложение Incy из App Store, затем откройте его и разрешите добавление VPN-конфигурации.", downloadLabel: "Скачать Incy для iPhone" },
      android: { appName: "Happ", description: "Для Android установите приложение Happ из Google Play, затем откройте его и разрешите добавление VPN-конфигурации.", downloadLabel: "Скачать Happ для Android" },
      windows: { appName: "Happ", description: "Для Windows скачайте Happ с официального сайта, установите приложение и откройте его для добавления подключения.", downloadLabel: "Скачать Happ для Windows" },
    },
  },
  en: {
    title: "Cake Project — initialize",
    description: "Cake Project — fast and secure VLESS connections in one click.",
    channel: "Secure channel",
    cakeAria: "Launch the cake animation",
    personalEyebrow: "Personal connection / 1",
    heroTitle: "Fast and secure<br>proxy connection",
    heroIntro: "Cake Project provides secure and stable VLESS connections. Initialization creates<br class=\"desktop-break\"> a personal connection for you and immediately copies it to your device's<br class=\"desktop-break\"> clipboard.",
    initializeAreaAria: "Initialize connection",
    initialize: "Initialize",
    initializePending: "Creating connection…",
    initializeRetry: "Retry initialization",
    manualLabel: "VLESS links for manual copying",
    manualHint: "If the browser blocks clipboard access, select the text and choose Copy.",
    connection: "Connection",
    paymentEyebrow: "Secure funding / 2",
    paymentTitle: "Timely support for the project<br>keeps every connection<br>stable",
    paymentIntro: "Cake Project is not a commercial project. Financial support from our users helps us<br class=\"desktop-break\"> maintain the network infrastructure and keep every connection<br class=\"desktop-break\"> operational.",
    platformGroupAria: "Choose a platform",
    stableEyebrow: "Stable connection / 3",
    installTitle: "1. Install the app",
    subscriptionTitle: "2. Add the subscription",
    download: "Download",
    languageAria: "Choose language",
    statusReady: "Ready to create a personal connection.",
    statusCopiedAgain: "VLESS links copied again.",
    statusCopyDenied: "The browser blocked clipboard access. Allow access and try again.",
    statusCreating: "Creating a Pasar Guard user and importing connections…",
    statusReadyNotCopied: ({ count }) => `Connection ready (${count}). Click the button again to copy the VLESS links.`,
    statusCopied: ({ count }) => count === 1 ? "Done: VLESS link copied." : `Done: VLESS links copied (${count}).`,
    statusGenericError: "Could not create the connection. Please try again.",
    subscriptionDescription: ({ appName }) => `Your connections are already saved to the clipboard. Open ${appName}, tap “+” to add a new connection, and choose “Import from clipboard”. If needed, use the Initialize button above to copy the links again.`,
    errors: {
      public_initialization_rate_limited: "Too many new connections. Please try again in an hour.",
      pasarguard_unavailable: "Pasar Guard is temporarily unavailable. Please try again later.",
      pasarguard_subscription_contains_no_vless: "The subscription contains no VLESS links.",
      no_vless_links: "Watcher returned no VLESS links.",
      invalid_vless_response: "Watcher returned data in an unexpected format.",
      secure_context_required: "Open this page over a secure HTTPS connection.",
    },
    platforms: {
      ios: { appName: "Incy", description: "For iPhone, install Incy from the App Store, open it, and allow the VPN configuration to be added.", downloadLabel: "Download Incy for iPhone" },
      android: { appName: "Happ", description: "For Android, install Happ from Google Play, open it, and allow the VPN configuration to be added.", downloadLabel: "Download Happ for Android" },
      windows: { appName: "Happ", description: "For Windows, download Happ from the official website, install it, and open it to add the connection.", downloadLabel: "Download Happ for Windows" },
    },
  },
};

const platformDownloadUrls = {
  ios: "https://apps.apple.com/ru/app/incy/id6756943388",
  android: "https://play.google.com/store/apps/details?id=com.happproxy",
  windows: "https://happ.info/",
};

function translate(key, variables = {}) {
  const value = key.split(".").reduce((result, part) => result?.[part], translations[currentLanguage]);
  return typeof value === "function" ? value(variables) : value;
}

function detectedLanguage() {
  try {
    const saved = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (saved === "ru" || saved === "en") return saved;
  } catch {
    // Browser storage is optional; locale detection remains available.
  }
  const preferred = navigator.languages?.[0] || navigator.language || "en";
  return preferred.toLowerCase().startsWith("ru") ? "ru" : "en";
}

function rebuildTimeFormatters() {
  const locale = currentLanguage === "ru" ? "ru-RU" : "en-GB";
  designTimeFormatter = new Intl.DateTimeFormat(locale, {
    day: "2-digit",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  accessibleTimeFormatter = new Intl.DateTimeFormat(locale, {
    dateStyle: "long",
    timeStyle: "medium",
  });
}

function updateDesignTime() {
  const now = new Date();
  const parts = Object.fromEntries(
    designTimeFormatter.formatToParts(now).map(({ type, value }) => [type, value]),
  );
  designTime.textContent = `${parts.day} ${parts.month.toUpperCase()} ${parts.year} ${parts.hour}-${parts.minute}-${parts.second}`;
  designTime.dateTime = now.toISOString();
  designTime.setAttribute("aria-label", accessibleTimeFormatter.format(now));
}

function scrollToPage(page) {
  const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  window.clearTimeout(railTransitionTimer);
  pageRail.classList.toggle("is-visible", page !== pageSections[0]);
  railTransitionTimer = window.setTimeout(() => {
    railTransitionTimer = 0;
    updatePageRail();
  }, 720);
  page.scrollIntoView({
    behavior: reduceMotion ? "auto" : "smooth",
    block: "start",
  });
}

function updatePageRail() {
  if (railTransitionTimer) return;
  const paymentOffset = Math.max(paymentPage.offsetTop, 1);
  pageRail.classList.toggle("is-visible", window.scrollY >= paymentOffset / 2);
}

let railFrame = 0;
function schedulePageRailUpdate() {
  if (railFrame) return;
  railFrame = window.requestAnimationFrame(() => {
    railFrame = 0;
    updatePageRail();
  });
}

updatePageRail();
window.addEventListener("scroll", schedulePageRailUpdate, { passive: true });
window.addEventListener("resize", schedulePageRailUpdate);

function nearestPageIndex() {
  return pageSections.reduce((nearest, page, index) => {
    const distance = Math.abs(page.getBoundingClientRect().top);
    return distance < nearest.distance ? { index, distance } : nearest;
  }, { index: 0, distance: Number.POSITIVE_INFINITY }).index;
}

function handleWheel(event) {
  if (event.ctrlKey || Math.abs(event.deltaY) <= Math.abs(event.deltaX) || Math.abs(event.deltaY) < 4) return;
  if (event.target instanceof Element && event.target.closest("textarea, input, select")) return;

  const direction = event.deltaY > 0 ? 1 : -1;
  const currentIndex = nearestPageIndex();
  const currentPage = pageSections[currentIndex];
  const currentRect = currentPage.getBoundingClientRect();
  const pageIsTallerThanViewport = currentPage.scrollHeight > window.innerHeight + 2;

  const isFinalPage = currentIndex === pageSections.length - 1;
  if (isFinalPage && pageIsTallerThanViewport && direction > 0 && currentRect.bottom > window.innerHeight + 2) return;
  if (isFinalPage && pageIsTallerThanViewport && direction < 0 && currentRect.top < -2) return;

  const targetIndex = Math.min(Math.max(currentIndex + direction, 0), pageSections.length - 1);
  event.preventDefault();
  if (wheelLocked || targetIndex === currentIndex) return;

  wheelLocked = true;
  window.clearTimeout(wheelUnlockTimer);
  scrollToPage(pageSections[targetIndex]);
  wheelUnlockTimer = window.setTimeout(() => {
    wheelLocked = false;
  }, 900);
}

window.addEventListener("wheel", handleWheel, { passive: false });

function selectPlatform(platform) {
  const settings = translations[currentLanguage].platforms[platform];
  if (!settings) return;

  currentPlatform = platform;
  platformButtons.forEach((button) => {
    const selected = button.dataset.platform === platform;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  platformDescription.textContent = settings.description;
  subscriptionDescription.textContent = translate("subscriptionDescription", { appName: settings.appName });
  downloadButton.href = platformDownloadUrls[platform];
  downloadButton.setAttribute("aria-label", settings.downloadLabel);
}

function renderStatus() {
  statusText.dataset.state = currentStatus.state;
  statusText.textContent = translate(currentStatus.key, currentStatus.variables);
}

function setButtonLabel(key) {
  currentButtonLabelKey = key;
  buttonLabel.textContent = translate(key);
}

function applyLanguage(language, persist = false) {
  currentLanguage = language === "ru" ? "ru" : "en";
  document.documentElement.lang = currentLanguage;
  document.title = translate("title");
  descriptionMeta.setAttribute("content", translate("description"));

  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = translate(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((element) => {
    element.innerHTML = translate(element.dataset.i18nHtml);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    element.setAttribute("aria-label", translate(element.dataset.i18nAriaLabel));
  });
  languageButtons.forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.language === currentLanguage));
  });

  rebuildTimeFormatters();
  updateDesignTime();
  setButtonLabel(currentButtonLabelKey);
  renderStatus();
  selectPlatform(currentPlatform);

  if (persist) {
    try {
      localStorage.setItem(LANGUAGE_STORAGE_KEY, currentLanguage);
    } catch {
      // The switch still works for this page view without storage.
    }
  }
}

connectionButton.addEventListener("click", () => scrollToPage(appsPage));
platformButtons.forEach((button) => {
  button.addEventListener("click", () => selectPlatform(button.dataset.platform));
});
languageButtons.forEach((button) => {
  button.addEventListener("click", () => applyLanguage(button.dataset.language, true));
});

applyLanguage(detectedLanguage());
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

function setStatus(key, state = "", variables = {}) {
  currentStatus = { key, state, variables };
  renderStatus();
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

function readableErrorKey(error) {
  return translations[currentLanguage].errors[error.message]
    ? `errors.${error.message}`
    : "statusGenericError";
}

async function handleInitialization() {
  if (requestPending) return;

  if (cachedVlessText) {
    const copied = await copyText(cachedVlessText);
    setManualFallback(copied ? "" : cachedVlessText);
    setStatus(
      copied ? "statusCopiedAgain" : "statusCopyDenied",
      copied ? "success" : "error",
    );
    if (copied) scrollToPage(paymentPage);
    return;
  }

  requestPending = true;
  initializeButton.disabled = true;
  setButtonLabel("initializePending");
  setStatus("statusCreating");

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

    setButtonLabel("initialize");
    setStatus(
      copied ? "statusCopied" : "statusReadyNotCopied",
      copied ? "success" : "error",
      { count: result.count },
    );
    if (copied) scrollToPage(paymentPage);
  } catch (error) {
    if (clipboardAttempt) await clipboardAttempt;
    setButtonLabel("initializeRetry");
    setStatus(readableErrorKey(error), "error");
  } finally {
    requestPending = false;
    initializeButton.disabled = false;
  }
}

initializeButton.addEventListener("click", handleInitialization);
