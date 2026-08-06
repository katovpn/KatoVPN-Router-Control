const state = {
  token: "",
  routerSession: null,
  activeView: "home",
  browserSessionId: null,
  browserSessionController: null,
  browserSessionClosing: false,
  pollTimer: null,
  supportTimer: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const delay = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function initializeToken() {
  const params = new URLSearchParams(window.location.search);
  const urlToken = params.get("token") || "";
  let storedToken = "";
  try {
    storedToken = window.sessionStorage.getItem("kato-router-session-token") || "";
    if (urlToken) window.sessionStorage.setItem("kato-router-session-token", urlToken);
  } catch (_) {}
  state.token = urlToken || storedToken;
  window.history.replaceState({}, document.title, window.location.pathname + window.location.hash);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Kato-Token": state.token,
      ...(options.headers || {}),
    },
    cache: "no-store",
  });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || "Не удалось выполнить запрос.");
    error.payload = payload.error;
    throw error;
  }
  return payload;
}

function newBrowserSessionId() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `kato-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function maintainBrowserSession() {
  while (!state.browserSessionClosing) {
    const clientId = newBrowserSessionId();
    const controller = new AbortController();
    state.browserSessionId = clientId;
    state.browserSessionController = controller;
    try {
      const response = await fetch(`/api/session/stream?client_id=${encodeURIComponent(clientId)}`, {
        headers: { "X-Kato-Token": state.token }, cache: "no-store", signal: controller.signal,
      });
      if (!response.ok || !response.body) throw new Error("session unavailable");
      const reader = response.body.getReader();
      while (!(await reader.read()).done) {}
    } catch (_) {
      // Closing the page and short loopback reconnects both end the stream normally.
    } finally {
      if (state.browserSessionId === clientId) {
        state.browserSessionId = null;
        state.browserSessionController = null;
      }
    }
    if (!state.browserSessionClosing) await delay(350);
  }
}

function closeBrowserSession() {
  if (state.browserSessionClosing) return;
  state.browserSessionClosing = true;
  const clientId = state.browserSessionId;
  state.browserSessionController?.abort();
  if (!clientId) return;
  fetch("/api/session/close", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Kato-Token": state.token },
    body: JSON.stringify({ client_id: clientId }), cache: "no-store", keepalive: true,
  }).catch(() => {});
}

window.addEventListener("pagehide", closeBrowserSession);
window.addEventListener("pageshow", (event) => {
  if (!event.persisted || !state.browserSessionClosing) return;
  state.browserSessionClosing = false;
  maintainBrowserSession();
});

function showError(message) {
  $("#error-message").textContent = message;
  $("#error-banner").classList.remove("hidden");
  window.setTimeout(() => $("#error-banner").classList.add("hidden"), 9000);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.classList.toggle("busy", busy);
  const text = button.querySelector("span");
  if (text && label) text.textContent = label;
}

function showLogin() {
  window.clearInterval(state.supportTimer);
  state.routerSession = null;
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
  $("#password").value = "";
  window.setTimeout(() => $("#password").focus(), 50);
}

function showApp(routerSession) {
  state.routerSession = routerSession;
  $("#password").value = "";
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  renderDashboard(routerSession.dashboard || {});
  renderSupport(routerSession.support || { status: "inactive", available: false });
  switchView(state.activeView);
}

function switchView(view) {
  const titles = {
    home: ["Обзор системы", "Главная"],
    internet: ["Домашняя сеть", "Интернет"],
    firmware: ["Возможности роутера", "Прошивка"],
    logs: ["Диагностика", "Логи"],
  };
  if (!titles[view]) return;
  state.activeView = view;
  $$('[data-section]').forEach((section) => section.classList.toggle("active", section.dataset.section === view));
  $$(".nav-item").forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle("active", active);
    button.toggleAttribute("aria-current", active);
  });
  $("#section-eyebrow").textContent = titles[view][0];
  $("#section-title").textContent = titles[view][1];
  window.location.hash = view;
}

function formatDate(value) {
  if (!value) return "Срок не указан";
  const normalized = String(value).includes("T") ? String(value) : String(value).replace(" ", "T");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000) return "Срок не указан";
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium" }).format(date);
}

function formatSupportExpiry(epochSeconds) {
  const date = new Date(Number(epochSeconds) * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function renderSupport(support) {
  window.clearInterval(state.supportTimer);
  if (state.routerSession) state.routerSession.support = support;
  const active = support.status === "active";
  const available = support.available !== false && support.status !== "unavailable";
  const stateLabel = $("#support-state");
  stateLabel.textContent = active ? "Подключён" : support.status === "starting" ? "Подключаем…" : available ? "Отключён" : "Недоступен";
  stateLabel.className = `label ${active ? "active" : available ? "" : "unavailable"}`;
  $("#support-idle").classList.toggle("hidden", active);
  $("#support-active").classList.toggle("hidden", !active);
  $("#support-availability-note").textContent = available
    ? "Приложение создаст исходящее защищённое подключение к закрытому серверу KatoVPN."
    : support.message || "Сервер временной поддержки ещё не подключён к этой сборке.";
  const startButton = $("#support-start-button");
  startButton.disabled = !available || support.status === "starting";

  if (!active) return;
  $("#support-code").textContent = support.code || "—";
  $("#support-server").textContent = support.server || "—";
  $("#support-port").textContent = support.port || "—";
  $("#support-router-login").textContent = support.router_username || state.routerSession?.username || "root";
  $("#support-expiry").textContent = formatSupportExpiry(support.expires_at);

  let expiryRefreshStarted = false;
  const updateCountdown = () => {
    const remaining = Math.max(0, Math.ceil(Number(support.expires_at) - Date.now() / 1000));
    const hours = String(Math.floor(remaining / 3600)).padStart(2, "0");
    const minutes = String(Math.floor((remaining % 3600) / 60)).padStart(2, "0");
    const seconds = String(remaining % 60).padStart(2, "0");
    $("#support-countdown").textContent = `${hours}:${minutes}:${seconds}`;
    if (remaining === 0 && !expiryRefreshStarted) {
      expiryRefreshStarted = true;
      window.clearInterval(state.supportTimer);
      window.setTimeout(refreshSupportStatus, 800);
    }
  };
  updateCountdown();
  state.supportTimer = window.setInterval(updateCountdown, 1000);
}

async function refreshSupportStatus() {
  try {
    const payload = await api("/api/support/status");
    renderSupport(payload.support || { status: "inactive", available: false });
  } catch (error) {
    showError(error.message);
  }
}

async function startSupport() {
  const button = $("#support-start-button");
  setBusy(button, true, "Создаём доступ…");
  try {
    const payload = await api("/api/support/start", { method: "POST", body: JSON.stringify({ confirmed: true }) });
    renderSupport(payload.support);
  } catch (error) {
    showError(error.message);
    await refreshSupportStatus();
  } finally {
    setBusy(button, false, "Разрешить поддержку на 1 час");
  }
}

async function stopSupport() {
  const button = $("#support-stop-button");
  setBusy(button, true, "Отключаем…");
  try {
    const payload = await api("/api/support/stop", { method: "POST", body: "{}" });
    renderSupport(payload.support);
    if ((payload.support?.warnings || []).length) showError(payload.support.warnings.join(" "));
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(button, false, "Отключить поддержку");
  }
}

async function copySupportDetails() {
  const support = state.routerSession?.support || {};
  if (support.status !== "active") return;
  const text = [
    "KatoVPN — временная поддержка",
    `Код: ${support.code || "—"}`,
    `Сервер: ${support.server || "—"}`,
    `Порт: ${support.port || "—"}`,
    `Логин роутера: ${support.router_username || state.routerSession?.username || "root"}`,
    `Действует до: ${formatSupportExpiry(support.expires_at)}`,
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  const button = $("#support-copy-button");
  setBusy(button, true, "Скопировано");
  window.setTimeout(() => setBusy(button, false, "Скопировать для поддержки"), 1200);
}

function formatBandLabel(band) {
  const value = String(band || "").toLowerCase().replace(/\s/g, "");
  if (value.includes("6")) return "6 ГГц";
  if (value.includes("5")) return "5 ГГц";
  if (value.includes("2")) return "2,4 ГГц";
  return "диапазон не определён";
}

function formatRadioLabel(radio, networks) {
  const network = (networks || []).find((item) => item.radio === radio);
  return `${radio} — ${formatBandLabel(network?.band)}`;
}

function emptyRow(titleText, subtitleText) {
  const row = document.createElement("div");
  row.className = "wifi-row";
  const main = document.createElement("div");
  main.className = "row-main";
  const title = document.createElement("strong");
  const subtitle = document.createElement("small");
  title.textContent = titleText;
  subtitle.textContent = subtitleText;
  main.append(title, subtitle);
  row.append(main);
  return row;
}

function renderDashboard(report) {
  const router = report.router || {};
  const internet = report.internet || {};
  const publicIp = report.public_ip || {};
  const subscription = report.subscription || {};
  const compatibility = report.compatibility || {};
  const safety = report.safety || {};
  const lan = report.lan || {};

  $("#sidebar-router").textContent = router.hostname || router.model || "Роутер";
  $("#sidebar-address").textContent = state.routerSession ? `${state.routerSession.host}:${state.routerSession.port}` : "—";
  $("#router-model").textContent = router.model || "OpenWrt роутер";
  $("#router-firmware").textContent = `${router.firmware || "OpenWrt"} · ${router.memory_mb || 0} МБ RAM`;

  const internetPill = $("#internet-pill");
  internetPill.className = `status-pill ${internet.online ? "online" : "offline"}`;
  internetPill.querySelector("span").textContent = internet.online ? "Интернет работает" : "Нет интернета с роутера";

  const checks = (compatibility.checks || []).filter((item) => item.code !== "package_manager");
  const passed = checks.filter((item) => item.status !== "block").length;
  $("#readiness-seal").querySelector("span").textContent = `${passed}/${checks.length}`;
  $("#compatibility-list").replaceChildren(...checks.map((item) => {
    const row = document.createElement("div");
    row.className = `status-row ${item.status}`;
    const dot = document.createElement("i");
    dot.className = "state-dot";
    const text = document.createElement("span");
    const title = document.createElement("strong");
    const value = document.createElement("small");
    title.textContent = item.title;
    value.textContent = item.value;
    text.append(title, value);
    row.append(dot, text);
    return row;
  }));

  $("#public-ip-address").textContent = publicIp.available ? publicIp.ip : "Не определён";
  $("#public-ip-flag").textContent = publicIp.flag || "◌";
  const location = [publicIp.city, publicIp.region, publicIp.country].filter(Boolean);
  $("#public-ip-location").textContent = publicIp.available
    ? (location.join(", ") || "Местоположение не определено")
    : "Сервис геолокации сейчас недоступен";
  $("#public-ip-provider").textContent = publicIp.provider || "Не определён";

  const subscriptionLabels = { active: "Активна", inactive: "Не активна", not_installed: "Не установлена" };
  const stateText = subscriptionLabels[subscription.state] || "Не установлена";
  $("#subscription-state").textContent = stateText;
  $("#subscription-state").className = `label subscription-${subscription.state || "not_installed"}`;
  $("#subscription-profile-state").textContent = subscription.staged ? "Ссылка сохранена" : stateText;
  $("#subscription-expiry").textContent = formatDate(subscription.expires_at);
  $("#subscription-note").textContent = subscription.configured
    ? subscription.reason === "expired"
      ? "Срок действия подписки истёк. Получите актуальную ссылку в личном кабинете."
      : subscription.reason === "link_unavailable"
        ? "Не удалось получить данные по установленной ссылке подписки."
        : subscription.expires_at
          ? "Статус и срок проверены по актуальной ссылке подписки."
          : "Подписка активна. Срок действия не указан в ответе по ссылке."
    : subscription.staged
      ? "Ссылка сохранена. Установите VPN-модули, чтобы создать профиль KatoVPN."
      : "Подписка не обнаружена. Укажите актуальную ссылку из личного кабинета в разделе «Прошивка».";
  if (document.activeElement !== $("#subscription-url")) $("#subscription-url").value = subscription.url || "";

  const wifi = report.wifi || [];
  $("#wifi-list").replaceChildren(...(wifi.length ? wifi.map((network) => {
    const row = document.createElement("div");
    row.className = "wifi-row";
    const main = document.createElement("div");
    main.className = "row-main";
    const name = document.createElement("strong");
    const details = document.createElement("small");
    name.textContent = network.ssid;
    details.textContent = `${formatRadioLabel(network.radio, wifi)} · канал ${network.channel} · ${network.encryption}`;
    main.append(name, details);
    const side = document.createElement("div");
    side.className = "row-side";
    const status = document.createElement("span");
    status.textContent = network.up ? "Работает" : "Отключена";
    const edit = document.createElement("button");
    edit.type = "button";
    edit.disabled = !safety.wifi_changes_enabled;
    edit.textContent = "Сменить пароль";
    edit.addEventListener("click", () => openWifiDialog("change_password", network));
    side.append(status, edit);
    row.append(main, side);
    return row;
  }) : [emptyRow("Wi‑Fi сети не найдены", "Возможно, беспроводной модуль отключён или отсутствует.")]));
  $("#create-wifi-button").disabled = !safety.wifi_create_enabled;

  $("#lan-ip").value = lan.ipaddr || state.routerSession?.host || "";
  $("#lan-state").textContent = lan.proto === "static" ? "Статический" : "Проверить режим";
  $("#lan-button").disabled = !safety.lan_changes_enabled;
  $("#router-password-button").disabled = !safety.password_change_enabled;

  const labels = { nikki: "VPN-модуль Nikki", mihomo: "Ядро Mihomo", adblock: "Блокировка рекламы" };
  $("#component-list").replaceChildren(...["nikki", "mihomo", "adblock"].map((key) => {
    const component = report.components?.[key] || {};
    const row = document.createElement("div");
    row.className = "component-row";
    const main = document.createElement("div");
    main.className = "row-main";
    const title = document.createElement("strong");
    const sub = document.createElement("small");
    title.textContent = labels[key];
    if (key === "adblock") {
      if (component.installed) sub.textContent = `Установлен${component.version ? ` · версия ${component.version}` : ""}`;
      else if (!component.eligible) sub.textContent = "Опционально для роутеров класса 512 МБ";
      else if (component.partial) sub.textContent = "Установлена только часть пакетов";
      else sub.textContent = "AdBlock + панель LuCI + русский язык";
    } else if (component.status === "runtime_missing") sub.textContent = `Пакет ${component.package_version || "установлен"}, но ядро не запускается`;
    else if (!component.installed) sub.textContent = "Не установлен";
    else if (key === "mihomo" && !component.managed) sub.textContent = `Работает · версия ${component.version || "не определена"} · пакет не зарегистрирован`;
    else sub.textContent = `Текущая версия ${component.version || "не определена"}`;
    main.append(title, sub);

    const side = document.createElement("div");
    side.className = "row-side";
    const status = document.createElement("span");
    status.className = `component-status ${component.update_available ? "available" : component.installed ? "current" : "missing"}`;
    if (key === "adblock") status.textContent = component.installed ? "Установлен" : component.eligible ? "Доступен" : "Не рекомендуется";
    else status.textContent = component.status === "runtime_missing"
      ? "Нужно восстановление"
      : component.update_available
        ? `Доступна ${component.latest}`
        : component.installed ? "Последняя версия" : "Требуется установка";
    const action = document.createElement("button");
    action.type = "button";
    action.setAttribute("data-update-component", key);
    if (key === "adblock") {
      action.textContent = component.installed ? "Установлен" : "Установить";
      action.disabled = !safety.adblock_install_enabled;
      action.addEventListener("click", startAdblockInstall);
    } else {
      action.textContent = component.update_available ? `Обновить` : component.installed ? "Актуально" : "Установить позже";
      action.disabled = !component.update_available;
      action.addEventListener("click", () => startUpdate(key));
    }
    side.append(status, action);
    row.append(main, side);
    return row;
  }));

  $("#install-readiness").classList.toggle("hidden", !compatibility.installation_needed);
  $("#install-readiness").classList.toggle("ready", compatibility.install_ready);
  $("#install-readiness").textContent = compatibility.install_ready
    ? "Роутер готов к установке VPN-модулей. Автоматическая чистая установка включится после аппаратного пилота."
    : `Для установки нужно исправить: ${(compatibility.blockers || []).map((item) => item.title).join(", ") || "проверку совместимости"}.`;

  const backups = report.backups || [];
  $("#backup-list").replaceChildren(...(backups.length ? backups.map((backup) => {
    const row = document.createElement("div");
    row.className = "backup-row";
    const main = document.createElement("div");
    main.className = "row-main";
    const title = document.createElement("strong");
    const sub = document.createElement("small");
    title.textContent = formatBackupId(backup.id);
    sub.textContent = `Настройки VPN · ${backup.size_kb || 0} КБ`;
    main.append(title, sub);
    const side = document.createElement("div");
    side.className = "row-side backup-actions";
    const restore = document.createElement("button");
    restore.type = "button";
    restore.textContent = "Восстановить";
    restore.disabled = !safety.backup_management_enabled;
    restore.addEventListener("click", () => restoreBackup(backup.id));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger-action";
    remove.textContent = "Удалить";
    remove.disabled = !safety.backup_management_enabled;
    remove.addEventListener("click", () => deleteBackup(backup.id));
    side.append(restore, remove);
    row.append(main, side);
    return row;
  }) : [emptyRow("Резервных копий пока нет", "Создайте копию перед экспериментами с профилем или обновлениями.")]));
  $("#backup-button").disabled = !safety.backup_management_enabled;
  $$(".log-download").forEach((button) => { button.disabled = !safety.log_export_enabled; });
}

function formatBackupId(id) {
  const match = String(id).match(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-/);
  if (!match) return id;
  return `${match[3]}.${match[2]}.${match[1]} · ${match[4]}:${match[5]}`;
}

async function refreshDashboard({ quiet = false } = {}) {
  const button = $("#refresh-button");
  if (!quiet) button.classList.add("busy");
  try {
    const payload = await api("/api/router/refresh", { method: "POST", body: "{}" });
    showApp(payload.router_session);
  } catch (error) {
    if (["router_session_required", "router_fingerprint_changed"].includes(error.payload?.code)) showLogin();
    showError(error.message);
  } finally {
    button.classList.remove("busy");
  }
}

function openOperation(title, message) {
  $("#operation-title").textContent = title;
  $("#operation-message").textContent = message;
  $("#operation-steps").replaceChildren();
  $("#operation-panel").classList.remove("hidden");
}

function renderJob(job) {
  $("#operation-steps").replaceChildren(...(job.steps || []).map((step) => {
    const item = document.createElement("li");
    item.className = step.state;
    item.textContent = step.message;
    return item;
  }));
  if (job.status === "success") {
    const operation = job.result?.operation;
    const messages = {
      subscription: "Подписка загружена. VPN-модули не обновлялись.",
      backup: "Резервная копия настроек VPN создана.",
      backup_delete: "Выбранная резервная копия удалена.",
      restore: "Настройки VPN восстановлены и проверены.",
      adblock_install: "AdBlock и русская панель управления установлены.",
      wifi_password: "Новый пароль Wi‑Fi подтверждён. Автоматический откат отменён.",
      wifi_create: "Новая Wi‑Fi сеть создана и подтверждена.",
      lan_ip: `Локальный адрес изменён на ${job.result?.new_ip}.`,
      router_password: "Новый пароль роутера подтверждён. Приложение продолжит использовать его только в текущей сессии.",
    };
    $("#operation-title").textContent = "Готово";
    if (operation === "update") {
      const updated = Object.entries(job.result?.component_updates || {})
        .filter(([, version]) => version)
        .map(([key, version]) => `${key === "nikki" ? "Nikki" : "Mihomo"} ${version}`);
      $("#operation-message").textContent = updated.length ? `Обновлено: ${updated.join(", ")}.` : "Компонент уже актуален.";
    } else {
      $("#operation-message").textContent = messages[operation] || "Операция завершена и проверена.";
    }
  } else if (job.status === "failed") {
    const details = job.error?.details || {};
    $("#operation-title").textContent = details.rolled_back ? "Изменение отменено" : "Операция не завершена";
    $("#operation-message").textContent = details.rolled_back
      ? `${job.error?.message || "Изменение не применено"} Предыдущие настройки восстановлены.`
      : job.error?.message || "Обновите сведения и проверьте состояние роутера.";
  }
}

async function pollJob(jobId) {
  window.clearTimeout(state.pollTimer);
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}`);
    renderJob(payload.job);
    if (["queued", "running"].includes(payload.job.status)) {
      state.pollTimer = window.setTimeout(() => pollJob(jobId), 1000);
    } else {
      await refreshDashboard({ quiet: true });
    }
  } catch (error) {
    showError(error.message);
  }
}

async function startJob(path, body, title, message) {
  openOperation(title, message);
  try {
    const payload = await api(path, { method: "POST", body: JSON.stringify(body) });
    pollJob(payload.job_id);
  } catch (error) {
    showError(error.message);
    $("#operation-panel").classList.add("hidden");
  }
}

async function startUpdate(componentKey) {
  const component = state.routerSession?.dashboard?.components?.[componentKey];
  if (!component?.update_available) return showError("Для этого модуля нет совместимого обновления.");
  const name = componentKey === "nikki" ? "Nikki" : "Mihomo";
  if (!window.confirm(`Перед обновлением ${name} приложение создаст резервную копию настроек. Продолжить?`)) return;
  startJob("/api/router/update-components", {
    confirmed: true,
    update_nikki: componentKey === "nikki",
    update_mihomo: componentKey === "mihomo",
  }, `Обновление ${name}`, "Пакет будет загружен и проверен до изменения роутера.");
}

async function startAdblockInstall() {
  if (!window.confirm("Будут установлены три официальных пакета: AdBlock, панель LuCI и русский язык. Продолжить?")) return;
  startJob("/api/router/install-adblock", { confirmed: true }, "Установка AdBlock", "Сначала пакетный менеджер выполнит проверку без изменений.");
}

async function configureSubscription(event) {
  event.preventDefault();
  const url = $("#subscription-url").value.trim();
  if (!url) return showError("Введите HTTPS-ссылку подписки.");
  const components = state.routerSession?.dashboard?.components || {};
  const ready = Boolean(components.nikki?.installed && components.mihomo?.installed);
  const confirmation = ready
    ? "Приложение создаст резервную копию и установит или обновит профиль KatoVPN. Продолжить?"
    : "VPN-модули ещё не установлены. Ссылка будет проверена и сохранена только в текущей сессии приложения. Продолжить?";
  if (!window.confirm(confirmation)) return;
  openOperation(ready ? "Обновление подписки" : "Сохранение ссылки", ready ? "Проверяем подписку и настройки VPN." : "Проверяем ссылку без изменения роутера.");
  try {
    const payload = await api("/api/router/configure-subscription", {
      method: "POST", body: JSON.stringify({ confirmed: true, subscription_url: url }),
    });
    if (payload.status === "staged") {
      showApp(payload.router_session);
      $("#operation-title").textContent = "Ссылка сохранена";
      $("#operation-message").textContent = "Роутер не изменён. Ссылка будет использована после установки VPN-модулей.";
      return;
    }
    pollJob(payload.job_id);
  } catch (error) {
    showError(error.message);
    $("#operation-panel").classList.add("hidden");
  }
}

function openWifiDialog(action, network = null) {
  const report = state.routerSession?.dashboard || {};
  const networks = report.wifi || [];
  const radios = [...new Set(networks.map((item) => item.radio).filter(Boolean))];
  $("#wifi-radio").replaceChildren(...radios.map((radio) => {
    const option = document.createElement("option");
    option.value = radio;
    option.textContent = formatRadioLabel(radio, networks);
    return option;
  }));
  $("#wifi-action").value = action;
  $("#wifi-section").value = network?.section || "";
  $("#wifi-radio").value = network?.radio || radios[0] || "";
  $("#wifi-radio").disabled = action === "change_password";
  $("#wifi-ssid-field").classList.toggle("hidden", action !== "create");
  $("#wifi-dialog-title").textContent = action === "create" ? "Создать Wi‑Fi сеть" : `Сменить пароль · ${network?.ssid || "Wi‑Fi"}`;
  $("#wifi-password").value = "";
  $("#wifi-ssid").value = "";
  $("#wifi-country").value = report.lan?.recommended_country || "RU";
  $("#wifi-dialog").showModal();
  window.setTimeout(() => (action === "create" ? $("#wifi-ssid") : $("#wifi-password")).focus(), 50);
}

async function submitWifi(event) {
  event.preventDefault();
  const action = $("#wifi-action").value;
  const payload = {
    confirmed: true,
    action,
    section: $("#wifi-section").value,
    radio: $("#wifi-radio").value,
    ssid: $("#wifi-ssid").value.trim(),
    password: $("#wifi-password").value,
    country: $("#wifi-country").value,
  };
  if (payload.password.length < 8) return showError("Пароль Wi‑Fi должен содержать минимум 8 символов.");
  if (action === "create" && !payload.ssid) return showError("Введите название новой Wi‑Fi сети.");
  const warning = "Связь может прерваться. Подключитесь с новым паролем в течение двух минут, иначе роутер вернёт прежние настройки. Продолжить?";
  if (!window.confirm(warning)) return;
  $("#wifi-dialog").close();
  startJob("/api/router/wifi", payload, action === "create" ? "Создание Wi‑Fi" : "Смена пароля Wi‑Fi", "Автоматический откат уже будет включён до изменения сети.");
}

async function changeLan(event) {
  event.preventDefault();
  const newIp = $("#lan-ip").value.trim();
  if (!newIp) return showError("Введите новый локальный IP роутера.");
  if (!window.confirm(`Роутер сменит адрес на ${newIp}. Возможно, потребуется переподключиться к сети. Без подтверждения сработает автоматический откат. Продолжить?`)) return;
  startJob("/api/router/lan-ip", { confirmed: true, new_ip: newIp }, "Смена локального IP", "Ожидайте переподключения. Приложение продолжит работать в этой вкладке.");
}

async function changeRouterPassword(event) {
  event.preventDefault();
  const newPassword = $("#router-new-password").value;
  const confirmation = $("#router-confirm-password").value;
  if (newPassword.length < 8) return showError("Новый пароль роутера должен содержать минимум 8 символов.");
  if (newPassword !== confirmation) return showError("Новый пароль и подтверждение не совпадают.");
  if (!window.confirm("Приложение сменит пароль администратора и проверит новый SSH-вход. При ошибке через две минуты вернётся прежний пароль. Продолжить?")) return;
  $("#router-new-password").value = "";
  $("#router-confirm-password").value = "";
  startJob(
    "/api/router/change-password",
    { confirmed: true, new_password: newPassword, confirm_password: confirmation },
    "Смена пароля роутера",
    "Проверяем новый вход, не сохраняя пароль на компьютере.",
  );
}

function createBackup() {
  if (!window.confirm("Создать новую резервную копию настроек VPN на роутере?")) return;
  startJob("/api/router/create-backup", { confirmed: true }, "Резервная копия", "Сохраняем настройки, подписки и mixin.");
}

function deleteBackup(backupId) {
  if (!window.confirm("Удалить выбранную резервную копию без возможности восстановления?")) return;
  startJob("/api/router/delete-backup", { confirmed: true, backup_id: backupId }, "Удаление копии", "Удаляется только выбранная папка резервной копии.");
}

function restoreBackup(backupId) {
  if (!window.confirm("Текущие настройки VPN будут сохранены в страховочную копию, затем выбранная версия будет восстановлена. Продолжить?")) return;
  startJob("/api/router/restore-backup", { confirmed: true, backup_id: backupId }, "Восстановление", "Создаём страховочную копию и проверяем результат.");
}

async function downloadLogs(kind, button) {
  const original = button.querySelector("span")?.textContent || "Скачать";
  setBusy(button, true, "Собираем…");
  try {
    const payload = await api("/api/router/export-logs", {
      method: "POST",
      body: JSON.stringify({
        kind,
        source: "all",
        lines: Number($("#log-lines").value) || 500,
      }),
    });
    const blob = new Blob([payload.text || ""], { type: "text/plain;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = payload.filename || "katovpn-debug.txt";
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(button, false, original);
  }
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#login-button");
  setBusy(button, true, "Проверяем роутер…");
  try {
    const payload = await api("/api/router/login", {
      method: "POST",
      body: JSON.stringify({
        host: $("#host").value.trim(), port: Number($("#port").value),
        username: $("#username").value.trim(), password: $("#password").value,
      }),
    });
    showApp(payload.router_session);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(button, false, "Подключиться");
  }
});

$("#toggle-password").addEventListener("click", () => {
  const input = $("#password");
  input.type = input.type === "password" ? "text" : "password";
  $("#toggle-password").textContent = input.type === "password" ? "Показать" : "Скрыть";
});

$$('[data-view]').forEach((button) => button.addEventListener("click", (event) => {
  event.preventDefault();
  switchView(button.dataset.view);
}));
$("#refresh-button").addEventListener("click", () => refreshDashboard());
$("#subscription-form").addEventListener("submit", configureSubscription);
$("#create-wifi-button").addEventListener("click", () => openWifiDialog("create"));
$("#wifi-form").addEventListener("submit", submitWifi);
$("[data-close-dialog]").addEventListener("click", () => $("#wifi-dialog").close());
$("#lan-form").addEventListener("submit", changeLan);
$("#router-password-form").addEventListener("submit", changeRouterPassword);
$("#support-start-button").addEventListener("click", startSupport);
$("#support-stop-button").addEventListener("click", stopSupport);
$("#support-copy-button").addEventListener("click", copySupportDetails);
$("#backup-button").addEventListener("click", createBackup);
$$('[data-log-kind]').forEach((button) => button.addEventListener("click", () => downloadLogs(button.dataset.logKind, button)));
$("#operation-close").addEventListener("click", () => $("#operation-panel").classList.add("hidden"));
$("#logout-button").addEventListener("click", async () => {
  try { await api("/api/router/logout", { method: "POST", body: "{}" }); } catch (_) {}
  showLogin();
});

async function boot() {
  initializeToken();
  maintainBrowserSession();
  const requestedView = window.location.hash.slice(1);
  if (["home", "internet", "firmware", "logs"].includes(requestedView)) state.activeView = requestedView;
  try {
    const payload = await api("/api/router/session");
    if (payload.router_session) showApp(payload.router_session);
    else showLogin();
  } catch (error) {
    showLogin();
    if (state.token) showError(error.message);
  }
}

boot();
