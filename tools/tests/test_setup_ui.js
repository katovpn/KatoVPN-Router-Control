const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

test("maintenance renders only VPN even when a legacy dashboard includes AdBlock", () => {
  const { node, context } = loadApp(async () => ({ ok: true, json: async () => ({ router_session: null }) }));
  vm.runInContext(`renderDashboard({ components: {
    nikki: { installed: true }, mihomo: { installed: true },
    adblock: { installed: true, eligible: true, update_available: true }
  }, safety: { adblock_install_enabled: true } });`, context);
  assert.equal(node("#component-list").children.length, 1);
  assert.equal(node("#component-list").children[0].children[0].children[0].textContent, "VPN-модуль");
  assert.equal(typeof context.startAdblockInstall, "undefined");
});

function element() {
  const listeners = {};
  const classes = new Set();
  return {
    value: "", textContent: "", className: "", disabled: false, style: {},
    children: [],
    classList: { add(name) { classes.add(name); }, remove(name) { classes.delete(name); }, toggle(name, force) { if (force === false) classes.delete(name); else classes.add(name); }, contains(name) { return classes.has(name); } },
    append(...items) { this.children.push(...items); }, appendChild(item) { this.children.push(item); },
    replaceChildren(...items) { this.children = items; }, remove() {}, select() {}, focus() {},
    querySelector() { return element(); }, addEventListener(type, handler) { listeners[type] = handler; },
    trigger(type) { return listeners[type]?.({ preventDefault() {} }); },
    toggleAttribute() {}, close() {},
  };
}

function loadApp(fetch) {
  const nodes = new Map();
  const get = (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, element());
    return nodes.get(selector);
  };
  const unrefTimeout = (callback, milliseconds) => {
    const timer = setTimeout(callback, milliseconds);
    timer.unref();
    return timer;
  };
  const window = {
    location: { search: "", pathname: "/", hash: "" }, history: { replaceState() {} },
    sessionStorage: { getItem() { return ""; }, setItem() {} },
    setTimeout: unrefTimeout, clearTimeout, setInterval, clearInterval, confirm() { return true; },
    addEventListener() {}, crypto: { randomUUID() { return "test"; } },
  };
  const context = {
    window, document: { title: "", querySelector: get, querySelectorAll() { return []; }, createElement: element, activeElement: null },
    fetch, URLSearchParams, AbortController, Error, Promise, Map, Set, Date, Number, String, Object,
    Intl, console, navigator: { clipboard: { writeText() { return Promise.resolve(); } } },
  };
  vm.runInNewContext(fs.readFileSync("tools/nikki-router-setup/web/app.js", "utf8"), context);
  return { node: get, window, context };
}

test("subscription setup submits the automatic setup job instead of a package update or legacy subscription route", async () => {
  const calls = [];
  const { node } = loadApp(async (path, options = {}) => {
    calls.push({ path, options });
    if (path === "/api/router/session") return { ok: true, json: async () => ({ router_session: null }) };
    return { ok: true, json: async () => ({ job_id: "setup-job" }) };
  });
  node("#subscription-url").value = "https://setup.example.test/subscription";

  await node("#subscription-form").trigger("submit");

  const setup = calls.find((call) => call.path === "/api/router/setup-vpn");
  assert.ok(setup, "the setup endpoint must be used");
  assert.deepEqual(JSON.parse(setup.options.body), {
    confirmed: true,
    subscription_url: "https://setup.example.test/subscription",
  });
  assert.equal(calls.some((call) => call.path === "/api/router/update-components"), false);
  assert.equal(calls.some((call) => call.path === "/api/router/configure-subscription"), false);
});

test("ready and unknown setup states keep the LAN verification limit visible", async () => {
  const dashboard = (setup) => ({ host: "192.0.2.1", port: 22, dashboard: { setup } });
  let loginCount = 0;
  const { node } = loadApp(async (path) => ({ ok: true, json: async () => path === "/api/router/login" ? {
    router_session: dashboard(loginCount++ === 0
      ? { state: "ready", action: "refresh", warnings: [], details: {} }
      : { state: "unknown", action: "blocked", warnings: [], details: {} }),
  } : {} }));
  await node("#login-form").trigger("submit");
  assert.equal(node("#subscription-profile-state").textContent, "Готово");
  assert.match(node("#subscription-action-note").textContent, /домашней сети требует отдельной проверки/);
  await node("#login-form").trigger("submit");
  assert.equal(node("#subscription-profile-state").textContent, "Нужно проверить");
  assert.equal(node("#subscription-button").disabled, true);
});

test("setup request failure closes the operation panel and clears active setup state", async () => {
  const { node, context } = loadApp(async (path) => {
    if (path === "/api/router/session") return { ok: true, json: async () => ({ router_session: null }) };
    if (path === "/api/router/setup-vpn") return { ok: false, json: async () => ({ error: { message: "Настройка недоступна" } }) };
    return { ok: true, json: async () => ({}) };
  });
  node("#subscription-url").value = "https://setup.example.test/subscription";
  await node("#subscription-form").trigger("submit");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(node("#error-message").textContent, "Настройка недоступна");
  assert.equal(node("#operation-panel").classList.contains("hidden"), true);
  assert.equal(vm.runInContext("state.activeOperation", context), null);
});

test("setup job failure keeps package state generic and puts diagnostics behind details", () => {
  const { node, context } = loadApp(async () => ({ ok: true, json: async () => ({ router_session: null }) }));
  vm.runInContext(`state.activeOperation = "setup"; renderJob({
    status: "failed", steps: [{ id: "apply", state: "error", message: "raw backend step" }],
    error: { code: "setup_verification", message: "raw backend error", details: {
      packages_installed: true, package_diagnostic: "raw package diagnostic"
    }}
  });`, context);
  assert.match(node("#operation-message").textContent, /VPN-компоненты установлены/);
  assert.equal(node("#operation-details-list").children.map((item) => item.textContent).join(" | "),
    "raw backend step | Код: setup_verification | raw backend error | raw package diagnostic");
});

test("setup success retains warnings from both result locations", () => {
  const { node, context } = loadApp(async () => ({ ok: true, json: async () => ({ router_session: null }) }));
  vm.runInContext(`state.activeOperation = "setup"; renderJob({
    status: "success", steps: [], result: { operation: "setup",
      warnings: [{ code: "external_proxy" }], setup: { warnings: [{ code: "external_dns" }] }
    }
  });`, context);
  const warning = "На роутере обнаружены дополнительные сетевые настройки. Они могут влиять на работу KatoVPN.";
  assert.equal(node("#operation-message").textContent.split(warning).length - 1, 2);
});

test("dashboard shows the generic setup state and the external network warning", async () => {
  const { node } = loadApp(async (path) => ({
    ok: true,
    json: async () => path === "/api/router/login" ? {
      router_session: {
        host: "192.0.2.1", port: 22,
        dashboard: {
          setup: {
            state: "needs_configuration", action: "configure",
            message: "Нужно настроить роутер для работы с KatoVPN.",
            warnings: [{ code: "external_network_settings", message: "internal detail" }],
            details: {},
          },
        },
      },
    } : {},
  }));
  await node("#login-form").trigger("submit");

  assert.equal(node("#subscription-profile-state").textContent, "Нужно настроить");
  assert.equal(node("#subscription-action-note").textContent, "Нужно настроить роутер для работы с KatoVPN.");
  assert.equal(node("#setup-warnings").children[0].textContent,
    "На роутере обнаружены дополнительные сетевые настройки. Они могут влиять на работу KatoVPN.");
});
