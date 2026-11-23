const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "../nikki-router-setup/web/app.js"), "utf8");
const render = source.slice(source.indexOf("function renderSupport("), source.indexOf("async function refreshSupportStatus("));
const elements = new Map();
const timers = new Map();
let nextTimer = 0;
const context = {
  state: { routerSession: {}, supportTimer: null, supportPollTimer: null, supportRevision: 0 },
  $: selector => {
    if (!elements.has(selector)) elements.set(selector, {
      textContent: "", className: "", disabled: false,
      classList: { toggle() {} },
    });
    return elements.get(selector);
  },
  window: {
    clearInterval: id => timers.delete(id), clearTimeout: id => timers.delete(id),
    setInterval: () => ++nextTimer,
    setTimeout: (callback, ms) => { timers.set(++nextTimer, { callback, ms }); return nextTimer; },
  },
  formatSupportExpiry: () => "expiry",
  refreshSupportStatus() {},
  Date, Math, String, Number,
};
vm.createContext(context);
vm.runInContext(render, context);
const support = { status: "active", code: "example", expires_at: Date.now() / 1000 + 3600 };
context.renderSupport({ ...support, connection_state: "recovering" });
assert.equal(elements.get("#support-state").textContent, "Восстанавливаем…");
assert.equal(elements.get("#support-code").textContent, support.code);
assert.equal([...timers.values()].filter(t => t.ms === 5000).length, 1);
context.renderSupport({ ...support, connection_state: "connected" });
assert.equal(elements.get("#support-state").textContent, "Подключён");
assert.equal([...timers.values()].filter(t => t.ms === 5000).length, 1);
context.renderSupport({ status: "stopping" });
assert.equal(elements.get("#support-state").textContent, "Отключаем…");
assert.equal(elements.get("#support-start-button").disabled, true);
assert.equal([...timers.values()].filter(t => t.ms === 5000).length, 1);
context.renderSupport({ status: "inactive" });
assert.equal([...timers.values()].filter(t => t.ms === 5000).length, 0);
async function checkStalePoll() {
  const refresh = source.slice(source.indexOf("async function refreshSupportStatus("), source.indexOf("async function startSupport("));
  vm.runInContext(refresh, context);
  let resolvePoll;
  context.api = () => new Promise(resolve => { resolvePoll = resolve; });
  context.showError = () => { throw new Error("Unexpected polling error"); };
  context.renderSupport(support);
  const pending = context.refreshSupportStatus({ quiet: true });
  context.renderSupport({ status: "inactive" });
  resolvePoll({ support });
  await pending;
  assert.equal(elements.get("#support-state").textContent, "Отключён");
  assert.equal([...timers.values()].filter(t => t.ms === 5000).length, 0);
}
checkStalePoll().then(() => console.log("Support UI tests passed")).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
