const test = require("node:test");
const assert = require("node:assert/strict");

const plugin = require("../plugin.js");

function createFakeApi(pluginConfig) {
  const hooks = new Map();
  const tools = [];

  return {
    pluginConfig,
    runtime: {},
    on(name, handler) {
      hooks.set(name, handler);
    },
    registerTool(factory) {
      tools.push(factory().name);
    },
    getHook(name) {
      return hooks.get(name);
    },
    getTools() {
      return tools.slice();
    },
  };
}

test.afterEach(() => {
  plugin.__internal.resetForTests();
});

test("enforce mode requires an explicit council endpoint", () => {
  assert.throws(
    () => plugin.__internal.resolvePluginConfig({ enforcement_mode: "enforce" }, {}),
    /council_endpoint is required/
  );
});

test("shadow mode requires an explicit council endpoint", () => {
  assert.throws(
    () => plugin.__internal.resolvePluginConfig({ enforcement_mode: "shadow" }, {}),
    /council_endpoint is required/
  );
});

test("audit mode is blocked unless explicitly opted in", () => {
  assert.throws(
    () => plugin.__internal.resolvePluginConfig({ enforcement_mode: "audit" }, {}),
    /audit mode is development-only/
  );

  const resolved = plugin.__internal.resolvePluginConfig(
    { enforcement_mode: "audit" },
    { GUARDSPINE_ALLOW_AUDIT_MODE: "1" }
  );
  assert.equal(resolved.mode, "audit");
});

test("register only exposes the safe tool surface", () => {
  const api = createFakeApi({
    enforcement_mode: "shadow",
    council_endpoint: "http://council.local",
  });

  plugin.register(api);

  const tools = api.getTools().sort();
  assert.deepEqual(
    tools,
    ["guardspine_audit_log", "guardspine_status", "memory_status"].sort()
  );
  assert.ok(!tools.includes("guardspine_approve"));
});
