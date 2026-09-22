// app/lib/wipe.js: "Clear all Reach data". Every store's chrome.storage.local
// literal key, this page's own localStorage and sessionStorage keys are
// gone after run(), unrelated keys are untouched, content scripts whose id
// this extension registered are unregistered, and an optional host grant
// is revoked only when asked. A fake chrome is installed before store.js
// (and everything wipe.js imports) loads, so this file runs alone.
import "./_splunk.js";
import "./_bundle.js"; // catalogue.js's data.js needs a fetch() stub at call time
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fakeChrome } from "./_chrome.js";

function memoryStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    has: (k) => m.has(k),
  };
}
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });

const fake = fakeChrome();
fake.install();
const { local, registered, permitted } = fake;
const grantedOrigins = () => Array.from(permitted);

const store = await import("../app/lib/store.js");
const layer = await import("../app/lib/layer.js");
const notebook = await import("../app/lib/notebook.js");
const benign = await import("../app/lib/benign.js");
const catalogue = await import("../app/lib/catalogue.js");
const falconDictionary = await import("../app/lib/falcon-dictionary.js");
const discoverySweep = await import("../app/lib/discovery-sweep.js");
const recipe = await import("../app/lib/recipe.js");
const runbooksStore = await import("../app/lib/runbooks-store.js");
const wipe = await import("../app/lib/wipe.js");
assert.equal(store.backend(), "chrome");

function seed() {
  local.clear();
  registered.splice(
    0,
    registered.length,
    { id: "reach-json-tree-https://splunk.example.com", matches: ["https://splunk.example.com/*"] },
    { id: "reach-sentinel-blade", matches: ["https://x.reactblade.portal.azure.net/*"] },
    { id: "not-reach-owned", matches: ["https://other.example.com/*"] }, // another extension's id shape; must survive
  );
  permitted.clear();
  permitted.add("https://splunk.example.com/*");
  permitted.add("https://www.virustotal.com/*");
  localStorage.setItem("reach.scope", "{}");
  localStorage.setItem("reach.pinned", "{}");
  localStorage.setItem("reach.splunkBase", "https://splunk.example.com:8000");
  localStorage.setItem("reach.platform", "splunk");
  localStorage.setItem("someOtherExtension.setting", "keep"); // not Reach's, must survive
  sessionStorage.setItem("reach.investigation", "{}");
  sessionStorage.setItem("reach.lastEvent", "{}");
  sessionStorage.setItem("unrelated.tabState", "keep");
  local.set("csIndex", "main");
  local.set("trustedOrigins", ["https://splunk.example.com"]);
  local.set("vtApiKey", "secret-key");
  local.set("reach.sentinel.alwaysPanel", true);
  local.set("reach.onboarding.dismissed", true);
  local.set("spAppNamespace", "search");
  local.set("reach.benign.inject", true);
  local.set("reach.enrich.circl.enabled", true);
  local.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  local.set("reach.modules", { enabled: { share: true } });
  localStorage.setItem("reach.theme", "dark");
  localStorage.setItem("reach.devExt", "abc");
  local.set("someOtherExtension.local", "keep"); // not Reach's, must survive
  local.set(`reach.${notebook.KEY}`, { investigations: [] });
  local.set(`reach.${benign.KEY}`, { entries: [] });
  local.set(`reach.${catalogue.USER_KEY}`, { fields: {} });
  local.set(`reach.${falconDictionary.KEY}`, { v: 1, source: "falcon-fdr-schema", fields: { X: { type: "string" } }, events: {}, counts: { fields: 1, fieldsWithValues: 0, events: 0 } });
  local.set(`reach.${discoverySweep.KEY}`, { running: false });
  local.set(`reach.${recipe.WORKSPACES_KEY}`, { w1: { name: "ws" } });
  local.set(`reach.${runbooksStore.KEY}`, { v: 1, runbooks: {} });
  local.set(`reach.${layer.INDEX_KEY}`, { envs: {} });
  local.set(`reach.${layer.PREFIX}https://splunk.example.com`, { sourcetypes: {} });
}

test("run(): every listed key is gone, unrelated keys survive", async () => {
  seed();
  const res = await wipe.run();

  for (const k of [
    "csIndex",
    "trustedOrigins",
    "vtApiKey",
    "reach.sentinel.alwaysPanel",
    "reach.onboarding.dismissed",
    "spAppNamespace",
    "reach.benign.inject",
    "reach.enrich.circl.enabled",
    "reach.enrich.selfhosted.origin",
    "reach.modules",
    `reach.${notebook.KEY}`,
    `reach.${benign.KEY}`,
    `reach.${catalogue.USER_KEY}`,
    `reach.${falconDictionary.KEY}`,
    `reach.${discoverySweep.KEY}`,
    `reach.${recipe.WORKSPACES_KEY}`,
    `reach.${runbooksStore.KEY}`,
    `reach.${layer.INDEX_KEY}`,
    `reach.${layer.PREFIX}https://splunk.example.com`,
  ]) {
    assert.equal(local.has(k), false, `${k} was not cleared`);
  }
  assert.equal(local.get("someOtherExtension.local"), "keep");

  for (const k of ["reach.scope", "reach.pinned", "reach.splunkBase", "reach.platform", "reach.theme", "reach.devExt"]) {
    assert.equal(localStorage.getItem(k), null, `${k} was not cleared`);
  }
  assert.equal(localStorage.getItem("someOtherExtension.setting"), "keep");

  assert.equal(sessionStorage.getItem("reach.investigation"), null);
  assert.equal(sessionStorage.getItem("reach.lastEvent"), null);
  assert.equal(sessionStorage.getItem("unrelated.tabState"), "keep");

  assert.equal(res.scriptsUnregistered, 2, "both reach- ids, not the unrelated one");
  assert.deepEqual(registered.map((s) => s.id), ["not-reach-owned"]);
});

test("run(): host permissions are untouched unless asked", async () => {
  seed();
  await wipe.run();
  assert.deepEqual(grantedOrigins(), ["https://splunk.example.com/*", "https://www.virustotal.com/*"]);
});

test("run({ revokeHosts: true }): every granted origin is removed and reported", async () => {
  seed();
  const res = await wipe.run({ revokeHosts: true });
  assert.deepEqual(grantedOrigins(), []);
  assert.deepEqual(res.hostsRevoked.sort(), ["https://splunk.example.com/*", "https://www.virustotal.com/*"].sort());
});

test("run(): degrades to local/session only with no chrome (the served harness)", async () => {
  seed();
  const saved = globalThis.chrome;
  delete globalThis.chrome;
  try {
    const res = await wipe.run();
    assert.equal(localStorage.getItem("reach.scope"), null);
    assert.equal(sessionStorage.getItem("reach.investigation"), null);
    assert.equal(res.scriptsUnregistered, 0);
    assert.deepEqual(res.hostsRevoked, []);
  } finally {
    globalThis.chrome = saved;
  }
});

test("clearModule(id): only that module's keys go; every other module's data survives", async () => {
  seed();
  const removed = await wipe.clearModule("virustotal");
  assert.deepEqual(removed, ["vtApiKey"]);
  assert.equal(local.has("vtApiKey"), false);
  assert.equal(local.has("reach.enrich.circl.enabled"), true);
  assert.equal(local.has(`reach.${notebook.KEY}`), true);
  assert.equal(localStorage.getItem("reach.pinned"), "{}");

  await wipe.clearModule("discovery");
  for (const k of [`reach.${discoverySweep.KEY}`, `reach.${recipe.WORKSPACES_KEY}`, `reach.${layer.INDEX_KEY}`, `reach.${layer.PREFIX}https://splunk.example.com`]) {
    assert.equal(local.has(k), false, `${k} was not cleared with the discovery module`);
  }
  assert.equal(localStorage.getItem("reach.devExt"), null);
  assert.equal(local.has(`reach.${catalogue.USER_KEY}`), true, "the catalogue's own layer is not discovery's");
  assert.equal(local.has(`reach.${falconDictionary.KEY}`), true, "the imported Falcon dictionary is not discovery's either");
  assert.equal(local.has(`reach.${benign.KEY}`), true);

  await wipe.clearModule("catalogue");
  assert.equal(local.has(`reach.${falconDictionary.KEY}`), false, "clearing the catalogue module clears the imported Falcon dictionary");
  assert.equal(local.has(`reach.${catalogue.USER_KEY}`), false);

  await wipe.clearModule("hold");
  assert.equal(local.has(`reach.${notebook.KEY}`), false);
  assert.equal(localStorage.getItem("reach.pinned"), null);
  assert.equal(local.has(`reach.${runbooksStore.KEY}`), true, "the runbooks are their own module's");

  await wipe.clearModule("runbooks");
  assert.equal(local.has(`reach.${runbooksStore.KEY}`), false);
  assert.equal(sessionStorage.getItem("reach.investigation"), null);
  assert.equal(sessionStorage.getItem("reach.lastEvent"), null);
  assert.equal(local.has("reach.modules"), true, "the enabled set is the shell's, not hold's");
});

test("run() is the union over every module: nothing a module owns survives it", async () => {
  seed();
  const res = await wipe.run();
  const modules = await import("../app/lib/modules.js");
  for (const m of modules.MODULES) {
    const k = modules.keysOf(m.id);
    for (const key of k.chrome) assert.equal(local.has(key), false, `${m.id}: ${key}`);
    for (const key of k.store) assert.equal(local.has(`reach.${key}`), false, `${m.id}: reach.${key}`);
    for (const key of k.local) assert.equal(localStorage.getItem(key), null, `${m.id}: ${key}`);
    for (const key of k.session) assert.equal(sessionStorage.getItem(key), null, `${m.id}: ${key}`);
  }
  assert.ok(res.storage.includes("reach.modules"));
  assert.ok(res.local.includes("reach.theme"));
  assert.ok(res.session.includes("reach.lastEvent"));
  assert.ok(!res.storage.includes("catalogue.user.bindings"), "a field clear is not reported as a key");
});

test("switching a module off through the registry clears its keys and revokes its hosts", async () => {
  seed();
  const modules = await import("../app/lib/modules.js");
  modules.reset();
  await modules.hydrate();
  permitted.clear();
  permitted.add("https://splunk.example.com/*");
  permitted.add("https://www.virustotal.com/*");
  local.set("reach.modules", { enabled: { virustotal: true } });
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("virustotal", "splunk"), true);
  const res = await modules.setEnabled("virustotal", false);
  assert.equal(res.ok, true);
  assert.deepEqual(res.hostsRevoked, ["https://www.virustotal.com/*"]);
  assert.deepEqual(res.removed, ["vtApiKey"]);
  assert.equal(local.has("vtApiKey"), false);
  assert.deepEqual(grantedOrigins(), ["https://splunk.example.com/*"]);
  assert.equal(modules.on("virustotal", "splunk"), false);
  assert.equal(local.get("reach.modules").enabled.virustotal, false);
});

test("switching a non-credential module off leaves every key it owns; only Clear removes them (S: Off keeps data)", async () => {
  seed();
  const modules = await import("../app/lib/modules.js");
  local.set("reach.catalogue.discovered.envs", { a: 1 });
  local.set("reach.catalogue.discovery.sweep", { b: 1 });
  local.set("reach.modules", { enabled: { discovery: true } });
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("discovery", "splunk"), true);
  const res = await modules.setEnabled("discovery", false);
  assert.equal(res.ok, true);
  assert.deepEqual(res.removed, [], "discovery owns no credential or grant key");
  assert.equal(local.has("reach.catalogue.discovered.envs"), true, "the swept environment survives Off");
  assert.equal(local.has("reach.catalogue.discovery.sweep"), true);
  assert.equal(modules.on("discovery", "splunk"), false, "the module is still off");
  const cleared = await wipe.clearModule("discovery");
  assert.ok(cleared.includes("reach.catalogue.discovered.envs"), "Clear still removes it");
  assert.equal(local.has("reach.catalogue.discovered.envs"), false);
});

test("switching selfhosted off removes only the origin and token, not the provider it also holds (S: only secret-marked keys go on Off)", async () => {
  seed();
  const modules = await import("../app/lib/modules.js");
  local.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  local.set("reach.enrich.selfhosted.token", "tok");
  local.set("reach.enrich.selfhosted.provider", "intelowl");
  permitted.add("https://misp.example.org/*");
  local.set("reach.modules", { enabled: { selfhosted: true } });
  modules.reset();
  await modules.hydrate();
  assert.equal(modules.on("selfhosted", "splunk"), true);
  const res = await modules.setEnabled("selfhosted", false);
  assert.equal(res.ok, true);
  assert.deepEqual(res.hostsRevoked, ["https://misp.example.org/*"]);
  assert.deepEqual(res.removed.sort(), ["reach.enrich.selfhosted.origin", "reach.enrich.selfhosted.token"].sort());
  assert.equal(local.has("reach.enrich.selfhosted.origin"), false);
  assert.equal(local.has("reach.enrich.selfhosted.token"), false);
  assert.equal(local.has("reach.enrich.selfhosted.provider"), true, "the provider choice is not a credential and survives Off");
  assert.equal(local.get("reach.enrich.selfhosted.provider"), "intelowl");

  const cleared = await wipe.clearModule("selfhosted");
  assert.ok(cleared.includes("reach.enrich.selfhosted.provider"), "Clear removes the rest");
  assert.equal(local.has("reach.enrich.selfhosted.provider"), false);
});

test("switching circl or epss off leaves their flag key; the worker still gates on the module set alone", async () => {
  seed();
  const modules = await import("../app/lib/modules.js");
  local.set("reach.modules", { enabled: { circl: true } });
  modules.reset();
  await modules.hydrate();
  const res = await modules.setEnabled("circl", false);
  assert.deepEqual(res.removed, [], "circl's flag key is module state, not a credential");
});

test("switching verdicts off clears the fleet corpus from every discovered environment and leaves the rest of discovery in place", async () => {
  seed();
  const corpus = { at: "2026-09-20T00:00:00Z", window: "-30d", source: "splunk", columns: ["sha256", "path", "signing_id", "platform", "hosts", "events", "first_seen", "last_seen"], rows: [["ab", "/x", "", "Mac", 1, 1, 1, 1]], received: 1, kept: 1, pruned: 0 };
  await layer.update("https://splunk.example.com", (e) => {
    e.org_corpus = corpus;
    e.sourcetypes["a:feed"] = { indexes: ["main"], count: 1, fields: {} };
  });
  await layer.update("/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z", (e) => {
    e.org_corpus = { ...corpus, source: "sentinel" };
  });
  const removed = await wipe.clearModule("verdicts");
  assert.deepEqual(removed, ["catalogue.discovered.org_corpus"]);
  const all = await layer.readAll();
  assert.equal(Object.keys(all).length, 2, "both environments stay");
  for (const env of Object.values(all)) assert.equal(env.org_corpus, undefined, "no fleet corpus survives the verdicts module going off");
  assert.deepEqual(all["https://splunk.example.com"].sourcetypes["a:feed"].indexes, ["main"], "the discovery module's own records stay");
});

// A new store's exported KEY/KEYS/PREFIX constant is easy to add and easy
// to forget to wire into wipe.js. This does not run wipe.js's own logic;
// it fails loudly the moment app/lib grows a storage-key export this file
// has not been told about, so the next person adds a line above instead of
// shipping a silent gap.
const KNOWN_KEY_EXPORTERS = new Set([
  "benign.js", // KEY, in storeDocKeys()
  "catalogue.js", // USER_KEY, in storeDocKeys()
  "discovery-sweep.js", // KEY, in storeDocKeys()
  "falcon-dictionary.js", // KEY, catalogue.falcon, registered under the catalogue module
  "storage-keys.js", // KEYS, the literal chrome.storage.local and localStorage names the registry lists
  "layer.js", // PREFIX, INDEX_KEY, in storeDocKeys()
  "modules.js", // KEY, the enabled module set, in storeDocKeys()
  "notebook.js", // KEY, in storeDocKeys()
  "recipe.js", // WORKSPACES_KEY, in storeDocKeys()
  "runbooks-store.js", // KEY, in storeDocKeys()
  "scope.js", // SCOPE_KEYS is the set of fact names ("index", "workspace"), not a storage key
  "searches.js", // KEY, in storeDocKeys()
  "wipe.js", // this file's own ENRICH_SETTING_KEYS
]);

test("app/lib has no exported *KEY*/*KEYS*/PREFIX constant outside the known set wipe.js accounts for", async () => {
  const dir = new URL("../app/lib/", import.meta.url);
  const files = (await readdir(dir)).filter((f) => f.endsWith(".js"));
  const unexpected = [];
  for (const f of files) {
    const src = await readFile(new URL(f, dir), "utf8");
    if (/^export const [A-Za-z_]*(KEY|KEYS|PREFIX)\b/m.test(src) && !KNOWN_KEY_EXPORTERS.has(f)) unexpected.push(f);
  }
  assert.deepEqual(unexpected, [], "add the new key to app/lib/wipe.js and to KNOWN_KEY_EXPORTERS above");
});
