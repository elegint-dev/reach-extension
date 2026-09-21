// The discovered layer on store.js's chrome.storage.local backend, the one
// the extension runs on: load() indexes the per-environment keys, a write
// fires one change event for its environment (through onChanged, none for
// the index), and the catalogue patches one environment per event. The fake is installed
// before store.js loads, so this file runs alone.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

const { chrome, local } = fakeChrome();
const log = [];
chrome.storage.onChanged.addListener((changes) => {
  for (const [k, ch] of Object.entries(changes)) log.push(`${ch.newValue === undefined ? "remove" : "set"} ${k}`);
});
globalThis.chrome = chrome;

const store = await import("../app/lib/store.js");
const layer = await import("../app/lib/layer.js");
assert.equal(store.backend(), "chrome");

const A = "https://one.splunk.test";
const B = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws";

test("chrome backend: load() indexes every environment key and leaves other keys alone", async () => {
  const envs = {
    [A]: { sourcetypes: { "aws:cloudtrail": { indexes: ["main"], count: 5, fields: { user: { profile: { count: 5, top: [{ value: "bob", count: 5 }] } } }, runs: [{ kind: "profile", at: "2026-09-11T00:00:00Z" }] } }, discovered_at: "2026-09-11T00:00:00Z" },
    [B]: { sourcetypes: { SigninLogs: { indexes: [], count: 0, fields: {} } }, steps: {}, resourceId: B, discovered_at: "2026-09-12T00:00:00Z" },
  };
  local.set(`reach.catalogue.discovered.${A}`, envs[A]);
  local.set(`reach.catalogue.discovered.${B}`, envs[B]);
  local.set("reach.notebook", { investigations: [] });
  const index = await layer.load();
  assert.deepEqual(Object.keys(index.envs).sort(), [A, B].sort());
  assert.deepEqual(local.get("reach.catalogue.discovered.envs").envs[A], { discovered_at: "2026-09-11T00:00:00Z", bytes: layer.bytes(envs[A]) });
  assert.deepEqual(log, ["set reach.catalogue.discovered.envs"]);
  assert.deepEqual(await layer.readAll(), envs);
  assert.ok(local.has("reach.notebook"), "other keys are untouched");
});

test("chrome backend: one change event per environment written, none for the index; another context's write is seen", async () => {
  const seen = [];
  const off = layer.subscribe((k, env) => seen.push([k, env ? Object.keys(env.sourcetypes).sort() : undefined]));
  const { notice } = await layer.update(A, (e) => (e.sourcetypes["b:feed"] = { indexes: [], count: 1, fields: {} }));
  assert.equal(notice, "");
  assert.deepEqual(seen, [[A, ["aws:cloudtrail", "b:feed"]]]);
  // A popup on the Splunk page writes the same key: this context hears it.
  const other = local.get(`reach.catalogue.discovered.${A}`);
  other.sourcetypes["from:popup"] = { indexes: [], count: 0, fields: {} };
  await chrome.storage.local.set({ [`reach.catalogue.discovered.${A}`]: other });
  assert.deepEqual(seen.at(-1), [A, ["aws:cloudtrail", "b:feed", "from:popup"]]);
  await layer.forget(B);
  assert.deepEqual(seen.at(-1), [B, undefined]);
  off();
  assert.equal(local.get("reach.catalogue.discovered.envs").envs[B], undefined);
});

test("chrome backend: readAll reads each environment by its own key and the index alone lists them", async () => {
  local.set(`reach.catalogue.discovered.https://orphan.test`, { sourcetypes: {}, discovered_at: "2026-01-01T00:00:00Z" });
  assert.deepEqual(Object.keys(await layer.readAll()), [A], "an orphan is invisible until load() reconciles");
  await layer.load();
  assert.deepEqual(Object.keys(await layer.readAll()).sort(), [A, "https://orphan.test"].sort());
});
