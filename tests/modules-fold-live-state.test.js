// The settings surface's per-row fold reads its own state live, not the
// registry's static shape: it_e399e301, three bugs from one live repro.
//   1. a freshly mounted row's fold has its lines filled with no click
//   2. the storage-keys line is a live read, so it reflects Off keeping
//      a non-credential module's data and Clear removing it in full
//   3. Clear runs the module's own full wipe, not Off's, and says so
// Checked on both surfaces (options.html's context and the panel fold's)
// and, where a module draws on both, both platforms.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import * as store from "../app/lib/store.js";
import { moduleList } from "../app/components/moduleList.js";

dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };

function rowFor(list, id) {
  const rows = dom.walk(list, (n) => n.attributes && n.attributes["data-module"]);
  return rows.find((n) => n.attributes["data-module"] === id);
}
function keysLineText(row) {
  const el = dom.walk(row, (n) => n.classList && n.classList.contains("r-module__keys"))[0];
  return el ? dom.text(el) : "";
}
function pillOf(row) {
  return dom.walk(row, (n) => n.classList && n.classList.contains("r-module__pill"))[0];
}
function statusOf(row) {
  return dom.walk(row, (n) => n.classList && n.classList.contains("r-module__status"))[0];
}
// 50ms, not 10: the fake now answers storage on a real macrotask, and a
// wipe chains several sequential reads and writes, each its own hop.
function tick(n = 50) {
  return new Promise((resolve) => setTimeout(resolve, n));
}

async function fresh() {
  modules.reset();
  await modules.hydrate();
}

for (const context of ["options", "panel"]) {
  for (const platform of ["splunk", "sentinel"]) {
    test(`${context}/${platform}: a freshly mounted row's storage-keys line reads live state with no click (S: freshly mounted fold is filled, not stale)`, async () => {
      const restore = fakeChrome().install();
      try {
        // discovery declares five key names in the registry but nothing is
        // written yet: the static name-count (5) must not appear here.
        await fresh();
        const list = moduleList({ platform, context });
        const row = rowFor(list, "discovery");
        await tick();
        assert.equal(keysLineText(row), "0 stored keys Clear", "nothing written yet, so nothing stored");
      } finally {
        restore();
      }
    });

    test(`${context}/${platform}: Off stops the module but keeps its stored data; the keys line stays live either way (S: Off keeps data)`, async () => {
      const restore = fakeChrome().install();
      try {
        await store.set("catalogue.discovered.envs", { a: 1 });
        await store.set("catalogue.discovery.sweep", { b: 1 });
        await store.set("sentinel.workspaces", { c: 1 });
        await fresh();
        const list = moduleList({ platform, context });
        const row = rowFor(list, "discovery");
        await tick();
        assert.equal(keysLineText(row), "3 stored keys Clear", "three keys actually written, read live");

        dom.fire(pillOf(row), "click"); // On -> Off
        await tick();
        assert.equal(pillOf(row).textContent, "Off");
        assert.equal(keysLineText(row), "3 stored keys Clear", "discovery owns no credential key, so Off leaves its data alone");
        assert.deepEqual(await store.get("catalogue.discovered.envs"), { a: 1 }, "the key survives Off");

        const clearBtn = dom.walk(row, (n) => n.tagName === "BUTTON" && n.textContent === "Clear")[0];
        dom.fire(clearBtn, "click");
        await tick();
        assert.equal(keysLineText(row), "0 stored keys Clear", "Clear still removes everything the module owns");
        assert.equal(await store.get("catalogue.discovered.envs"), undefined, "Clear actually removed the key");
      } finally {
        restore();
      }
    });

    test(`${context}/${platform}: Clear wipes the module's keys, says so, and is not gated on the pill (S: Clear runs Off's wipe)`, async () => {
      const restore = fakeChrome().install();
      try {
        await store.set("benign", { "field:sourcetype": ["value"] });
        await store.setLiteral({ "reach.benign.inject": true });
        await fresh();
        const list = moduleList({ platform, context });
        const row = rowFor(list, "benign");
        await tick();
        assert.equal(keysLineText(row), "2 stored keys Clear");

        const clearBtn = dom.walk(row, (n) => n.tagName === "BUTTON" && n.textContent === "Clear")[0];
        dom.fire(clearBtn, "click");
        await tick();

        assert.equal(keysLineText(row), "0 stored keys Clear", "Clear's wipe ran and the count was re-read");
        assert.equal(statusOf(row).textContent, "Cleared.");
        assert.equal(pillOf(row).textContent, "On", "Clear does not switch the module off");
        assert.equal(await store.get("benign"), undefined);
      } finally {
        restore();
      }
    });
  }
}

// The mount path under a slow chrome.storage.local: it_0534c648's report
// was that a served page's harness reads localStorage synchronously and so
// never sees the row paint before its read resolves. A fake whose get()
// answers on a later timer, not the same tick, stands in for the real
// extension's IPC round trip; this is a guard, not a fail-on-main
// regression, since cf86227 (1.0.11) already made the keys line and every
// drafted setting input self-refresh on their own promise, independent of
// modules.hydrate(); this test pins that so a future change cannot regress
// it silently.
test("the settings surface has nothing to show before a slow chrome.storage.local resolves, and the right thing after, with no click", async () => {
  const c = fakeChrome();
  const rawGet = c.chrome.storage.local.get.bind(c.chrome.storage.local);
  c.chrome.storage.local.get = (...args) => new Promise((resolve) => setTimeout(() => rawGet(...args).then(resolve), 20));
  const restore = c.install();
  try {
    await store.set("benign", { "field:sourcetype": ["value"] });
    modules.reset();
    const hydrated = modules.hydrate(); // in flight, not yet awaited
    const list = moduleList({ platform: "splunk", context: "options" });
    const row = rowFor(list, "benign");
    // Nothing has resolved yet: the keys line is still hidden, not a
    // stale count.
    const line = dom.walk(row, (n) => n.classList && n.classList.contains("r-module__keys"))[0];
    assert.equal(line.hidden, true, "the line has not painted a guess before its own read resolves");
    await hydrated;
    await tick(60);
    assert.equal(keysLineText(row), "1 stored key Clear", "the line rendered once its read resolved, with no click");
  } finally {
    restore();
  }
});
