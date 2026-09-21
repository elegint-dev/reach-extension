// The worker refuses a lookup whose module is off, whatever the source's
// own key or toggle says: the enabled set (reach.modules) is read through
// app/lib/modules.js, followed through storage changes, and answered as
// { ok: false, reason: "module off" } before any fetch. A status message
// still answers, so Settings can show what is configured.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeChrome } from "./_chrome.js";

const EXT_ID = "test-ext";
const fake = fakeChrome({ id: EXT_ID });
fake.chrome.permissions.contains = async () => true; // every host granted
fake.install();
const { local: storage } = fake;
const fetches = [];

globalThis.fetch = async (url, opts = {}) => {
  fetches.push({ url: String(url), opts });
  return { ok: true, status: 200, json: async () => ({ data: {} }) };
};

// Every source is configured and permitted; only the module set decides.
storage.set("vtApiKey", "a".repeat(64));
storage.set("reach.enrich.circl.enabled", true);
storage.set("reach.enrich.epss.enabled", true);
storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
storage.set("reach.enrich.selfhosted.token", "tok");
await import("../background.js");

const send = (msg, sender = { id: EXT_ID }) => fake.deliver(fake.bgListeners, msg, sender);

const LOOKUPS = {
  virustotal: { type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" },
  circl: { type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "e".repeat(64) },
  epss: { type: "reach:enrich:lookup", source: "epss", kind: "cve", id: "CVE-2021-44228" },
  selfhosted: { type: "reach:selfhosted:lookup", kind: "hash", id: "e".repeat(64) },
};

test("with no module set stored, every enrichment module is at its tier (off) and each lookup is refused before any fetch", async () => {
  for (const [id, msg] of Object.entries(LOOKUPS)) {
    const res = await send(msg);
    assert.equal(res.ok, false, id);
    assert.equal(res.reason, "module off", id);
    assert.match(res.error, /is off: turn it on in Reach's settings/, id);
  }
  assert.equal(fetches.length, 0);
});

test("a status message still answers for a module that is off", async () => {
  assert.deepEqual(await send({ type: "reach:vt:status" }), { ok: true, configured: true, permitted: true });
  assert.deepEqual(await send({ type: "reach:enrich:status", source: "epss" }), { ok: true, enabled: true, permitted: true });
});

test("turning a module on in the stored set lets its lookup through, and only its", async () => {
  await chrome.storage.local.set({ "reach.modules": { enabled: { circl: true } } });
  const res = await send(LOOKUPS.circl);
  assert.equal(res.ok, true);
  assert.equal(fetches.length, 1);
  assert.match(fetches[0].url, /hashlookup\.circl\.lu/);
  const vt = await send(LOOKUPS.virustotal);
  assert.equal(vt.reason, "module off");
  assert.equal(fetches.length, 1);
});

test("turning the module off again is seen on the next message, with the source's own toggle still true", async () => {
  await chrome.storage.local.set({ "reach.modules": { enabled: { circl: false } } });
  assert.equal(storage.get("reach.enrich.circl.enabled"), true);
  const res = await send(LOOKUPS.circl);
  assert.deepEqual(res, { ok: false, status: 0, reason: "module off", error: "CIRCL hashlookup is off: turn it on in Reach's settings." });
  assert.equal(fetches.length, 1);
});

test("a source no module owns is refused the same way", async () => {
  const res = await send({ type: "reach:enrich:lookup", source: "nope", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.ok, false);
  assert.equal(fetches.length, 1);
});
