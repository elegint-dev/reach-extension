// background.js's VirusTotal handler, over the same fake-chrome shape as
// relay.test.js: the key is read from storage.local by the worker alone,
// the request carries it in x-apikey, and what comes back to the caller is
// the report (or one sentence), never the key.

import { test } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { fakeChrome } from "./_chrome.js";

const EXT_ID = "test-ext";
const VT = "https://www.virustotal.com/*";
const fake = fakeChrome({ id: EXT_ID, permitted: [VT], getURL: (p) => pathToFileURL(new URL(`../${p}`, import.meta.url).pathname).href });
fake.install();
const { local: storage } = fake;
const fetches = [];
let respond = () => ({ status: 200, json: { data: { id: "8.8.8.8", type: "ip_address", attributes: { last_analysis_stats: { malicious: 0, harmless: 90 } } } } });

globalThis.fetch = async (url, opts = {}) => {
  fetches.push({ url: String(url), opts });
  const r = respond(String(url));
  if (r.throw) throw new Error(r.throw);
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json };
};

// The module is on; the worker refuses a lookup for one that is off
// (tests/relay-module-off.test.js).
storage.set("reach.modules", { enabled: { virustotal: true } });
await import("../background.js");

const send = (msg, sender = { id: EXT_ID }) => fake.deliver(fake.bgListeners, msg, sender);

test("status: unconfigured until a key is stored and the permission granted", async () => {
  assert.deepEqual(await send({ type: "reach:vt:status" }), { ok: true, configured: false, permitted: true });
  fake.permitted.delete(VT);
  storage.set("vtApiKey", "a".repeat(64));
  assert.deepEqual(await send({ type: "reach:vt:status" }), { ok: true, configured: true, permitted: false });
  fake.permitted.add(VT);
  assert.deepEqual(await send({ type: "reach:vt:status" }), { ok: true, configured: true, permitted: true });
});

test("lookup refuses without a key or permission, and touches nothing", async () => {
  storage.delete("vtApiKey");
  let res = await send({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(res.ok, false);
  assert.match(res.error, /not set up/);
  storage.set("vtApiKey", "a".repeat(64));
  fake.permitted.delete(VT);
  res = await send({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(res.ok, false);
  assert.match(res.error, /no permission/);
  fake.permitted.add(VT);
  assert.equal(fetches.length, 0, "no request was made");
});

test("lookup: the key goes in x-apikey to the v3 endpoint and never comes back", async () => {
  storage.set("vtApiKey", "  " + "b".repeat(64) + "\n");
  const res = await send({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(res.ok, true);
  assert.equal(res.status, 200);
  assert.equal(res.data.data.id, "8.8.8.8");
  assert.equal(fetches.length, 1);
  assert.equal(fetches[0].url, "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8");
  assert.equal(fetches[0].opts.headers["x-apikey"], "b".repeat(64), "trimmed key in the header");
  assert.equal(fetches[0].opts.credentials, "omit");
  assert.equal(JSON.stringify(res).includes("b".repeat(64)), false, "response carries no key");
});

test("lookup: cached for the same indicator; a different one fetches", async () => {
  const before = fetches.length;
  const again = await send({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(again.ok, true);
  assert.equal(again.cached, true);
  assert.equal(fetches.length, before, "served from cache");
  await send({ type: "reach:vt:lookup", kind: "domain", id: "example.com" });
  assert.equal(fetches.length, before + 1);
  assert.equal(fetches[before].url, "https://www.virustotal.com/api/v3/domains/example.com");
  await send({ type: "reach:vt:lookup", kind: "hash", id: "d41d8cd98f00b204e9800998ecf8427e" });
  assert.equal(fetches[before + 1].url, "https://www.virustotal.com/api/v3/files/d41d8cd98f00b204e9800998ecf8427e");
});

test("lookup: only the three kinds and a sane id; never a proxy for the key", async () => {
  const before = fetches.length;
  for (const msg of [
    { type: "reach:vt:lookup", kind: "url", id: "aHR0cDovL2V4YW1wbGUuY29t" },
    { type: "reach:vt:lookup", kind: "ip", id: "../../users/current" },
    { type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8?x=1" },
    { type: "reach:vt:lookup", kind: "ip", id: 42 },
    { type: "reach:vt:lookup", kind: "ip" },
  ]) {
    const res = await send(msg);
    assert.equal(res.ok, false, JSON.stringify(msg));
    assert.match(res.error, /refused/);
  }
  assert.equal(fetches.length, before);
});

test("lookup: 404 is cached, 429/401 are not, network errors are one sentence", async () => {
  respond = () => ({ status: 404, json: { error: { code: "NotFoundError", message: "not found" } } });
  let res = await send({ type: "reach:vt:lookup", kind: "hash", id: "e".repeat(64) });
  assert.deepEqual(res, { ok: false, status: 404, body: { error: { code: "NotFoundError", message: "not found" } } });
  const before = fetches.length;
  res = await send({ type: "reach:vt:lookup", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.cached, true);
  assert.equal(fetches.length, before, "404 served from cache");

  respond = () => ({ status: 429, json: { error: { code: "QuotaExceededError" } } });
  res = await send({ type: "reach:vt:lookup", kind: "ip", id: "1.1.1.1" });
  assert.equal(res.status, 429);
  res = await send({ type: "reach:vt:lookup", kind: "ip", id: "1.1.1.1" });
  assert.equal(res.cached, undefined, "a quota failure is retried, not cached");

  respond = () => ({ throw: "Failed to fetch" });
  res = await send({ type: "reach:vt:lookup", kind: "ip", id: "9.9.9.9" });
  assert.equal(res.ok, false);
  assert.equal(res.status, 0);
  assert.match(res.error, /Could not reach VirusTotal \(Failed to fetch\)/);
});

test("another extension cannot use the relay", async () => {
  const res = await send({ type: "reach:vt:lookup", kind: "ip", id: "8.8.8.8" }, { id: "someone-else" });
  assert.equal(res, undefined);
});
