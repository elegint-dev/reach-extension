// background.js's generic CIRCL/EPSS handler, over the same fake-chrome
// shape as virustotal-relay.test.js: both sources are off until their
// Settings key is true AND the host permission is granted; the enabled
// flag and the permission are re-read from storage on every message,
// never trusted from the caller.

import { test } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { fakeChrome } from "./_chrome.js";

const EXT_ID = "test-ext";
const fake = fakeChrome({ id: EXT_ID, permitted: ["https://hashlookup.circl.lu/*", "https://api.first.org/*"], getURL: (p) => pathToFileURL(new URL(`../${p}`, import.meta.url).pathname).href });
fake.install();
const { local: storage, permitted: permittedHosts } = fake;
const fetches = [];
let respond = () => ({ status: 200, json: { message: "stub" } });

globalThis.fetch = async (url, opts = {}) => {
  fetches.push({ url: String(url), opts });
  const r = respond(String(url));
  if (r.throw) throw new Error(r.throw);
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json };
};

// The module is on; the worker refuses a lookup for one that is off
// (tests/relay-module-off.test.js).
storage.set("reach.modules", { enabled: { circl: true, epss: true } });
await import("../background.js");

const send = (msg, sender = { id: EXT_ID }) => fake.deliver(fake.bgListeners, msg, sender);

test("status: both sources report their own enabled flag and permission, independent of each other", async () => {
  assert.deepEqual(await send({ type: "reach:enrich:status", source: "circl" }), { ok: true, enabled: false, permitted: true });
  storage.set("reach.enrich.circl.enabled", true);
  assert.deepEqual(await send({ type: "reach:enrich:status", source: "circl" }), { ok: true, enabled: true, permitted: true });
  assert.deepEqual(await send({ type: "reach:enrich:status", source: "epss" }), { ok: true, enabled: false, permitted: true });
});

test("lookup refuses when the source is off, even with permission granted", async () => {
  storage.delete("reach.enrich.circl.enabled");
  const res = await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.ok, false);
  assert.match(res.error, /is off/);
  assert.equal(fetches.length, 0);
});

test("lookup refuses when enabled but not permitted", async () => {
  storage.set("reach.enrich.epss.enabled", true);
  permittedHosts.delete("https://api.first.org/*");
  const res = await send({ type: "reach:enrich:lookup", source: "epss", kind: "cve", id: "CVE-2021-44228" });
  assert.equal(res.ok, false);
  assert.match(res.error, /no permission/);
  permittedHosts.add("https://api.first.org/*");
});

test("lookup: an unknown source, a mismatched kind or a malformed id is refused before any fetch", async () => {
  storage.set("reach.enrich.circl.enabled", true);
  storage.set("reach.enrich.epss.enabled", true);
  const before = fetches.length;
  for (const msg of [
    { type: "reach:enrich:lookup", source: "nope", kind: "hash", id: "e".repeat(64) },
    { type: "reach:enrich:lookup", source: "circl", kind: "cve", id: "CVE-2021-44228" },
    { type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "not-hex" },
    { type: "reach:enrich:lookup", source: "epss", kind: "cve", id: "../../etc/passwd" },
  ]) {
    const res = await send(msg);
    assert.equal(res.ok, false, JSON.stringify(msg));
  }
  assert.equal(fetches.length, before);
});

test("lookup: CIRCL builds the sha256/sha1/md5 path by id length, sends no headers a plain GET would not", async () => {
  respond = () => ({ status: 200, json: { db: "nsrl_legacy", FileName: "notepad.exe" } });
  const sha256 = "e".repeat(64);
  const res = await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: sha256 });
  assert.equal(res.ok, true);
  assert.equal(res.data.FileName, "notepad.exe");
  assert.equal(fetches.at(-1).url, `https://hashlookup.circl.lu/lookup/sha256/${sha256}`);
  assert.equal(fetches.at(-1).opts.credentials, "omit");

  await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "d".repeat(32) });
  assert.match(fetches.at(-1).url, /\/lookup\/md5\//);
  await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "c".repeat(40) });
  assert.match(fetches.at(-1).url, /\/lookup\/sha1\//);
});

test("lookup: CIRCL's 404 for an unknown hash still comes back with the body, not an error", async () => {
  respond = () => ({ status: 404, json: { message: "Non existing SHA-256", query: "x" } });
  const res = await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "f".repeat(64) });
  assert.equal(res.ok, false);
  assert.equal(res.status, 404);
  assert.equal(res.data.message, "Non existing SHA-256");
});

test("lookup: EPSS queries by cve id", async () => {
  respond = () => ({ status: 200, json: { status: "OK", total: 1, data: [{ cve: "CVE-2021-44228", epss: "0.99999", percentile: "1.0", date: "2026-09-18" }] } });
  const res = await send({ type: "reach:enrich:lookup", source: "epss", kind: "cve", id: "CVE-2021-44228" });
  assert.equal(res.ok, true);
  assert.equal(fetches.at(-1).url, "https://api.first.org/data/v1/epss?cve=CVE-2021-44228");
  assert.equal(res.data.data[0].epss, "0.99999");
});

test("lookup: a network failure is one plain sentence, and never touches the fetch when refused", async () => {
  respond = () => ({ throw: "Failed to fetch" });
  const res = await send({ type: "reach:enrich:lookup", source: "epss", kind: "cve", id: "CVE-2021-44228" });
  assert.equal(res.ok, false);
  assert.equal(res.status, 0);
  assert.match(res.error, /Could not reach epss \(Failed to fetch\)/);
});

test("another extension cannot use the relay", async () => {
  const res = await send({ type: "reach:enrich:lookup", source: "circl", kind: "hash", id: "a".repeat(64) }, { id: "someone-else" });
  assert.equal(res, undefined);
});
