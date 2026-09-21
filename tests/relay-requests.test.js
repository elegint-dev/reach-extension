// The request each relay descriptor builds is the request the worker sent
// before the descriptors existed: url, method, headers, credentials and
// cache, pinned in tests/fixtures/relay-requests.json, and the answer
// shape each source's call() reads, pinned on the response fixtures.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fakeChrome } from "./_chrome.js";

const REQUESTS = JSON.parse(readFileSync(new URL("./fixtures/relay-requests.json", import.meta.url), "utf8"));
const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));

const EXT_ID = "test-ext";
const fake = fakeChrome({ id: EXT_ID });
fake.chrome.permissions.contains = async () => true; // every host granted
fake.install();
const { local: storage } = fake;
const fetches = [];
let respond = () => ({ status: 200, json: {} });

globalThis.fetch = async (url, opts = {}) => {
  fetches.push({ url: String(url), opts });
  const r = respond(String(url));
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json };
};

await import("../background.js");

const send = (msg, sender = { id: EXT_ID }) => fake.deliver(fake.bgListeners, msg, sender);

async function run(name, response) {
  const c = REQUESTS[name];
  storage.clear();
  storage.set("reach.modules", { enabled: { virustotal: true, circl: true, epss: true, selfhosted: true } });
  for (const [k, v] of Object.entries(c.storage)) storage.set(k, v);
  respond = () => response;
  const before = fetches.length;
  const res = await send(c.message);
  assert.equal(fetches.length, before + 1, `${name}: one fetch`);
  assert.deepEqual(fetches.at(-1), c.fetch, `${name}: the request as sent`);
  return res;
}

test("VirusTotal: the v3 URL, the key in x-apikey, and the report under data", async () => {
  const report = { data: { id: "d41d8cd98f00b204e9800998ecf8427e", attributes: { last_analysis_stats: { malicious: 0 } } } };
  const res = await run("virustotal", { status: 200, json: report });
  assert.deepEqual(res, { ok: true, status: 200, data: report });
});

test("CIRCL: the digest path, no header a plain GET would not send, hit and miss bodies passed through", async () => {
  const hit = fixture("circl-hashlookup-hit.json");
  let res = await run("circl", { status: 200, json: hit });
  assert.deepEqual(res, { ok: true, status: 200, data: hit });
  const miss = fixture("circl-hashlookup-miss.json");
  res = await run("circl", { status: 404, json: miss });
  assert.deepEqual(res, { ok: false, status: 404, data: miss });
});

test("EPSS: the cve query, the rows under data", async () => {
  const hit = fixture("epss-hit.json");
  const res = await run("epss", { status: 200, json: hit });
  assert.deepEqual(res, { ok: true, status: 200, data: hit });
});

test("MISP: restSearch as a GET query string with the raw token in authorization, provider on the answer", async () => {
  const hit = fixture("misp-restsearch-hit.json");
  const res = await run("misp", { status: 200, json: hit });
  assert.deepEqual(res, { ok: true, status: 200, provider: "misp", data: hit });
});

test("IntelOwl: jobs by observable_name with a Token header, a 401 names the origin", async () => {
  const hit = fixture("intelowl-jobs-hit.json");
  let res = await run("intelowl", { status: 200, json: hit });
  assert.deepEqual(res, { ok: true, status: 200, provider: "intelowl", data: hit });
  res = await run("intelowl", { status: 401, json: { detail: "no" } });
  assert.deepEqual(res, { ok: false, status: 401, provider: "intelowl", data: { detail: "no" }, error: "https://intelowl.example.org:8443 rejected the token." });
});

test("MISP writes: a sighting and a proposed attribute as JSON POSTs with the raw token, the event page as a GET with named parameters", async () => {
  const sighting = fixture("misp-sighting-add.json");
  let res = await run("misp-sighting", { status: 200, json: sighting });
  assert.deepEqual(res, { ok: true, status: 200, provider: "misp", data: sighting });
  const attribute = fixture("misp-attribute-add.json");
  res = await run("misp-attribute", { status: 200, json: attribute });
  assert.deepEqual(res, { ok: true, status: 200, provider: "misp", data: attribute });
  const events = fixture("misp-events-index.json");
  res = await run("misp-events", { status: 200, json: events });
  assert.deepEqual(res, { ok: true, status: 200, provider: "misp", data: events });
});
