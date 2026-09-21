// background.js's write() over the self-hosted descriptor: a MISP
// sighting and a proposed attribute leave only through the relay, only
// with the module on, the origin saved and permitted, and the module's
// own writes toggle on; IntelOwl has no write path. Responses are the
// ones a MISP 2.5.47 answered when the fixtures were recorded.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));

const bgListeners = [];
const changeListeners = [];
const storage = new Map();
const EXT_ID = "test-ext";
const permittedHosts = new Set(["https://misp.example.org/*"]);
const fetches = [];
let respond = () => ({ status: 200, json: {} });

globalThis.chrome = {
  runtime: { id: EXT_ID, lastError: null, onMessage: { addListener: (fn) => bgListeners.push(fn) }, onConnect: { addListener: () => {} }, onStartup: { addListener: () => {} }, onInstalled: { addListener: () => {} } },
  tabs: { query: async () => [] },
  storage: {
    local: {
      get: async (k) => (Array.isArray(k) ? Object.fromEntries(k.map((x) => [x, storage.get(x)])) : { [k]: storage.get(k) }),
      set: async (obj) => {
        const changes = {};
        for (const [k, v] of Object.entries(obj)) {
          changes[k] = { oldValue: storage.get(k), newValue: v };
          storage.set(k, v);
        }
        for (const fn of changeListeners) fn(changes, "local");
      },
      remove: async (k) => (Array.isArray(k) ? k.forEach((x) => storage.delete(x)) : storage.delete(k)),
    },
    onChanged: { addListener: (fn) => changeListeners.push(fn) },
  },
  scripting: { getRegisteredContentScripts: async () => [], registerContentScripts: async () => {}, updateContentScripts: async () => {} },
  permissions: { contains: async ({ origins }) => origins.every((o) => permittedHosts.has(o)), onAdded: { addListener: () => {} } },
};

globalThis.fetch = async (url, opts = {}) => {
  fetches.push({ url: String(url), opts });
  const r = respond(String(url), opts);
  if (r.throw) throw new Error(r.throw);
  return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.json };
};

storage.set("reach.modules", { enabled: { selfhosted: true } });
storage.set("reach.enrich.selfhosted.provider", "misp");
storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
storage.set("reach.enrich.selfhosted.token", "rawkey123");
await import("../background.js");

function send(msg, sender = { id: EXT_ID }) {
  return new Promise((resolve) => {
    for (const fn of bgListeners) if (fn(msg, sender, resolve) === true) return;
    resolve(undefined);
  });
}

const SIGHTING = { type: "reach:selfhosted:write", op: "sighting", attributeId: "1" };
const ATTRIBUTE = { type: "reach:selfhosted:write", op: "attribute", eventId: "2", kind: "domain", id: "proposed-by-reach.example.net", comment: "held: seen in DNS from the T1003.001 host" };
const EVENTS = { type: "reach:selfhosted:write", op: "events" };

test("with the writes toggle off (the default) every write is refused before any fetch, and status says writes are off", async () => {
  for (const msg of [SIGHTING, ATTRIBUTE, EVENTS]) {
    const res = await send(msg);
    assert.equal(res.ok, false, msg.op);
    assert.equal(res.reason, "writes off", msg.op);
    assert.match(res.error, /Allow writes to MISP/, msg.op);
  }
  assert.equal(fetches.length, 0);
  const st = await send({ type: "reach:selfhosted:status" });
  assert.equal(st.writes, false);
});

test("with the module off the write is refused as module off, whatever the toggle says", async () => {
  await chrome.storage.local.set({ "reach.enrich.selfhosted.writes": true });
  await chrome.storage.local.set({ "reach.modules": { enabled: { selfhosted: false } } });
  const res = await send(SIGHTING);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "module off");
  assert.equal(fetches.length, 0);
  await chrome.storage.local.set({ "reach.modules": { enabled: { selfhosted: true } } });
});

test("a sighting is one POST to /sightings/add/<attribute id> with source Reach, the raw key, no cookies; the new sighting comes back", async () => {
  const body = fixture("misp-sighting-add.json");
  respond = () => ({ status: 200, json: body });
  const res = await send(SIGHTING);
  assert.equal(res.ok, true);
  assert.equal(res.data.Sighting.source, "Reach");
  assert.equal(fetches.length, 1);
  const f = fetches[0];
  assert.equal(f.url, "https://misp.example.org/sightings/add/1");
  assert.equal(f.opts.method, "POST");
  assert.deepEqual(JSON.parse(f.opts.body), { source: "Reach" });
  assert.equal(f.opts.headers.authorization, "rawkey123");
  assert.equal(f.opts.headers["content-type"], "application/json");
  assert.equal(f.opts.credentials, "omit");
  assert.equal(JSON.stringify(res).includes("rawkey123"), false);
});

test("a proposed attribute is one POST to /attributes/add/<event id>: type from the kind, the Hold reason as comment, to_ids false", async () => {
  const body = fixture("misp-attribute-add.json");
  respond = () => ({ status: 200, json: body });
  const res = await send(ATTRIBUTE);
  assert.equal(res.ok, true);
  assert.equal(res.data.Attribute.to_ids, false);
  const f = fetches.at(-1);
  assert.equal(f.url, "https://misp.example.org/attributes/add/2");
  assert.equal(f.opts.method, "POST");
  assert.deepEqual(JSON.parse(f.opts.body), { type: "domain", value: "proposed-by-reach.example.net", comment: "held: seen in DNS from the T1003.001 host", to_ids: false });
});

test("the event list is a GET of the recent page with CakePHP named parameters, newest first, no body", async () => {
  const body = fixture("misp-events-index.json");
  respond = () => ({ status: 200, json: body });
  const res = await send(EVENTS);
  assert.equal(res.ok, true);
  assert.equal(res.data.length, 2);
  const f = fetches.at(-1);
  assert.equal(f.url, "https://misp.example.org/events/index/limit:8/sort:timestamp/direction:desc");
  assert.equal(f.opts.method, "GET");
  assert.equal(f.opts.body, undefined);
  assert.equal(f.opts.headers["content-type"], undefined);
});

test("a malformed write is refused before any fetch: an unknown op, a non-numeric id, a kind with no MISP type, a hash of the wrong length", async () => {
  const before = fetches.length;
  for (const msg of [
    { type: "reach:selfhosted:write", op: "delete", attributeId: "1" },
    { type: "reach:selfhosted:write", op: "sighting", attributeId: "1; drop" },
    { type: "reach:selfhosted:write", op: "sighting", attributeId: "../events" },
    { type: "reach:selfhosted:write", op: "attribute", eventId: "2", kind: "technique", id: "T1003" },
    { type: "reach:selfhosted:write", op: "attribute", eventId: "2", kind: "hash", id: "abc123" },
    { type: "reach:selfhosted:write", op: "attribute", eventId: "x", kind: "domain", id: "a.example" },
    { type: "reach:selfhosted:write", op: "constructor", attributeId: "1" },
  ]) {
    const res = await send(msg);
    assert.equal(res.ok, false, JSON.stringify(msg));
    assert.match(res.error, /Write refused/, JSON.stringify(msg));
  }
  assert.equal(fetches.length, before);
});

test("MISP's own refusal text comes back: a duplicate attribute's 403 names the reason, the guard's 405 names the setting", async () => {
  respond = () => ({ status: 403, json: fixture("misp-attribute-add-error.json") });
  let res = await send(ATTRIBUTE);
  assert.equal(res.ok, false);
  assert.equal(res.error, "https://misp.example.org returned 403: A similar attribute already exists for this event.");

  respond = () => ({ status: 405, json: { name: "POST, PUT and AJAX requests are allowed just from same origin.", message: "POST, PUT and AJAX requests are allowed just from same origin.", url: "/sightings/add/1" } });
  res = await send(SIGHTING);
  assert.equal(res.ok, false);
  assert.match(res.error, /405/);
  assert.match(res.error, /Security\.check_sec_fetch_site_header/);
});

test("IntelOwl has no write path: the toggle on, the provider set to intelowl, every write is refused before any fetch", async () => {
  await chrome.storage.local.set({ "reach.enrich.selfhosted.provider": "intelowl" });
  const before = fetches.length;
  const res = await send(SIGHTING);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "writes off");
  assert.equal(fetches.length, before);
  const st = await send({ type: "reach:selfhosted:status" });
  assert.equal(st.writes, false, "status never reports writes on for IntelOwl");
  await chrome.storage.local.set({ "reach.enrich.selfhosted.provider": "misp" });
});

test("a write without the host permission or without an origin is refused, touching nothing", async () => {
  const before = fetches.length;
  permittedHosts.delete("https://misp.example.org/*");
  let res = await send(SIGHTING);
  assert.equal(res.ok, false);
  assert.match(res.error, /no permission/);
  permittedHosts.add("https://misp.example.org/*");
  storage.delete("reach.enrich.selfhosted.origin");
  res = await send(SIGHTING);
  assert.equal(res.ok, false);
  assert.match(res.error, /not set up/);
  storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  assert.equal(fetches.length, before);
});

test("another extension cannot write through the relay", async () => {
  const res = await send(SIGHTING, { id: "someone-else" });
  assert.equal(res, undefined);
});
