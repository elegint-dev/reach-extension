// background.js's self-hosted enrichment handler (app/lib/enrich/selfhosted.js's
// call() dispatches here), over the same fake-chrome shape as
// virustotal-relay.test.js and enrich-relay.test.js: the origin, token and
// provider are read from storage.local by the worker alone, re-checked
// against the permission on every call, and never handed back to the
// caller. Also covers registerForGrant()'s exclusion of the self-hosted
// origin from Splunk/Sentinel content-script registration, the same
// exclusion already applied to virustotal.com.

import { test } from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { fakeChrome } from "./_chrome.js";

const EXT_ID = "test-ext";
const fake = fakeChrome({ id: EXT_ID, getURL: (p) => pathToFileURL(new URL(`../${p}`, import.meta.url).pathname).href });
fake.install();
const { local: storage, permitted: permittedHosts, registered: registeredScripts, startupListeners: onStartupListeners } = fake;
const onPermissionsAdded = (grant) => fake.permissionListeners.forEach((fn) => fn(grant));
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
storage.set("reach.modules", { enabled: { selfhosted: true } });
await import("../background.js");

const send = (msg, sender = { id: EXT_ID }) => fake.deliver(fake.bgListeners, msg, sender);

const flush = () => new Promise((r) => setTimeout(r, 10));

test("status: unconfigured until an origin is stored and the permission granted", async () => {
  assert.deepEqual(await send({ type: "reach:selfhosted:status" }), { ok: true, configured: false, permitted: false, provider: "misp", origin: "", writes: false });
  storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  assert.deepEqual(await send({ type: "reach:selfhosted:status" }), { ok: true, configured: true, permitted: false, provider: "misp", origin: "https://misp.example.org", writes: false });
  permittedHosts.add("https://misp.example.org/*");
  assert.deepEqual(await send({ type: "reach:selfhosted:status" }), { ok: true, configured: true, permitted: true, provider: "misp", origin: "https://misp.example.org", writes: false });
});

test("lookup refuses without a configured origin or a granted permission, touching nothing", async () => {
  storage.delete("reach.enrich.selfhosted.origin");
  permittedHosts.delete("https://misp.example.org/*");
  let res = await send({ type: "reach:selfhosted:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(res.ok, false);
  assert.match(res.error, /not set up/);

  storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  res = await send({ type: "reach:selfhosted:lookup", kind: "ip", id: "8.8.8.8" });
  assert.equal(res.ok, false);
  assert.match(res.error, /no permission/);
  assert.equal(fetches.length, 0);
});

test("lookup: an unsupported kind or an oversized id is refused before any fetch", async () => {
  permittedHosts.add("https://misp.example.org/*");
  const before = fetches.length;
  for (const msg of [
    { type: "reach:selfhosted:lookup", kind: "technique", id: "T1003" },
    { type: "reach:selfhosted:lookup", kind: "ip", id: "x".repeat(3000) },
    { type: "reach:selfhosted:lookup", kind: "ip", id: "" },
  ]) {
    const res = await send(msg);
    assert.equal(res.ok, false, JSON.stringify(msg));
  }
  assert.equal(fetches.length, before);
});

// A GET, not the documented POST-with-JSON-body form: MISP's own
// Security.check_sec_fetch_site_header guard (on by default) throws 405 on
// any POST/PUT/AJAX whose Sec-Fetch-Site isn't "same-origin", which a
// browser-set header a fetch() call can neither read nor override always
// is for a cross-origin extension request. The guard only inspects
// post/put/ajax, so restSearch's GET form (same params as a query string)
// clears it.
test("lookup: MISP gets restSearch as a query string with event tags and sightings, the raw key in Authorization with no Bearer prefix", async () => {
  storage.set("reach.enrich.selfhosted.provider", "misp");
  storage.set("reach.enrich.selfhosted.token", "rawkey123");
  respond = () => ({ status: 200, json: { response: { Attribute: [] } } });
  const res = await send({ type: "reach:selfhosted:lookup", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.ok, true);
  assert.equal(res.provider, "misp");
  const f = fetches.at(-1);
  assert.equal(f.url, `https://misp.example.org/attributes/restSearch?returnFormat=json&value=${"e".repeat(64)}&includeEventTags=1&includeSightings=1`);
  assert.equal(f.opts.method, "GET");
  assert.equal(f.opts.headers.authorization, "rawkey123");
  assert.equal(f.opts.credentials, "omit");
  assert.equal(f.opts.body, undefined);
});

test("lookup: IntelOwl looks up existing jobs by observable_name, never analyze_observable", async () => {
  storage.set("reach.enrich.selfhosted.provider", "intelowl");
  storage.set("reach.enrich.selfhosted.token", "tok456");
  respond = () => ({ status: 200, json: { count: 0, results: [] } });
  const res = await send({ type: "reach:selfhosted:lookup", kind: "domain", id: "example.com" });
  assert.equal(res.ok, true);
  assert.equal(res.provider, "intelowl");
  const f = fetches.at(-1);
  assert.equal(f.url, "https://misp.example.org/api/jobs?observable_name=example.com");
  assert.equal(f.opts.method, "GET");
  assert.equal(f.opts.headers.authorization, "Token tok456");
  assert.ok(!f.url.includes("analyze_observable"));
});

test("status: an unrecognised stored provider such as a leftover cortex value reads back as misp", async () => {
  storage.set("reach.enrich.selfhosted.provider", "cortex");
  storage.set("reach.enrich.selfhosted.origin", "https://cortex.example.org");
  permittedHosts.add("https://cortex.example.org/*");
  const res = await send({ type: "reach:selfhosted:status" });
  assert.equal(res.provider, "misp");
});

test("migration: a stored cortex config is cleared and its permission revoked on startup, a misp config is left alone", async () => {
  assert.ok(onStartupListeners.length, "the worker registered an onStartup listener");
  storage.set("reach.enrich.selfhosted.provider", "cortex");
  storage.set("reach.enrich.selfhosted.origin", "https://cortex.example.org");
  storage.set("reach.enrich.selfhosted.token", "cortex-token");
  permittedHosts.add("https://cortex.example.org/*");
  await Promise.all(onStartupListeners.map((fn) => fn()));
  assert.equal(storage.has("reach.enrich.selfhosted.provider"), false);
  assert.equal(storage.has("reach.enrich.selfhosted.origin"), false);
  assert.equal(storage.has("reach.enrich.selfhosted.token"), false);
  assert.equal(permittedHosts.has("https://cortex.example.org/*"), false, "the cortex origin's permission was revoked");

  storage.set("reach.enrich.selfhosted.provider", "misp");
  storage.set("reach.enrich.selfhosted.origin", "https://misp.example.org");
  storage.set("reach.enrich.selfhosted.token", "misp-token");
  permittedHosts.add("https://misp.example.org/*");
  await Promise.all(onStartupListeners.map((fn) => fn()));
  assert.equal(storage.get("reach.enrich.selfhosted.provider"), "misp", "a misp config is not touched by the migration");
  assert.ok(permittedHosts.has("https://misp.example.org/*"));
});

test("lookup: a 401 names the origin, a network failure is one plain sentence, the token never comes back", async () => {
  storage.set("reach.enrich.selfhosted.provider", "misp");
  respond = () => ({ status: 401, json: { message: "unauthorized" } });
  let res = await send({ type: "reach:selfhosted:lookup", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.ok, false);
  assert.match(res.error, /rejected the token/);
  assert.equal(JSON.stringify(res).includes("rawkey123"), false);

  respond = () => ({ throw: "Failed to fetch" });
  res = await send({ type: "reach:selfhosted:lookup", kind: "hash", id: "e".repeat(64) });
  assert.equal(res.ok, false);
  assert.equal(res.status, 0);
  assert.match(res.error, /Could not reach https:\/\/misp\.example\.org \(Failed to fetch\)/);
});

test("another extension cannot use the relay", async () => {
  const res = await send({ type: "reach:selfhosted:lookup", kind: "hash", id: "e".repeat(64) }, { id: "someone-else" });
  assert.equal(res, undefined);
});

test("registerForGrant excludes the self-hosted origin from Splunk/Sentinel content-script registration, the same as virustotal.com", async () => {
  assert.ok(fake.permissionListeners.length, "the worker registered a permissions.onAdded listener");
  const before = registeredScripts.length;
  const splunkPattern = "https://splunk.example.com/*";
  onPermissionsAdded({ origins: ["https://misp.example.org/*", splunkPattern] });
  await flush();
  assert.equal(registeredScripts.filter((s) => s.matches[0] === "https://misp.example.org/*").length, 0, "the self-hosted origin never gets a content script");
  assert.ok(registeredScripts.length > before, "an ordinary Splunk origin in the same grant still registers");
  assert.ok(registeredScripts.some((s) => s.matches[0] === splunkPattern));
  const { trustedOrigins = [] } = await chrome.storage.local.get("trustedOrigins");
  assert.ok(!trustedOrigins.includes("https://misp.example.org"), "the self-hosted origin never lands in Splunk discovery");
  assert.ok(trustedOrigins.includes("https://splunk.example.com"));
});
