// app/lib/enrich.js: the registry (register/list/get/gate/kindsFor/
// offersFor), the CISA KEV bundle source over a fixture, and the
// VirusTotal adapter's migration into the registry (same refusal
// reasons, same fetch-only-on-explicit-click behaviour).

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as enrich from "../app/lib/enrich.js";
import * as kev from "../app/lib/enrich/kev.js";
import * as vt from "../app/lib/enrich/virustotal.js";

beforeEach(() => {
  enrich.reset();
});

// ---------------------------------------------------------------------------
// registry

test("register: validates shape and rejects a repeat id", () => {
  assert.throws(() => enrich.register({ id: "", label: "x", kinds: ["cve"], mode: "bundle", call: async () => {} }), /id is required/);
  assert.throws(() => enrich.register({ id: "x", kinds: ["cve"], mode: "bundle", call: async () => {} }), /label is required/);
  assert.throws(() => enrich.register({ id: "x", label: "X", kinds: [], mode: "bundle", call: async () => {} }), /non-empty array/);
  assert.throws(() => enrich.register({ id: "x", label: "X", kinds: ["cve"], mode: "carrier-pigeon", call: async () => {} }), /mode must be one of/);
  assert.throws(() => enrich.register({ id: "x", label: "X", kinds: ["cve"], mode: "bundle" }), /call must be a function/);
  enrich.register({ id: "x", label: "X", kinds: ["cve"], mode: "bundle", call: async () => {} });
  assert.throws(() => enrich.register({ id: "x", label: "X2", kinds: ["cve"], mode: "bundle", call: async () => {} }), /already registered/);
});

test("list: sources for a kind, registration order, empty for an unregistered kind", () => {
  const a = enrich.register({ id: "a", label: "A", kinds: ["cve"], mode: "bundle", call: async () => {} });
  const b = enrich.register({ id: "b", label: "B", kinds: ["cve", "ip"], mode: "deeplink", call: async () => {} });
  assert.deepEqual(enrich.list("cve"), [a, b]);
  assert.deepEqual(enrich.list("ip"), [b]);
  assert.deepEqual(enrich.list("domain"), []);
  assert.equal(enrich.get("a"), a);
  assert.equal(enrich.get("missing"), undefined);
  assert.deepEqual(enrich.all(), [a, b]);
});

test("gate: bundle and deeplink sources are always allowed", () => {
  const bundle = enrich.register({ id: "b1", label: "Bundle", kinds: ["cve"], mode: "bundle", call: async () => {} });
  const link = enrich.register({ id: "d1", label: "Deep", kinds: ["cve"], mode: "deeplink", call: async () => {} });
  assert.deepEqual(enrich.gate(bundle, { enabledIds: [] }), { allowed: true });
  assert.deepEqual(enrich.gate(link, {}), { allowed: true });
});

test("gate: fetch and stream sources are refused unless enabled, by array or Set", () => {
  const fetchSrc = enrich.register({ id: "f1", label: "Fetch Co", kinds: ["ip"], mode: "fetch", call: async () => {} });
  const off = enrich.gate(fetchSrc, { enabledIds: [] });
  assert.equal(off.allowed, false);
  assert.match(off.why, /Fetch Co is not configured/);
  assert.equal(off.configure, true, "a gate refusal points the row at the module's settings");
  assert.equal(enrich.gate(fetchSrc, { enabledIds: ["f1"] }).allowed, true);
  assert.equal(enrich.gate(fetchSrc, { enabledIds: new Set(["f1"]) }).allowed, true);
  assert.equal(enrich.gate(fetchSrc, {}).allowed, false, "no enabledIds at all still refuses");

  const streamSrc = enrich.register({ id: "s1", label: "Stream Co", kinds: ["hash"], mode: "stream", call: async () => {} });
  assert.equal(enrich.gate(streamSrc, { enabledIds: [] }).allowed, false);
});

// ---------------------------------------------------------------------------
// kindsFor / refusalFor / offersFor

test("kindsFor: a CVE value, and ip/domain/hash via the same rules as virustotal.js", () => {
  assert.deepEqual(enrich.kindsFor("CVE-2021-44228"), [{ kind: "cve", id: "CVE-2021-44228" }]);
  assert.deepEqual(enrich.kindsFor("8.8.8.8"), [{ kind: "ip", id: "8.8.8.8" }]);
  assert.deepEqual(enrich.kindsFor("example.com"), [{ kind: "domain", id: "example.com" }]);
  const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.deepEqual(enrich.kindsFor(sha256), [{ kind: "hash", id: sha256 }, { kind: "sha256", id: sha256 }]);
  assert.deepEqual(enrich.kindsFor("16afba5c5c43e07c9e3e5e2e544e95df"), [{ kind: "hash", id: "16afba5c5c43e07c9e3e5e2e544e95df" }], "an MD5-length id is hash-shaped but never sha256");
  assert.deepEqual(enrich.kindsFor("not a candidate at all"), []);
});

test("offersFor: a matched value pairs with every registered source for its kind, gated", () => {
  const kevLike = enrich.register({ id: "kev-like", label: "KEV-like", kinds: ["cve"], mode: "bundle", call: async () => {} });
  const vtLike = enrich.register({ id: "vt-like", label: "VT-like", kinds: ["ip", "domain", "hash"], mode: "fetch", call: async () => {} });

  const cveOffers = enrich.offersFor("CVE-2021-44228", { enabledIds: [] });
  assert.deepEqual(cveOffers, [{ source: kevLike, kind: "cve", id: "CVE-2021-44228", allowed: true, why: undefined }]);

  const ipOffersOff = enrich.offersFor("8.8.8.8", { enabledIds: [] });
  assert.equal(ipOffersOff.length, 1);
  assert.equal(ipOffersOff[0].source, vtLike);
  assert.equal(ipOffersOff[0].allowed, false);

  const ipOffersOn = enrich.offersFor("8.8.8.8", { enabledIds: ["vt-like"] });
  assert.equal(ipOffersOn[0].allowed, true);
});

test("offersFor: a shaped-but-refused value still offers its kind's sources, marked not-sent", () => {
  enrich.register({ id: "vt-like", label: "VT-like", kinds: ["ip", "domain", "hash"], mode: "fetch", call: async () => {} });
  const offers = enrich.offersFor("10.1.2.3", { enabledIds: ["vt-like"] });
  assert.equal(offers.length, 1);
  assert.equal(offers[0].kind, "ip");
  assert.equal(offers[0].allowed, false);
  assert.match(offers[0].why, /Not sent: a private address/);
});

test("offersFor: nothing offered for a value with no matching kind and no refusal", () => {
  enrich.register({ id: "vt-like", label: "VT-like", kinds: ["ip", "domain", "hash"], mode: "fetch", call: async () => {} });
  assert.deepEqual(enrich.offersFor("just some text", {}), []);
});

// ---------------------------------------------------------------------------
// KEV bundle source over a fixture

const KEV_DOC = {
  format: "reach-kev",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  catalogVersion: "2026.09.18",
  count: 2,
  vulnerabilities: [
    { cveID: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2", dateAdded: "2021-12-10", dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known", shortDescription: "Log4Shell." },
    { cveID: "CVE-2020-0601", vendorProject: "Microsoft", product: "Windows CryptoAPI", dateAdded: "2020-01-14", dueDate: "2020-01-28", knownRansomwareCampaignUse: "Unknown", shortDescription: "CurveBall." },
  ],
};

function stubFetch(doc) {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => doc });
}

test("kev: classify only CVE-shaped values", () => {
  assert.deepEqual(kev.classify("CVE-2021-44228"), { kind: "cve", id: "CVE-2021-44228" });
  assert.equal(kev.classify("8.8.8.8"), null);
});

test("kev: linkFor is the CISA catalogue search, no lookup needed", () => {
  const link = kev.linkFor("cve-2021-44228");
  assert.equal(link.href, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-44228");
});

test("kev: call() on a hit reports date added, due date, ransomware use and vendor/product", async () => {
  kev.reset();
  stubFetch(KEV_DOC);
  const res = await kev.call("CVE-2021-44228");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /In CISA KEV since 2021-12-10, due 2021-12-24, ransomware use: known, Apache Log4j2/);
  assert.equal(res.lines[1], "Log4Shell.");
  assert.equal(res.link.href, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=CVE-2021-44228");
});

test("kev: call() on a miss says not listed, with the catalogue's as-of date", async () => {
  kev.reset();
  stubFetch(KEV_DOC);
  const res = await kev.call("CVE-1999-00001");
  assert.equal(res.status, "empty");
  assert.match(res.lines[0], /is not in the CISA Known Exploited Vulnerabilities catalogue \(catalogue as of 2026-09-18\)/);
});

test("kev: call() on a non-CVE value is refused, no fetch attempted", async () => {
  kev.reset();
  let called = false;
  globalThis.fetch = async () => { called = true; return { ok: true, status: 200, json: async () => KEV_DOC }; };
  const res = await kev.call("8.8.8.8");
  assert.equal(res.status, "refused");
  assert.equal(called, false);
});

test("kev: call() reports an error when the bundle cannot be read, without throwing", async () => {
  kev.reset();
  globalThis.fetch = async () => ({ ok: false, status: 404 });
  const res = await kev.call("CVE-2021-44228");
  assert.equal(res.status, "error");
});

test("kev: load() is cached; a second call() does not fetch again", async () => {
  kev.reset();
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return { ok: true, status: 200, json: async () => KEV_DOC }; };
  await kev.call("CVE-2021-44228");
  await kev.call("CVE-2020-0601");
  assert.equal(calls, 1);
});

// ---------------------------------------------------------------------------
// VirusTotal's migration into the registry: same refusal reasons, same
// explicit-click-only shape, now reshaped into { status, lines, link }.

test("vt adapter: classify and linkFor match app/lib/virustotal.js exactly", () => {
  assert.deepEqual(vt.classify("8.8.8.8"), { kind: "ip", id: "8.8.8.8" });
  assert.equal(vt.linkFor("8.8.8.8").href, "https://www.virustotal.com/gui/ip-address/8.8.8.8");
});

test("vt adapter: call() on a refused value (private IP) never touches ask()", async () => {
  let asked = false;
  const res = await vt.call("10.1.2.3", { ask: async () => { asked = true; } });
  assert.equal(res.status, "refused");
  assert.equal(asked, false);
});

test("vt adapter: call() on an id-field hash is refused with the field reason, unchanged from virustotal.js", async () => {
  const aid = "0123456789abcdef0123456789abcdef";
  const res = await vt.call(aid, { fieldName: "aid", ask: async () => { throw new Error("must not be called"); } });
  assert.equal(res.status, "refused");
});

test("vt adapter: call() sends nothing without ctx.ask (no background worker in this context)", async () => {
  const res = await vt.call("8.8.8.8", {});
  assert.equal(res.status, "error");
  assert.match(res.lines[0], /background worker/);
  assert.ok(res.link, "the open-anyway link is still offered");
});

test("vt adapter: call() reshapes a report into ok lines with the same verdict and facts", async () => {
  const data = {
    data: {
      attributes: {
        last_analysis_stats: { malicious: 2, suspicious: 0, harmless: 60, undetected: 10 },
        last_analysis_date: 1700000000,
        as_owner: "GOOGLE",
        asn: 15169,
        country: "US",
      },
    },
  };
  const res = await vt.call("8.8.8.8", { ask: async (msg) => { assert.equal(msg.type, "reach:vt:lookup"); return { ok: true, status: 200, data }; } });
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /^malicious: 2 of 72 vendors flag it as malicious/);
  assert.ok(res.lines.some((l) => l.startsWith("owner: GOOGLE")));
});

test("vt adapter: source object registers cleanly as the one fetch source", () => {
  enrich.register(vt.source);
  assert.equal(enrich.get("virustotal").mode, "fetch");
  assert.deepEqual(enrich.list("hash").map((s) => s.id), ["virustotal"]);
  assert.deepEqual(enrich.gate(vt.source, { enabledIds: [] }), { allowed: false, why: "VirusTotal is not configured. Set it up in Reach's settings before anything is sent to it.", configure: true });
});

test("kev source object registers cleanly as the one bundle source for cve", () => {
  enrich.register(kev.source);
  assert.equal(enrich.get("kev").mode, "bundle");
  assert.deepEqual(enrich.gate(kev.source, { enabledIds: [] }), { allowed: true });
});
