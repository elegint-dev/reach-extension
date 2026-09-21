// The G3 living-off-the-land sources: LOLDrivers and LOLRMM as bundled
// enrichment sources (app/lib/enrich/{loldrivers,lolrmm}.js) over a
// fixture, and LOLBAS, GTFOBins and HijackLibs as deep-link-only sources
// (app/lib/enrich/{lolbas,gtfobins,hijacklibs}.js, no data ships: GPL-3.0
// is deferred per docs/COMPLIANCE.md). Also checks the two committed
// bundles under app/data/enrich/ against the combined 300 KB gzip budget.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as loldrivers from "../app/lib/enrich/loldrivers.js";
import * as lolrmm from "../app/lib/enrich/lolrmm.js";
import * as lolbas from "../app/lib/enrich/lolbas.js";
import * as gtfobins from "../app/lib/enrich/gtfobins.js";
import * as hijacklibs from "../app/lib/enrich/hijacklibs.js";
import * as enrich from "../app/lib/enrich.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(here, "..", "app/data/enrich");

beforeEach(() => {
  loldrivers.reset();
  lolrmm.reset();
});

// ---------------------------------------------------------------------------
// LOLDrivers: bundle, hash and driver_name kinds

const LOLDRIVERS_DOC = {
  format: "reach-loldrivers",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  count: 2,
  entries: [
    { id: "00561455-9da1-4f0c-8564-e4c99b716a74", category: "malicious", names: ["driver_090d409f.sys"], sha256: ["090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49"] },
    { id: "0144dbef-1da8-406c-8e35-7afee57dc471", category: "vulnerable driver", names: ["isodrivep64.sys"], sha256: ["1e42c8cb410a7ed653cfe62bbd8cf191f31a47337fe1ffcc35232d03f2da05ef"] },
  ],
};

function stubFetch(doc) {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => doc });
}

test("loldrivers: classify a SHA-256 hash and a .sys driver name, never a bare word or a non-driver extension", () => {
  const sha = "090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49";
  assert.deepEqual(loldrivers.classify(sha), { kind: "sha256", id: sha });
  assert.deepEqual(loldrivers.classify("driver_090d409f.sys"), { kind: "driver_name", id: "driver_090d409f.sys" });
  assert.deepEqual(loldrivers.classify("C:\\Windows\\System32\\drivers\\iobios64.sys"), { kind: "driver_name", id: "iobios64.sys" });
  assert.equal(loldrivers.classify("certutil.exe"), null, "an .exe is not a driver");
  assert.equal(loldrivers.classify("bandaid"), null, "a bare word is never offered");
});

test("loldrivers: call() on a hash hit names the driver and its category", async () => {
  stubFetch(LOLDRIVERS_DOC);
  const res = await loldrivers.call("090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /malicious driver: driver_090d409f\.sys/);
  assert.equal(res.link.href, "https://www.loldrivers.io/drivers/00561455-9da1-4f0c-8564-e4c99b716a74/");
});

test("loldrivers: call() on a driver-name hit works even with no sample hash on the entry", async () => {
  stubFetch({ ...LOLDRIVERS_DOC, entries: [{ id: "058fb356", category: "vulnerable driver", names: ["bandai.sys"], sha256: [] }] });
  const res = await loldrivers.call("bandai.sys");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /vulnerable driver/);
});

test("loldrivers: call() on a miss says not in the catalogue", async () => {
  stubFetch(LOLDRIVERS_DOC);
  const res = await loldrivers.call("deadbeef00000000000000000000000000000000000000000000000000000000".slice(0, 64));
  assert.equal(res.status, "empty");
});

test("loldrivers: call() on a non-matching value is refused, no fetch attempted", async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return { ok: true, status: 200, json: async () => LOLDRIVERS_DOC }; };
  const res = await loldrivers.call("certutil.exe");
  assert.equal(res.status, "refused");
  assert.equal(called, false);
});

// ---------------------------------------------------------------------------
// LOLRMM: bundle, binary_name and domain kinds

const LOLRMM_DOC = {
  format: "reach-lolrmm",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  count: 1,
  entries: [{ name: "ZeroTier", slug: "zerotier", category: "RAT", installationPaths: ["zerotier*.msi", "zerotier*.exe", "zero-powershell.exe"], domains: ["zerotier.com", "*.zerotier.com"] }],
};

// A wildcard-only basename (`*\TightVNC\*`'s basename is `*` alone) must
// not stand in for a bare basename match: on main it turned globToRe into
// /^.*$/, so any binary_name or domain value read as a hit. The whole glob
// still answers a real, path-shaped click (a directory match), and a
// literal basename glob (`tigervnc*.exe`) still matches a bare name.
const WILDCARD_BASENAME_DOC = {
  format: "reach-lolrmm",
  version: 1,
  generated_at: "2026-09-18T00:00:00.000Z",
  count: 1,
  entries: [{ name: "TigerVNC", slug: "tigervnc", category: "RAT", installationPaths: ["tigervnc*.exe", "C:\\Program Files\\TightVNC\\*", "*\\TightVNC\\*", "*\\tvnserver.exe"], domains: [] }],
};

test("lolrmm: classify a binary name and a domain, never a driver or a DLL", () => {
  assert.deepEqual(lolrmm.classify("zerotier.exe"), { kind: "binary_name", id: "zerotier.exe" });
  assert.deepEqual(lolrmm.classify("sub.zerotier.com"), { kind: "domain", id: "sub.zerotier.com" });
  assert.equal(lolrmm.classify("iobios64.sys"), null);
  assert.equal(lolrmm.classify("version.dll"), null);
});

test("lolrmm: call() matches an installation-path glob, and a wildcard domain", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => LOLRMM_DOC });
  const byPath = await lolrmm.call("zerotier-one.exe");
  assert.equal(byPath.status, "ok");
  assert.match(byPath.lines[0], /ZeroTier/);
  assert.equal(byPath.link.href, "https://lolrmm.io/tools/zerotier");

  const byDomain = await lolrmm.call("relay.zerotier.com");
  assert.equal(byDomain.status, "ok");
});

test("lolrmm: call() on a miss says not in the index", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => LOLRMM_DOC });
  const res = await lolrmm.call("notarmm.exe");
  assert.equal(res.status, "empty");
});

test("lolrmm: a wildcard-only basename glob matches nothing on its own", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => WILDCARD_BASENAME_DOC });
  // "random.exe" has no path, so only a bare basename match could hit;
  // TigerVNC's only wildcard-only-basename globs (`*\TightVNC\*`,
  // `C:\Program Files\TightVNC\*`) must not stand in for that match.
  const res = await lolrmm.call("random.exe");
  assert.equal(res.status, "empty", "a wildcard-only basename must never match a bare, unrelated name");
});

test("lolrmm: TigerVNC's own GuardDuty-unrelated repro value is refused, not matched", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => WILDCARD_BASENAME_DOC });
  // The owner's reported repro string: no extension and no path separator,
  // so app/lib/shapes.js detectProcessName never offers it as a
  // binary_name in the first place, on main or after this fix.
  const res = await lolrmm.call("GeneratedFindingPublicDNSName1");
  assert.equal(res.status, "refused");
});

test("lolrmm: a literal glob still matches its own binary, wildcard-only or not", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => WILDCARD_BASENAME_DOC });
  const byLiteralBasename = await lolrmm.call("tigervnc.exe");
  assert.equal(byLiteralBasename.status, "ok");
  assert.match(byLiteralBasename.lines[0], /TigerVNC/);
});

test("lolrmm: a wildcard-only-basename glob still matches through the whole path, when the click is path-shaped", async () => {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => WILDCARD_BASENAME_DOC });
  // A directory match ("*\TightVNC\*") the basename alone could never
  // carry: "random.exe" alone missed above, but under a TightVNC folder
  // it is a real install. (No space in the path here: app/lib/shapes.js
  // detectProcessName refuses any value with whitespace, "C:\Program
  // Files\..." included, before this module ever sees it, which is a
  // shapes.js constraint and not part of this bug.)
  const res = await lolrmm.call("C:\\Apps\\TightVNC\\random.exe");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /TigerVNC/);
});

// The wildcard-only-basename bug is a property of app/lib/enrich/lolrmm.js's
// own installation-path glob matching alone: loldrivers.js indexes by an
// exact SHA-256 or an exact driver name (byHash/byName Maps, no glob), and
// lolbas.js/gtfobins.js/hijacklibs.js carry no dataset and no glob code at
// all (deep-link only, GPL-3.0 deferred per docs/COMPLIANCE.md). Neither
// side of this fix touches them.

test("loldrivers: an unrelated driver name never matches another entry's exact name", async () => {
  stubFetch(LOLDRIVERS_DOC);
  const res = await loldrivers.call("isodrivep64.sys");
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /vulnerable driver.*isodrivep64\.sys/);
  const miss = await loldrivers.call("driver_not_in_the_catalogue.sys");
  assert.equal(miss.status, "empty", "loldrivers has no glob path, so no name can match by accident");
});

test("lolbas: a deep link is built from the exact clicked name, no glob or catalogue lookup involved", () => {
  const link = lolbas.linkFor("psexec.exe");
  assert.match(link.href, /%22psexec\.exe%22/, "the search query carries the exact clicked name, not a pattern");
});

// ---------------------------------------------------------------------------
// LOLBAS, GTFOBins, HijackLibs: deep-link only, no data ships

test("lolbas: classify a Windows binary name, build a GitHub-search deep link, never fetch anything", () => {
  assert.deepEqual(lolbas.classify("Certutil.exe"), { kind: "binary_name", id: "Certutil.exe" });
  const link = lolbas.linkFor("Certutil.exe");
  assert.equal(link.href, "https://github.com/search?q=repo%3ALOLBAS-Project%2FLOLBAS%20%22Certutil.exe%22&type=code");
  assert.equal(lolbas.classify("iobios64.sys"), null, "a driver is LOLDrivers' shape, not LOLBAS'");
  assert.equal(lolbas.classify("version.dll"), null, "a library is HijackLibs' shape, not LOLBAS'");
  assert.equal(lolbas.linkFor("just text"), null);
});

test("gtfobins: only the basename of a path counts, never a bare word", () => {
  assert.equal(gtfobins.classify("find"), null, "a bare word with no path is not offered");
  assert.deepEqual(gtfobins.classify("/usr/bin/find"), { kind: "binary_name", id: "find" });
  const link = gtfobins.linkFor("/usr/bin/find");
  assert.equal(link.href, "https://gtfobins.org/gtfobins/find/");
});

test("hijacklibs: classify only a .dll name, deep link is a GitHub search", () => {
  assert.deepEqual(hijacklibs.classify("version.dll"), { kind: "dll_name", id: "version.dll" });
  assert.equal(hijacklibs.classify("certutil.exe"), null);
  const link = hijacklibs.linkFor("version.dll");
  assert.equal(link.href, "https://github.com/search?q=repo%3Awietze%2FHijackLibs%20%22version.dll%22&type=code");
});

test("lolbas/gtfobins/hijacklibs: deep-link call() carries the same link, never touches the network", async () => {
  let touched = false;
  globalThis.fetch = async () => { touched = true; throw new Error("must not be called"); };
  const a = await lolbas.call("Certutil.exe");
  const b = await gtfobins.call("/bin/cat");
  const c = await hijacklibs.call("version.dll");
  assert.equal(a.status, "ok");
  assert.equal(b.status, "ok");
  assert.equal(c.status, "ok");
  assert.equal(touched, false);
});

// ---------------------------------------------------------------------------
// kindsFor(): a "name.exe"-shaped value must not also read as a domain

test("kindsFor: a binary_name-shaped click is never also offered as a domain, so LOLRMM never grows two rows for one value", () => {
  const kinds = enrich.kindsFor("zerotier.exe").map((k) => k.kind);
  assert.deepEqual(kinds, ["binary_name"], "app/lib/virustotal.js classify() would otherwise also read this as a domain");
});

test("kindsFor: an actual hostname with no file-name shape still reads as a domain", () => {
  assert.deepEqual(enrich.kindsFor("zerotier.com"), [{ kind: "domain", id: "zerotier.com" }]);
});

// ---------------------------------------------------------------------------
// The committed bundles

test("app/data/enrich: loldrivers.json and lolrmm.json fit the combined 300 KB gzip budget", () => {
  let total = 0;
  for (const f of ["loldrivers.json", "lolrmm.json"]) total += gzipSync(readFileSync(path.join(DATA_DIR, f))).length;
  assert.ok(total <= 300 * 1024, `combined gzip size ${total} exceeds the 300 KB budget`);
});

test("app/data/enrich/loldrivers.json: every entry has an id and at least one name", () => {
  const doc = JSON.parse(readFileSync(path.join(DATA_DIR, "loldrivers.json")));
  assert.equal(doc.count, doc.entries.length);
  for (const e of doc.entries) {
    assert.ok(e.id, "entry missing an id");
    assert.ok(Array.isArray(e.names) && e.names.length, `${e.id}: no name`);
    for (const h of e.sha256) assert.match(h, /^[0-9a-f]{64}$/);
  }
});

test("app/data/enrich/lolrmm.json: every entry has a name and a slug", () => {
  const doc = JSON.parse(readFileSync(path.join(DATA_DIR, "lolrmm.json")));
  assert.equal(doc.count, doc.entries.length);
  for (const e of doc.entries) {
    assert.ok(e.name, "entry missing a name");
    assert.match(e.slug, /^[a-z0-9-]+$/, `${e.name}: slug is not URL-safe`);
  }
});
