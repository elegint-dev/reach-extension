// The G4 fetch-mode sources, both off by default: CIRCL hashlookup
// (app/lib/enrich/circl.js) and EPSS (app/lib/enrich/epss.js), each
// gated the same way VirusTotal is, response parsers exercised against
// fixtures captured from the live APIs on 2026-09-19
// (tests/fixtures/circl-hashlookup-{hit,miss}.json,
// tests/fixtures/epss-{hit,miss}.json). No live calls in this file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as circl from "../app/lib/enrich/circl.js";
import * as epss from "../app/lib/enrich/epss.js";
import * as enrich from "../app/lib/enrich.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(path.join(here, "fixtures", name)));

// ---------------------------------------------------------------------------
// CIRCL hashlookup

test("circl: classify only a hash, the same rule as app/lib/virustotal.js", () => {
  const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.deepEqual(circl.classify(sha256), { kind: "hash", id: sha256 });
  assert.equal(circl.classify("8.8.8.8"), null);
  assert.equal(circl.classify("example.com"), null);
  const aid = "0123456789abcdef0123456789abcdef";
  assert.equal(circl.classify(aid, { fieldName: "aid" }), null, "an id field's hex is not a hash, same as VirusTotal");
});

test("circl: linkFor is always null, no per-hash public page", () => {
  assert.equal(circl.linkFor("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), null);
});

test("circl: summarize() on a live hit fixture names the dataset and any parent packages", () => {
  const hit = fixture("circl-hashlookup-hit.json");
  const lines = circl.summarize(hit);
  assert.match(lines[0], /^Known good, known in \d+ sources \(NSRL/);
  assert.ok(lines.some((l) => l.startsWith("File name on record:")));
});

test("circl: summarize() on a bare NSRL hit with no parents", () => {
  const lines = circl.summarize({ db: "nsrl_legacy", FileName: "notepad.exe" });
  assert.equal(lines[0], "Known good, known in NSRL.");
  assert.equal(lines[1], "File name on record: notepad.exe");
});

test("circl: call() on a live miss fixture reports empty, on a hit reports ok", async () => {
  const miss = fixture("circl-hashlookup-miss.json");
  const hit = fixture("circl-hashlookup-hit.json");
  const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  const missRes = await circl.call(sha256, { ask: async () => ({ ok: false, status: 404, data: miss }) });
  assert.equal(missRes.status, "empty");

  const hitRes = await circl.call(sha256, { ask: async () => ({ ok: true, status: 200, data: hit }) });
  assert.equal(hitRes.status, "ok");
  assert.match(hitRes.lines[0], /Known good/);
});

test("circl: call() on a refused value never asks; on an ask failure reports an error", async () => {
  let asked = false;
  const refused = await circl.call("8.8.8.8", { ask: async () => { asked = true; } });
  assert.equal(refused.status, "refused");
  assert.equal(asked, false);

  const errored = await circl.call("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", { ask: async () => ({ ok: false, status: 500, error: "boom" }) });
  assert.equal(errored.status, "error");
  assert.equal(errored.lines[0], "boom");

  const noWorker = await circl.call("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", {});
  assert.equal(noWorker.status, "error");
});

test("circl: source object is fetch mode, off unless enabled", () => {
  assert.equal(circl.source.mode, "fetch");
  const gated = enrich.gate(circl.source, { enabledIds: [] });
  assert.equal(gated.allowed, false);
  assert.equal(enrich.gate(circl.source, { enabledIds: ["circl"] }).allowed, true);
});

// ---------------------------------------------------------------------------
// EPSS

test("epss: classify only a CVE id", () => {
  assert.deepEqual(epss.classify("CVE-2021-44228"), { kind: "cve", id: "CVE-2021-44228" });
  assert.equal(epss.classify("8.8.8.8"), null);
});

test("epss: summarize() on a live high-percentile fixture renders score and top-percent", () => {
  const hit = fixture("epss-hit.json");
  const lines = epss.summarize(hit.data[0]);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^EPSS 1\.00 \(top <0\.1 percent\) as of \d{4}-\d{2}-\d{2}$/);
});

test("epss: summarize() derives top-percent from percentile, not from the score", () => {
  // A mid-range CVE: a high score does not by itself mean a high percentile.
  const lines = epss.summarize({ cve: "CVE-0000-0000", epss: "0.40000", percentile: "0.98000", date: "2026-01-01" });
  assert.equal(lines[0], "EPSS 0.40 (top 2 percent) as of 2026-01-01");
});

test("epss: summarize() on no row, or a row missing a score, is empty", () => {
  assert.deepEqual(epss.summarize(null), []);
  assert.deepEqual(epss.summarize({ cve: "CVE-0000-0000", percentile: "0.5" }), []);
});

test("epss: call() on the live miss fixture (empty data array) reports no score", async () => {
  const miss = fixture("epss-miss.json");
  const res = await epss.call("CVE-1999-9999", { ask: async () => ({ ok: true, status: 200, data: miss }) });
  assert.equal(res.status, "empty");
});

test("epss: call() on the live hit fixture reports ok", async () => {
  const hit = fixture("epss-hit.json");
  const res = await epss.call("CVE-2021-44228", { ask: async () => ({ ok: true, status: 200, data: hit }) });
  assert.equal(res.status, "ok");
  assert.match(res.lines[0], /^EPSS 1\.00/);
});

test("epss: call() on a refused value never asks", async () => {
  let asked = false;
  const res = await epss.call("not a cve", { ask: async () => { asked = true; } });
  assert.equal(res.status, "refused");
  assert.equal(asked, false);
});

test("epss: source object is fetch mode, off unless enabled", () => {
  assert.equal(epss.source.mode, "fetch");
  assert.equal(enrich.gate(epss.source, { enabledIds: [] }).allowed, false);
  assert.equal(enrich.gate(epss.source, { enabledIds: ["epss"] }).allowed, true);
});
