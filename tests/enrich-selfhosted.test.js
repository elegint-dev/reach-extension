// The G5 self-hosted enrichment source (app/lib/enrich/selfhosted.js): a
// user-typed MISP or IntelOwl origin. Response parsers exercised
// against fixtures shaped like each API's own documented response
// (tests/fixtures/misp-restsearch-{hit,miss}.json,
// tests/fixtures/intelowl-jobs-{hit,miss}.json). No live calls in this file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as selfhosted from "../app/lib/enrich/selfhosted.js";
import * as enrich from "../app/lib/enrich.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(path.join(here, "fixtures", name)));

// ---------------------------------------------------------------------------
// classify(): the union of kinds this source answers

test("classify: hash, ip and domain follow VirusTotal's own conservative rule", () => {
  const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.deepEqual(selfhosted.classify(sha256), { kind: "hash", id: sha256 });
  assert.deepEqual(selfhosted.classify("8.8.8.8"), { kind: "ip", id: "8.8.8.8" });
  assert.deepEqual(selfhosted.classify("example.com"), { kind: "domain", id: "example.com" });
  assert.equal(selfhosted.classify("10.0.0.5"), null, "a private address is refused, same as VirusTotal");
});

test("classify: a CVE id", () => {
  assert.deepEqual(selfhosted.classify("cve-2021-44228"), { kind: "cve", id: "CVE-2021-44228" });
});

test("classify: an absolute URL, a shape VirusTotal never offers", () => {
  assert.deepEqual(selfhosted.classify("https://example.com/a/b?c=1"), { kind: "url", id: "https://example.com/a/b?c=1" });
  assert.equal(selfhosted.classify("not a url"), null);
});

test("classify: nothing matches a bare word", () => {
  assert.equal(selfhosted.classify("hello"), null);
});

// ---------------------------------------------------------------------------
// originStatus(): https required, http only for localhost/RFC1918

test("originStatus: https is accepted outright, path/query/fragment refused", () => {
  assert.deepEqual(selfhosted.originStatus("https://misp.example.org"), { ok: true, origin: "https://misp.example.org" });
  assert.deepEqual(selfhosted.originStatus("https://misp.example.org:8443"), { ok: true, origin: "https://misp.example.org:8443" });
  assert.equal(selfhosted.originStatus("https://misp.example.org/attributes").ok, false);
  assert.equal(selfhosted.originStatus("https://misp.example.org?x=1").ok, false);
});

test("originStatus: http is accepted only for localhost or RFC1918, with a warning kept", () => {
  const local = selfhosted.originStatus("http://localhost:8080");
  assert.equal(local.ok, true);
  assert.match(local.warn, /http, not https/);

  const rfc1918 = selfhosted.originStatus("http://10.1.2.3");
  assert.equal(rfc1918.ok, true);
  assert.ok(rfc1918.warn);

  const publicHttp = selfhosted.originStatus("http://misp.example.org");
  assert.equal(publicHttp.ok, false);
  assert.match(publicHttp.why, /https/);
});

test("originStatus: empty, malformed or a non-http(s) scheme is refused", () => {
  assert.equal(selfhosted.originStatus("").ok, false);
  assert.equal(selfhosted.originStatus("not a url").ok, false);
  assert.equal(selfhosted.originStatus("ftp://misp.example.org").ok, false);
});

test("patternFor: mirrors popup.js's own ${protocol}//${host}/* shape, port included", () => {
  assert.equal(selfhosted.patternFor("https://misp.example.org:8443"), "https://misp.example.org:8443/*");
  assert.equal(selfhosted.patternFor("not a url"), null);
});

// ---------------------------------------------------------------------------
// deepLinkFor()

test("deepLinkFor: MISP names its own attributes page, IntelOwl links to the instance root", () => {
  assert.deepEqual(selfhosted.deepLinkFor("misp", "https://misp.example.org", "8.8.8.8"), { href: "https://misp.example.org/attributes/index?value=8.8.8.8", label: "Open in MISP ↗" });
  assert.equal(selfhosted.deepLinkFor("intelowl", "https://intelowl.example.org", "8.8.8.8").href, "https://intelowl.example.org/");
  assert.equal(selfhosted.deepLinkFor("misp", "not a url", "8.8.8.8"), null);
});

test("deepLinkFor: cortex is not a recognised provider", () => {
  assert.equal(selfhosted.deepLinkFor("cortex", "https://cortex.example.org", "8.8.8.8"), null);
});

// ---------------------------------------------------------------------------
// summarize()

test("summarize: MISP counts attributes and events, unions tags", () => {
  const hit = fixture("misp-restsearch-hit.json");
  const lines = selfhosted.summarize("misp", hit);
  assert.equal(lines[0], "2 matching attributes across 2 events.");
  assert.match(lines[1], /tags: tlp:amber, malware:emotet/);
});

test("summarize: MISP on an empty attribute list is empty", () => {
  assert.deepEqual(selfhosted.summarize("misp", fixture("misp-restsearch-miss.json")), []);
});

// misp-restsearch-event-tags.json: a real includeEventTags=1 response
// (captured from a local MISP), where both tags come from the event, not
// the attribute, and arrive in the order MISP happened to attach them
// (tlp, then the galaxy tag) here, but the ordering has to hold regardless
// of that arrival order, which the false-positive fixture below checks.
test("summarize: TLP leads the tag line, ahead of the ATT&CK technique tag, for tags merged in from the event", () => {
  const lines = selfhosted.summarize("misp", fixture("misp-restsearch-event-tags.json"));
  assert.equal(lines[0], "1 matching attribute across 1 event.");
  assert.equal(lines[1], 'tags: tlp:amber, misp-galaxy:mitre-attack-pattern="OS Credential Dumping: LSASS Memory - T1003.001"');
});

// misp-restsearch-false-positive.json: the attribute's own tag
// (false-positive) is first in MISP's Tag array, ahead of the two tags
// inherited from the event; the display order has to survive that.
test("summarize: false-positive sorts last even though MISP returns it first in the Tag array", () => {
  const lines = selfhosted.summarize("misp", fixture("misp-restsearch-false-positive.json"));
  assert.equal(lines[1], 'tags: tlp:amber, misp-galaxy:mitre-attack-pattern="OS Credential Dumping: LSASS Memory - T1003.001", false-positive');
});

test("summarize: IntelOwl reports prior job count and the latest status", () => {
  const hit = fixture("intelowl-jobs-hit.json");
  const lines = selfhosted.summarize("intelowl", hit);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^2 prior jobs for this observable \(latest: reported_without_fails on 2026-09-01\)\.$/);
});

test("summarize: IntelOwl on no results is empty", () => {
  assert.deepEqual(selfhosted.summarize("intelowl", fixture("intelowl-jobs-miss.json")), []);
});

// ---------------------------------------------------------------------------
// call()

test("call: a refused value never asks", async () => {
  let asked = false;
  const res = await selfhosted.call("not a candidate value", {
    provider: "misp",
    origin: "https://misp.example.org",
    ask: async () => {
      asked = true;
    },
  });
  assert.equal(res.status, "refused");
  assert.equal(asked, false);
});

test("call: an unrecognised provider such as a stored cortex value falls back to misp", async () => {
  const res = await selfhosted.call("8.8.8.8", {
    provider: "cortex",
    origin: "https://misp.example.org",
    ask: async () => ({ ok: true, status: 200, data: fixture("misp-restsearch-miss.json") }),
  });
  assert.equal(res.status, "empty");
});

test("call: misp hit and miss map onto ok and empty", async () => {
  const hit = fixture("misp-restsearch-hit.json");
  const hitRes = await selfhosted.call("8.8.8.8", { provider: "misp", origin: "https://misp.example.org", ask: async () => ({ ok: true, status: 200, data: hit }) });
  assert.equal(hitRes.status, "ok");
  assert.match(hitRes.lines[0], /matching attribute/);

  const missRes = await selfhosted.call("8.8.8.8", { provider: "misp", origin: "https://misp.example.org", ask: async () => ({ ok: true, status: 200, data: fixture("misp-restsearch-miss.json") }) });
  assert.equal(missRes.status, "empty");
});

test("call: an ask failure or a missing worker reports an error, never throws", async () => {
  const errored = await selfhosted.call("8.8.8.8", { provider: "misp", origin: "https://misp.example.org", ask: async () => ({ ok: false, status: 401, error: "https://misp.example.org rejected the token." }) });
  assert.equal(errored.status, "error");
  assert.match(errored.lines[0], /rejected the token/);

  const noWorker = await selfhosted.call("8.8.8.8", { provider: "misp", origin: "https://misp.example.org" });
  assert.equal(noWorker.status, "error");
});

// ---------------------------------------------------------------------------
// registration and gating

test("source: fetch mode, off unless enabled, registered under enrich.js", () => {
  assert.equal(selfhosted.source.mode, "fetch");
  assert.equal(enrich.gate(selfhosted.source, { enabledIds: [] }).allowed, false);
  assert.equal(enrich.gate(selfhosted.source, { enabledIds: ["selfhosted"] }).allowed, true);
  assert.equal(enrich.get("selfhosted").id, "selfhosted");
});

test("source recipients name the user's own server, not a third party", () => {
  assert.match(selfhosted.source.recipients[0], /your own account/);
});

test("enrich.kindsFor: an absolute URL is offered as the url kind, and the selfhosted source is listed for it", () => {
  const kinds = enrich.kindsFor("https://example.com/a?b=1", {});
  assert.ok(kinds.some((k) => k.kind === "url"));
  const urlSources = enrich.list("url");
  assert.ok(urlSources.some((s) => s.id === "selfhosted"));
});

test("enrich.offersFor: a url click offers selfhosted, gated off by default", () => {
  const offers = enrich.offersFor("https://example.com/a?b=1", {});
  const row = offers.find((o) => o.source.id === "selfhosted" && o.kind === "url");
  assert.ok(row);
  assert.equal(row.allowed, false);
});

test("registry: no cortex provider or label, the self-hosted source is MISP/IntelOwl only", () => {
  assert.equal(selfhosted.PROVIDERS.includes("cortex"), false);
  assert.deepEqual(selfhosted.PROVIDERS, ["misp", "intelowl"]);
  assert.equal("cortex" in selfhosted.PROVIDER_LABEL, false);
  assert.equal(selfhosted.source.label.includes("Cortex"), false);
});
