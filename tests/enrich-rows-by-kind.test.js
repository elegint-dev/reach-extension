// Enrichment rows draw only for sources whose declared kinds include the
// clicked value's kind, on every surface enrichBlock draws for (the Splunk
// popup, the blade menu, the value page). A GuardDuty finding id is an
// MD5-length hex string: hash-shaped for VirusTotal and CIRCL, never a
// SHA-256 for LOLDrivers, whose catalogue indexes nothing shorter.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import "./_splunk.js";
import * as dom from "./_dom.js";
import * as enrich from "../app/lib/enrich.js";
import * as modules from "../app/lib/modules.js";
import { source as kev } from "../app/lib/enrich/kev.js";
import { source as virustotal } from "../app/lib/enrich/virustotal.js";
import { enrichBlock } from "../app/lib/popup-ui.js";

const FINDING_ID = "16afba5c5c43e07c9e3e5e2e544e95df";
const SHA256 = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";
const IP = "8.8.8.8";

before(() => {
  for (const s of [kev, virustotal]) {
    try {
      enrich.register(s);
    } catch {
      /* registered by another file in this process */
    }
  }
});

const bundled = () => modules.sources("splunk");
const withVt = () => [...bundled(), "virustotal"];
const ids = (offers) => offers.map((o) => o.source.id);
dom.install(); // a bundled row's own lookup lands in the DOM after the test returns
const block = (value, offers) => enrichBlock({ value, offers, ask: async () => null, settingsUrl: "options.html#virustotal" });

test("a finding id (MD5-length hex) offers no bundled source: LOLDrivers answers sha256 only, so no Enrichment block is drawn at all", () => {
  const offers = enrich.offersFor(FINDING_ID, { fieldName: "gd_finding_id", enabledIds: [], sources: bundled() });
  assert.deepEqual(ids(offers), []);
  assert.equal(block(FINDING_ID, offers), null);
});

test("a finding id with VirusTotal on offers VirusTotal alone, still never LOLDrivers or KEV", () => {
  const offers = enrich.offersFor(FINDING_ID, { fieldName: "gd_finding_id", enabledIds: ["virustotal"], sources: withVt() });
  assert.deepEqual(ids(offers), ["virustotal"]);
});

test("a sha256 offers LOLDrivers and never KEV; VirusTotal joins when its module is on, with its button unclicked", () => {
  const off = enrich.offersFor(SHA256, { fieldName: "SHA256HashData", enabledIds: [], sources: bundled() });
  assert.deepEqual(ids(off), ["loldrivers"]);
  const on = enrich.offersFor(SHA256, { fieldName: "SHA256HashData", enabledIds: ["virustotal"], sources: withVt() });
  assert.deepEqual(ids(on).sort(), ["loldrivers", "virustotal"]);
  const el = block(SHA256, on);
  assert.ok(el, "a block is drawn");
  assert.deepEqual(dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__label")).map(dom.text).sort(), ["LOLDrivers", "VirusTotal"]);
  assert.equal(dom.text(dom.walk(el, (n) => n.classList && n.classList.contains("reach-run-btn--live"))[0]), "Check on VirusTotal");
});

test("an IP offers VirusTotal when on and nothing bundled: no hash or sha256 source lists it", () => {
  assert.deepEqual(ids(enrich.offersFor(IP, { fieldName: "src_ip", enabledIds: [], sources: bundled() })), []);
  assert.deepEqual(ids(enrich.offersFor(IP, { fieldName: "src_ip", enabledIds: ["virustotal"], sources: withVt() })), ["virustotal"]);
});

test("enrichBlock drops an offer whose kind the source never declared, whoever built the offer", () => {
  const stray = { source: kev, kind: "hash", id: FINDING_ID, allowed: true };
  assert.equal(block(FINDING_ID, [stray]), null);
});
