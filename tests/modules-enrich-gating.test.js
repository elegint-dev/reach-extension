// An enrichment source offers only while its module is on: an off module's
// row is absent, never greyed; an on-but-unconfigured source's row says
// "not configured" and links the settings surface on that module's head;
// a bundled source narrowed to one platform offers only there.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import * as enrich from "../app/lib/enrich.js";
import { source as kevSource } from "../app/lib/enrich/kev.js";
import { source as vtSource } from "../app/lib/enrich/virustotal.js";
import { enrichBlock } from "../app/lib/popup-ui.js";

for (const s of [kevSource, vtSource]) {
  try {
    enrich.register(s);
  } catch {
    /* already registered */
  }
}

const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";
fakeChrome({ storage: false }).install();

test("offersFor with the registry's source set: the off modules' sources are absent, the bundled ones offer", async () => {
  modules.reset();
  await modules.hydrate();
  const offers = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: [], sources: modules.sources("splunk") });
  const ids = offers.map((o) => o.source.id);
  assert.ok(ids.includes("loldrivers"), `bundled LOLDrivers offers on a hash: ${ids}`);
  for (const off of ["virustotal", "circl", "selfhosted"]) assert.ok(!ids.includes(off), `${off} is off by default and must not be offered: ${ids}`);
});

test("offersFor without a source set keeps every registered source, the shape the older callers pass", () => {
  const ids = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: [] }).map((o) => o.source.id);
  assert.ok(ids.includes("virustotal"));
});

test("a module switched on but not configured offers a row that says so and links its settings anchor", async () => {
  modules.reset();
  await modules.hydrate();
  const res = await modules.setEnabled("virustotal", true);
  assert.equal(res.ok, true);
  assert.deepEqual(res.hosts, ["https://www.virustotal.com/*"], "the enable click requests the module's host");
  const offers = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: [], sources: modules.sources("splunk") });
  const vt = offers.find((o) => o.source.id === "virustotal");
  assert.ok(vt, "VirusTotal offers once its module is on");
  assert.equal(vt.allowed, false);
  assert.equal(vt.configure, true);

  const restore = dom.install();
  try {
    const el = enrichBlock({ value: HASH, offers: [vt], ask: async () => null, settingsUrl: (source) => `options.html#${modules.anchor(modules.sourceOwner(source.id).id)}` });
    const setup = dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__setup"))[0];
    assert.ok(setup, "the row carries a set-it-up link");
    assert.equal(setup.getAttribute("href"), "options.html#module-virustotal");
    assert.match(dom.text(el), /VirusTotal: not configured/);
    assert.match(dom.text(setup), /Set it up/);
  } finally {
    restore();
  }

  // Configured: the row is the Check button, no setup link.
  const on = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: ["virustotal"], sources: modules.sources("splunk") }).find((o) => o.source.id === "virustotal");
  assert.equal(on.allowed, true);
  await modules.setEnabled("virustotal", false);
});

test("a shape refusal draws no set-it-up link: the value, not the setup, is the reason", async () => {
  modules.reset();
  await modules.hydrate();
  await modules.setEnabled("virustotal", true);
  const offers = enrich.offersFor("10.0.0.7", { fieldName: "src_ip", enabledIds: ["virustotal"], sources: modules.sources("splunk") });
  const vt = offers.find((o) => o.source.id === "virustotal");
  assert.ok(vt && vt.allowed === false && !vt.configure);
  const restore = dom.install();
  try {
    const el = enrichBlock({ value: "10.0.0.7", offers: [vt], ask: async () => null, settingsUrl: () => "options.html#module-virustotal" });
    assert.equal(dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__setup")).length, 0);
    assert.match(dom.text(el), /Not sent/);
  } finally {
    restore();
    await modules.setEnabled("virustotal", false);
  }
});

test("ESCU offers on Splunk only and the Sentinel rule index on Sentinel only", async () => {
  modules.reset();
  await modules.hydrate();
  const splunk = enrich.offersFor("T1003.001", { fieldName: "technique", enabledIds: [], sources: modules.sources("splunk") }).map((o) => o.source.id);
  const sentinel = enrich.offersFor("T1003.001", { fieldName: "technique", enabledIds: [], sources: modules.sources("sentinel") }).map((o) => o.source.id);
  assert.ok(splunk.includes("escu") && !splunk.includes("sentinel-rules"), `splunk: ${splunk}`);
  assert.ok(sentinel.includes("sentinel-rules") && !sentinel.includes("escu"), `sentinel: ${sentinel}`);
  assert.ok(splunk.includes("attack") && sentinel.includes("attack"));
});

test("the bundled module off removes every bundled row; the enrichment band then has nothing to draw", async () => {
  modules.reset();
  await modules.hydrate();
  await modules.setEnabled("enrich-bundled", false);
  assert.deepEqual(modules.sources("splunk"), []);
  const offers = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: [], sources: modules.sources("splunk") });
  assert.deepEqual(offers, []);
  await modules.setEnabled("enrich-bundled", true);
});
