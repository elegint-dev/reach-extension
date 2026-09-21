// An enabled-but-unconfigured source's "Set it up" link is one click away:
// its row stands open beside the first offer, never inside the "N more
// enrichment sources" fold, on every surface enrichBlock draws for.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import * as modules from "../app/lib/modules.js";
import * as enrich from "../app/lib/enrich.js";
import { source as loldrivers } from "../app/lib/enrich/loldrivers.js";
import { source as circl } from "../app/lib/enrich/circl.js";
import { source as virustotal } from "../app/lib/enrich/virustotal.js";
import { source as selfhosted } from "../app/lib/enrich/selfhosted.js";
import { enrichBlock } from "../app/lib/popup-ui.js";
import { heading } from "../app/lib/headings.js";

for (const s of [loldrivers, circl, virustotal, selfhosted]) {
  try {
    enrich.register(s);
  } catch {
    /* already registered */
  }
}

const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";
const fake = fakeChrome({ storage: false });
fake.chrome.permissions.contains = async () => true; // every host granted
fake.install();
// One DOM for the file: a bundled row's lookup settles after its test ends.
const restore = dom.install();

function inFold(node) {
  for (let p = node.parentNode; p; p = p.parentNode) if (p.classList && p.classList.contains("reach-fold")) return true;
  return false;
}

// A bundled row settles its lookup after the block is drawn; wait for it so
// nothing renders after the test ends.
async function settled(el) {
  for (let i = 0; i < 200; i++) {
    if (!dom.walk(el, (n) => n.classList && n.classList.contains("reach-row__body") && dom.text(n) === "Checking…").length) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("a bundled row never settled");
}

function draw(offers) {
  return enrichBlock({ value: HASH, offers, ask: async () => null, settingsUrl: (source) => `options.html#${modules.anchor(modules.sourceOwner(source.id).id)}` });
}

test("the self-hosted row's Set it up link stands outside the fold when a bundled row comes first", async () => {
  modules.reset();
  await modules.hydrate();
  await modules.setEnabled("selfhosted", true);
  const offers = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: [], sources: modules.sources("splunk") });
  assert.equal(offers[0].source.id, "loldrivers", "the bundled row is the first offer");
  const sh = offers.find((o) => o.source.id === "selfhosted");
  assert.ok(sh && sh.configure === true);
  try {
    const el = draw(offers);
    const setup = dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__setup"));
    assert.equal(setup.length, 1);
    assert.equal(setup[0].getAttribute("href"), "options.html#module-selfhosted");
    assert.equal(inFold(setup[0]), false, "the link is not behind the fold");
    assert.equal(dom.walk(el, (n) => n.classList && n.classList.contains("reach-fold")).length, 0, "nothing is left to fold");
    await settled(el);
  } finally {
    await modules.setEnabled("selfhosted", false);
  }
});

test("only rows past the first without a setup link fold; every configure row stays open, in offer order", async () => {
  modules.reset();
  await modules.hydrate();
  for (const id of ["virustotal", "circl", "selfhosted"]) await modules.setEnabled(id, true);
  const offers = enrich.offersFor(HASH, { fieldName: "SHA256HashData", enabledIds: ["circl"], sources: modules.sources("splunk") });
  // Registration order: CIRCL, LOLDrivers, the relay, then VirusTotal.
  assert.deepEqual(offers.map((o) => o.source.id), ["circl", "loldrivers", "selfhosted", "virustotal"]);
  try {
    const el = draw(offers);
    const rows = dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__row"));
    // A source's label is its own class: the band title class is reserved for the section's heading (C5).
    const label = (r) => dom.text(dom.walk(r, (n) => n.classList && n.classList.contains("reach-enrich__label"))[0]);
    const open = rows.filter((r) => !inFold(r)).map(label);
    const folded = rows.filter((r) => inFold(r)).map(label);
    assert.deepEqual(open, ["CIRCL hashlookup", "Self-hosted (MISP / IntelOwl)", "VirusTotal"]);
    assert.deepEqual(folded, ["LOLDrivers"]);
    for (const setup of dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__setup"))) assert.equal(inFold(setup), false);
    const summary = dom.walk(el, (n) => n.tagName === "SUMMARY")[0];
    assert.equal(dom.text(summary), heading("other-sources", 1), "the fold's title is the registry's");
    await settled(el);
  } finally {
    for (const id of ["virustotal", "circl", "selfhosted"]) await modules.setEnabled(id, false);
  }
});

test.after(() => restore());
