// An enrichment row's "bundled" mark (nothing left the browser to answer
// it) is read off the owning module's declared `sends` line in the
// registry (app/lib/modules.js), never a per-row list of source ids and
// never source.mode alone: a bundle source and a deep-link source both
// carry it when their module says "nothing", and a fetch source with a
// real destination never does, however its offer is gated.
import { test } from "node:test";
import assert from "node:assert/strict";
import "./_splunk.js";
import * as dom from "./_dom.js";
import * as enrich from "../app/lib/enrich.js";
import * as modules from "../app/lib/modules.js";
import { source as kev } from "../app/lib/enrich/kev.js";
import { source as lolbas } from "../app/lib/enrich/lolbas.js";
import { source as virustotal } from "../app/lib/enrich/virustotal.js";
import { enrichBlock } from "../app/lib/popup-ui.js";

const BUNDLED_TITLE = "read from the extension's own file, nothing sent";

for (const s of [kev, lolbas, virustotal]) {
  try {
    enrich.register(s);
  } catch {
    /* registered by another file in this process */
  }
}

const restore = dom.install();

function offer(source, kind, allowed = true) {
  return { source, kind, id: "x", allowed };
}

function rowsOf(el) {
  return dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__row"));
}

function labelOf(row) {
  return dom.text(dom.walk(row, (n) => n.classList && n.classList.contains("reach-enrich__label"))[0]);
}

function bundledMarkOf(row) {
  return dom.walk(row, (n) => n.classList && n.classList.contains("reach-enrich__bundled"))[0] || null;
}

// A bundled row settles its own async lookup after the block is drawn.
async function settled(el) {
  for (let i = 0; i < 200; i++) {
    if (!dom.walk(el, (n) => n.classList && n.classList.contains("reach-row__body") && dom.text(n) === "Checking…").length) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("a bundled row never settled");
}

test("a bundle-mode source owned by a module whose sends is 'nothing...' carries the bundled mark, titled from the registry, not the row", async () => {
  const el = enrichBlock({ value: "CVE-2021-44228", offers: [offer(kev, "cve")], ask: async () => null, settingsUrl: "options.html" });
  const row = rowsOf(el)[0];
  assert.equal(labelOf(row), "CISA KEV", "the mark is a sibling of the label, never appended into its text");
  const mark = bundledMarkOf(row);
  assert.ok(mark, "CISA KEV is owned by enrich-bundled, whose sends starts with nothing");
  assert.equal(mark.getAttribute("title"), BUNDLED_TITLE);
  await settled(el);
});

test("a deep-link source under the same offline module carries the mark too: it is not keyed off mode === 'bundle'", () => {
  const el = enrichBlock({ value: "certutil.exe", offers: [offer(lolbas, "binary_name")], ask: async () => null, settingsUrl: "options.html" });
  const row = rowsOf(el)[0];
  assert.equal(labelOf(row), "LOLBAS");
  assert.ok(bundledMarkOf(row), "lolbas is owned by enrich-bundled, whose sends also starts with nothing");
});

test("a fetch source owned by a module with a real destination never carries the mark, allowed or refused", () => {
  const allowedEl = enrichBlock({ value: "8.8.8.8", offers: [offer(virustotal, "ip", true)], ask: async () => null, settingsUrl: "options.html" });
  const allowedRow = rowsOf(allowedEl)[0];
  assert.equal(labelOf(allowedRow), "VirusTotal");
  assert.equal(bundledMarkOf(allowedRow), null);

  const refusedEl = enrichBlock({
    value: "8.8.8.8",
    offers: [{ ...offer(virustotal, "ip", false), why: "VirusTotal is off." }],
    ask: async () => null,
    settingsUrl: "options.html",
  });
  const refusedRow = rowsOf(refusedEl)[0];
  assert.equal(bundledMarkOf(refusedRow), null, "the sends line, not the allowed/refused gate, decides the mark");
});

test("the registry, not a hardcoded id list, decides the mark: an id with no owning module gets none even in bundle mode", async () => {
  const orphan = { id: "no-such-module-owns-me", label: "Orphan Source", kinds: ["cve"], mode: "bundle", call: async () => ({ status: "empty", lines: [] }), linkFor: () => null };
  assert.equal(modules.sourceOwner(orphan.id), null, "fixture: no module in the registry declares this id");
  const el = enrichBlock({ value: "CVE-2021-44228", offers: [offer(orphan, "cve")], ask: async () => null, settingsUrl: "options.html" });
  const row = rowsOf(el)[0];
  assert.equal(bundledMarkOf(row), null);
  await settled(el);
});

test.after(() => restore());
