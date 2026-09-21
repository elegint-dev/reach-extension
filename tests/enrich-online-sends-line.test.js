// An online enrichment row (a fetch or stream source that can send) prints
// its owning module's sends line beside its button, read off the registry
// (app/lib/modules.js), so every such row says what leaves and where
// before the click: VirusTotal, CIRCL and EPSS alike. A bundled row and a
// refused row print none: nothing is about to leave.
import { test } from "node:test";
import assert from "node:assert/strict";
import "./_splunk.js";
import * as dom from "./_dom.js";
import * as enrich from "../app/lib/enrich.js";
import * as modules from "../app/lib/modules.js";
import { source as lolbas } from "../app/lib/enrich/lolbas.js";
import { source as virustotal } from "../app/lib/enrich/virustotal.js";
import { source as circl } from "../app/lib/enrich/circl.js";
import { source as epss } from "../app/lib/enrich/epss.js";
import { enrichBlock } from "../app/lib/popup-ui.js";

for (const s of [lolbas, virustotal, circl, epss]) {
  try {
    enrich.register(s);
  } catch {
    /* registered by another file in this process */
  }
}
const restore = dom.install();
test.after(() => restore());

const offer = (source, kind, allowed = true) => ({ source, kind, id: "x", allowed });
const rowsOf = (el) => dom.walk(el, (n) => n.classList && n.classList.contains("reach-enrich__row"));
const sendsOf = (row) => dom.walk(row, (n) => n.classList && n.classList.contains("reach-enrich__sends")).map((n) => dom.text(n));
const buttonOf = (row) => dom.walk(row, (n) => n.tagName === "BUTTON" && /^Check on/.test(dom.text(n)))[0] || null;

const HASH = "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9";

for (const [source, kind, value] of [[virustotal, "hash", HASH], [circl, "hash", HASH], [epss, "cve", "CVE-2021-44228"]]) {
  test(`the ${source.label} row draws its module's sends line beside the button`, () => {
    const el = enrichBlock({ value, offers: [offer(source, kind)], ask: async () => null, settingsUrl: "options.html" });
    const row = rowsOf(el)[0];
    assert.ok(buttonOf(row), "an online row draws its button");
    const owner = modules.sourceOwner(source.id);
    assert.deepEqual(sendsOf(row), [`Sends: ${owner.sends}`]);
  });
}

test("a bundled row and a refused online row print no sends line", () => {
  const bundled = rowsOf(enrichBlock({ value: "certutil.exe", offers: [offer(lolbas, "binary_name")], ask: async () => null, settingsUrl: "options.html" }))[0];
  assert.deepEqual(sendsOf(bundled), []);
  const refused = rowsOf(enrichBlock({ value: HASH, offers: [{ ...offer(circl, "hash", false), why: "CIRCL hashlookup is off." }], ask: async () => null, settingsUrl: "options.html" }))[0];
  assert.deepEqual(sendsOf(refused), []);
});
