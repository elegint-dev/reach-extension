// The field page's runbook line (app/views/field.js runbookLine): drawn
// under the title block only when this tab's last clicked row carried a
// rule key, linking the runbook page with the row's entities; absent on
// every other row, and absent while the runbooks module is off. The
// pack field page renders here; the FDR bundle's field page needs the
// ledger's DOM and is checked in the served harness.
import "./_splunk.js";
import "./_bundle.js";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

const restore = dom.install();
globalThis.document.head = new dom.Node("head");
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
const session = new Map();
globalThis.sessionStorage = { getItem: (k) => (session.has(k) ? session.get(k) : null), setItem: (k, v) => session.set(k, String(v)), removeItem: (k) => session.delete(k) };
const catalogue = await import("../app/lib/catalogue.js");
const modules = await import("../app/lib/modules.js");
const lastEvent = await import("../app/lib/last-event.js");
const fields = await import("../app/lib/pack-fields.js");
const field = await import("../app/views/field.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));

function ctxFor(params) {
  const drawer = {};
  for (const m of ["setTitle", "setSpl", "setParams", "setHazards", "setState", "setMacros", "setEmptyText"]) drawer[m] = () => {};
  return { fields, catalogue, route: "field", params, drawer, setUrl() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {}, navigate() {}, modules };
}

const lines = (el) => el.querySelectorAll(".r-runbook-line");

const PAGE = { name: "eventName", st: "aws:cloudtrail" };

test("with no alert row in the tab, the field page draws no runbook line and still renders", () => {
  lastEvent.clear();
  const el = field.render(ctxFor(PAGE));
  assert.ok(el.querySelector("h1"));
  assert.equal(lines(el).length, 0);
});

test("with a notable row remembered, the field page draws one runbook line under the title block, linking the page with the row's entities", () => {
  lastEvent.remember({ platform: "splunk", container: "stash", fields: rows.splunk.notable_search_name });
  const el = field.render(ctxFor(PAGE));
  const l = lines(el);
  assert.equal(l.length, 1);
  const a = l[0].querySelector("a");
  assert.equal(dom.text(a), "Runbook for Disabled Kerberos Pre-Authentication Discovery With Get-ADUser →");
  assert.match(a.attributes.href, /^#\/runbook\/escu%3Aname%3A/);
  assert.match(a.attributes.href, /[?&]dest=WIN-DC01/);
  assert.equal(el.children.indexOf(l[0]), 1, "directly under the title block");
  lastEvent.clear();
});

test("a plain event row remembered draws no line, and an alert row draws none while the module is off", async () => {
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: rows.splunk.plain_event });
  assert.equal(lines(field.render(ctxFor(PAGE))).length, 0);
  lastEvent.remember({ platform: "splunk", container: "stash", fields: rows.splunk.notable_search_name });
  await modules.setEnabled("runbooks", false);
  assert.equal(lines(field.render(ctxFor(PAGE))).length, 0);
  await modules.setEnabled("runbooks", true);
  assert.equal(lines(field.render(ctxFor(PAGE))).length, 1);
  lastEvent.clear();
});

after(() => restore());
