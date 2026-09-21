// The runbook page's close step (app/views/runbook.js): with nothing
// current it says what to do first; with the primary entity held it names
// the investigation and its evidence and offers Close as benign, escalated
// and inconclusive; a click closes the current investigation with that
// outcome on the Hold, writes no pin and nothing to the held store; the
// Hold row's pin starts the investigation with this rule as its origin; a
// pivot copied from the drawer is recorded on the held entity under the
// pack edge's label.
import "./_splunk.js";
import "./_bundle.js";
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

const restore = dom.install();
globalThis.document.head = new dom.Node("head");
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
const store = await import("../app/lib/store.js");
const router = await import("../app/lib/router.js");
const modules = await import("../app/lib/modules.js");
const catalogue = await import("../app/lib/catalogue.js");
const runbooks = await import("../app/lib/runbooks.js");
const rbStore = await import("../app/lib/runbooks-store.js");
const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
const view = await import("../app/views/runbook.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.splunk.notable_search_name;
const ruleKey = runbooks.ruleKeyFor(row, "splunk");
const hash = runbooks.href(ruleKey, row);
const from = { platform: "splunk", container: "stash", scope: "main", column: "dest" };

function drawerStub() {
  const d = {};
  for (const m of ["setTitle", "setSpl", "setParams", "setHazards", "setState", "copy", "fill"]) d[m] = () => {};
  return d;
}

function open() {
  const state = router.parse(hash);
  let copyHandler = null;
  const ctx = { catalogue, route: state.route, params: state.params, drawer: drawerStub(), setUrl() {}, setDrawerParamHandler() {}, setDrawerCopyHandler: (fn) => { copyHandler = fn; }, navigate() {} };
  const el = view.render(ctx);
  document.body.appendChild(el);
  return { el, ctx, copy: (text) => copyHandler && copyHandler(text) };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const closeStep = (el) => el.querySelectorAll(".r-runbook__step").find((s) => s.dataset.kind === "close");
const outcomes = (el) => closeStep(el).querySelectorAll(".r-runbook__outcome");

beforeEach(async () => {
  document.body.replaceChildren();
  await store.remove(rbStore.KEY);
  await store.remove(notebook.KEY);
  rbStore._reset();
  await rbStore.load();
  await notebook.load({ force: true });
  investigation.clear();
});

test("with no current investigation the close step says to Hold or mark first and offers no outcome", async () => {
  const { el } = open();
  await el.ready;
  const step = closeStep(el);
  assert.ok(step, "the seed ends with a close step");
  assert.match(dom.text(step.querySelector(".r-runbook__closeline")), /^Nothing to close yet: Hold the entity or mark it benign above/);
  assert.deepEqual(outcomes(el), []);
});

test("the Hold row starts the investigation with this rule as its origin; the close step then names it, the Hold as evidence and the three outcomes", async () => {
  const { el } = open();
  await el.ready;
  const hold = el.querySelector(".reach-hold__btn");
  hold.click();
  for (let i = 0; i < 20 && !notebook.current(); i++) await settle();
  const inv = notebook.current();
  assert.ok(inv, "the Hold started an investigation");
  assert.equal(inv.origin.ruleKey, ruleKey.key);
  assert.equal(inv.origin.ruleName, ruleKey.name);
  assert.equal(inv.origin.platform, "splunk");
  assert.deepEqual(inv.entries.map((e) => [e.kind, e.field, e.value]), [["pin", "dest", "WIN-DC01"]]);
  await settle();
  const line = dom.text(closeStep(el).querySelector(".r-runbook__closeline"));
  assert.match(line, /^Closes Untitled investigation .* on the Hold of dest = WIN-DC01\.$/);
  assert.deepEqual(outcomes(el).map((b) => dom.text(b)), ["Close as benign", "Close as escalated", "Close as inconclusive"]);
});

test("Close as escalated closes the current investigation on the pin as evidence, adds no entry and leaves the held store alone; the page then shows nothing current", async () => {
  const pin = await notebook.record({ field: "dest", value: "WIN-DC01", reason: "the DC", from }, { origin: runbooks.originOf(ruleKey, "splunk") });
  const inv = notebook.current();
  const { el } = open();
  await el.ready;
  const held = { ...investigation.all() };
  outcomes(el).find((b) => b.dataset.outcome === "escalated").click();
  for (let i = 0; i < 20 && notebook.get(inv.id).status !== "closed"; i++) await settle();
  const closed = notebook.get(inv.id);
  assert.equal(closed.status, "closed");
  assert.equal(closed.outcome.result, "escalated");
  assert.deepEqual(closed.outcome.evidence, { kind: "hold", entry: pin.id, field: "dest", value: "WIN-DC01" });
  assert.equal(closed.outcome.reason, "the DC", "the pin's reason travels with the outcome");
  assert.equal(closed.entries.length, 1, "no entry was added by the close");
  assert.deepEqual(investigation.all(), held);
  assert.equal(notebook.currentId(), null);
  await settle();
  assert.match(dom.text(el.querySelector(".r-runbook__status")), /^Closed Untitled investigation .* as escalated\.$/);
  assert.match(dom.text(closeStep(el).querySelector(".r-runbook__closeline")), /^Nothing to close yet/);
});

test("a benign close takes the Mark benign entry as evidence over the pin; an investigation from another rule closes but says it will not count", async () => {
  const pin = await notebook.record({ field: "dest", value: "WIN-DC01", from }, { origin: { ruleKey: "escu:name:some other rule", ruleName: "Other", platform: "splunk" } });
  const mark = await notebook.add({ kind: "benign", on: pin.id, field: "dest", value: "WIN-DC01", reason: "the DC's own scan", from });
  const inv = notebook.current();
  const { el } = open();
  await el.ready;
  assert.match(dom.text(closeStep(el).querySelector(".r-runbook__closeline")), /on the Mark benign of dest = WIN-DC01 \(it started from another rule, so it does not count toward this runbook's draft\)\.$/);
  outcomes(el).find((b) => b.dataset.outcome === "benign").click();
  for (let i = 0; i < 20 && notebook.get(inv.id).status !== "closed"; i++) await settle();
  const closed = notebook.get(inv.id);
  assert.deepEqual(closed.outcome.evidence, { kind: "benign", entry: mark.id, field: "dest", value: "WIN-DC01" });
  assert.equal(closed.outcome.reason, "the DC's own scan");
  assert.equal(closed.origin.ruleKey, "escu:name:some other rule", "the origin is not rewritten by the close");
});

test("a pivot copied from the drawer lands on the held entity as an edge named by the pack edge; nothing is recorded for an entity not held", async () => {
  const { el, copy } = open();
  await el.ready;
  const step = el.querySelectorAll(".r-runbook__step").find((s) => s.dataset.stepId.startsWith("pivot-dest-"));
  step.querySelectorAll("button").find((b) => dom.text(b) === "Run").click(); // selects the step into the drawer
  copy("index=main sourcetype=stash dest=WIN-DC01");
  await settle();
  assert.equal(notebook.current(), null, "a copy holds nothing");
  const pin = await notebook.record({ field: "dest", value: "WIN-DC01", from });
  copy("index=main sourcetype=stash dest=WIN-DC01");
  for (let i = 0; i < 20 && notebook.current().entries.length < 2; i++) await settle();
  const edge = notebook.current().entries.find((e) => e.kind === "pivot");
  assert.ok(edge, "the pivot is in the notebook");
  assert.equal(edge.origin, pin.id);
  assert.equal(edge.name, "Sensors that reported under this hostname");
  assert.equal(edge.query.text, "index=main sourcetype=stash dest=WIN-DC01");
});

after(() => restore());
