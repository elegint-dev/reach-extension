// The runbook page's close step on Sentinel (app/views/runbook.js): the
// Hold row holds the CompromisedEntity under the Entities field carrying
// it, so a KQL pivot copied from the drawer on a pack pivot step lands on
// that pin and the investigation carries the Hold and the pivot; the copy
// itself holds nothing.
import "./_sentinel.js";
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
const row = rows.sentinel.security_alert;
const hash = runbooks.href(runbooks.ruleKeyFor(row, "sentinel"), row);

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
  return { el, copy: (text) => copyHandler && copyHandler(text) };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(async () => {
  document.body.replaceChildren();
  await store.remove(rbStore.KEY);
  await store.remove(notebook.KEY);
  rbStore._reset();
  await rbStore.load();
  await notebook.load({ force: true });
  investigation.clear();
});

test("the Hold row holds the CompromisedEntity under its Entities field; Copy KQL on a pack pivot step bound from that field then records the pivot on the Hold, so the investigation carries two entries", async () => {
  const { el, copy } = open();
  await el.ready;
  const step = el.querySelectorAll(".r-runbook__step").find((s) => s.dataset.stepId.startsWith("pivot-") && /Entities\.Address = 10\.1\.2\.3/.test(dom.text(s)));
  assert.ok(step, "a pack pivot step bound from Entities.Address");
  step.querySelectorAll("button").find((b) => dom.text(b) === "Copy KQL").click();
  copy("SecurityAlert | where Entities has '10.1.2.3'");
  await settle();
  assert.equal(notebook.current(), null, "a copy holds nothing");
  el.querySelector(".reach-hold__btn").click();
  for (let i = 0; i < 20 && !notebook.current(); i++) await settle();
  const pin = notebook.current().entries.find((e) => e.kind === "pin");
  assert.equal(pin.field, "Entities.Address");
  assert.equal(pin.value, "10.1.2.3");
  const held = { ...investigation.all() };
  copy("SecurityAlert | where Entities has '10.1.2.3'");
  for (let i = 0; i < 20 && notebook.current().entries.length < 2; i++) await settle();
  assert.deepEqual(investigation.all(), held, "the copy leaves the held store alone");
  const entries = notebook.current().entries;
  assert.equal(entries.length, 2, "the Hold and the pivot");
  const edge = entries.find((e) => e.kind === "pivot");
  assert.equal(edge.origin, pin.id);
  assert.equal(edge.query.language, "KQL");
  assert.equal(edge.query.text, "SecurityAlert | where Entities has '10.1.2.3'");
  assert.deepEqual(entries.filter((e) => e.kind === "pin").length, 1, "the copy wrote no second pin");
});

after(() => restore());
