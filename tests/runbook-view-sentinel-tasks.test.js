// The runbook page on Sentinel (app/views/runbook.js): the stored seed
// binds its pivots from the row's Entities list on a later open, and the
// share row hands the steps to Sentinel as incident tasks, to the
// clipboard and as a file, in the automation rule action shape.
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
const tasks = await import("../app/lib/runbooks-tasks.js");
const view = await import("../app/views/runbook.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.sentinel.security_alert;
const ruleKey = runbooks.ruleKeyFor(row, "sentinel");

function open(hash) {
  const state = router.parse(hash);
  const d = {};
  for (const m of ["setTitle", "setSpl", "setParams", "setHazards", "setState", "copy"]) d[m] = () => {};
  const el = view.render({ catalogue, route: state.route, params: state.params, drawer: d, setUrl() {}, setDrawerParamHandler() {}, navigate() {} });
  document.body.appendChild(el);
  return el;
}

beforeEach(async () => {
  document.body.replaceChildren();
  await store.remove(rbStore.KEY);
  rbStore._reset();
  await rbStore.load();
});

test("a stored Sentinel seed binds its pivots from the Entities list of the row the page is opened with", async () => {
  const el = open(runbooks.href(ruleKey, row));
  await el.ready;
  const stored = rbStore.get(ruleKey.key);
  const host = stored.steps.find((s) => s.pivot && s.pivot.type === "hostname");
  assert.deepEqual(host.pivot.binds, { value: "Entities.HostName" });
  const entities = JSON.stringify([{ Type: "host", HostName: "DB02" }, { Type: "account", Name: "svc_backup" }]);
  const again = open(runbooks.href(ruleKey, { ...row, Entities: entities }));
  await again.ready;
  const step = again.querySelectorAll(".r-runbook__step").find((s) => s.attributes["data-step-id"] === host.id);
  assert.match(dom.text(step.querySelector(".r-runbook__bound")), /Entities\.HostName = DB02/);
  assert.deepEqual(step.querySelectorAll("button").map(dom.text), ["Copy KQL"]);
});

test("the share row: Copy as incident tasks writes the automation rule actions to the clipboard; Download tasks is beside it", async () => {
  const el = open(runbooks.href(ruleKey, row));
  await el.ready;
  const buttons = el.querySelector(".r-runbook__share").querySelectorAll("button");
  assert.deepEqual(buttons.map(dom.text), ["Copy as incident tasks", "Download tasks"]);
  const written = [];
  const saved = globalThis.navigator;
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => written.push(t) } }, configurable: true, writable: true });
  try {
    dom.fire(buttons[0], "click", { target: buttons[0] });
    await new Promise((r) => setTimeout(r, 0));
  } finally {
    Object.defineProperty(globalThis, "navigator", { value: saved, configurable: true, writable: true });
  }
  assert.equal(written.length, 1);
  const doc = JSON.parse(written[0]);
  assert.equal(doc.format, tasks.FORMAT);
  assert.equal(doc.rule.name, "GitLab - Brute-force Attempts");
  assert.deepEqual(doc.actions.map((a) => a.actionConfiguration.title), rbStore.get(ruleKey.key).steps.map((s) => s.question));
  assert.ok(doc.actions.every((a) => a.actionType === "AddIncidentTask"));
  assert.equal(dom.text(buttons[0]), "Copied");
});

// The Copied label goes back to its text on a timer; let it fire before the DOM is taken away.
after(async () => {
  await new Promise((r) => setTimeout(r, 1300));
  restore();
});
