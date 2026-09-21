// The draft beside the seed (app/views/runbook.js, runbooks-store
// draftFrom): nothing with no closed investigation of the rule, one line
// under three, and from three on a Draft from your investigations (N)
// section before Steps carrying the "from your last N investigations"
// label, the pivots with their counts, how they closed, the reasons, and
// Adopt; Adopt writes the missing steps and conditions into the stored
// runbook, the page redraws with them and the origin line says how many
// investigations were adopted; a close on the page refreshes the draft.
import "./_splunk.js";
import "./_bundle.js";
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";

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
const { heading } = await import("../app/lib/headings.js");
const view = await import("../app/views/runbook.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.splunk.notable_search_name;
const ruleKey = runbooks.ruleKeyFor(row, "splunk");
const hash = runbooks.href(ruleKey, row);
const from = { platform: "splunk", container: "stash", scope: "main", column: "dest" };
const TRIED = "Which users this address tried";
const resolve = matcher();
const h2s = (el) => el.querySelectorAll("h2").map((n) => dom.text(n));
const ids = (el) => h2s(el).map((t) => (resolve(t) || { id: `unregistered: ${t}` }).id);
const isSubsequence = (seq, master) => {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
};

function drawerStub() {
  const d = {};
  for (const m of ["setTitle", "setSpl", "setParams", "setHazards", "setState", "copy", "fill"]) d[m] = () => {};
  return d;
}

function open() {
  const state = router.parse(hash);
  const ctx = { catalogue, route: state.route, params: state.params, drawer: drawerStub(), setUrl() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {}, navigate() {} };
  const el = view.render(ctx);
  document.body.appendChild(el);
  return { el, ctx };
}

// One closed investigation of the rule with the named pivots on a held dest.
async function closedOne(i, pivots, outcome, reason) {
  const p = await notebook.record({ field: "dest", value: `H${i}`, from }, { origin: runbooks.originOf(ruleKey, "splunk") });
  for (const name of pivots) await notebook.pivot({ origin: p.id, query: { text: `q ${name} H${i}`, language: "SPL" }, name });
  await notebook.close(notebook.currentId(), { outcome, evidence: { entry: p.id }, reason });
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const draftSection = (el) => el.querySelector(".r-runbook__draft");

beforeEach(async () => {
  document.body.replaceChildren();
  await store.remove(rbStore.KEY);
  await store.remove(notebook.KEY);
  rbStore._reset();
  await rbStore.load();
  await notebook.load({ force: true });
});

test("no closed investigation of the rule: no draft section and no note; under three: one line and no h2", async () => {
  const a = open();
  await a.el.ready;
  assert.equal(draftSection(a.el), null);
  assert.equal(a.el.querySelector(".r-runbook__draftnote"), null);
  assert.deepEqual(ids(a.el), ["steps", "benign-conditions", "escalation-conditions"]);
  await closedOne(1, [TRIED], "benign", "the scanner");
  await closedOne(2, [TRIED], "benign", "the scanner");
  document.body.replaceChildren();
  const b = open();
  await b.el.ready;
  assert.equal(draftSection(b.el), null);
  assert.equal(dom.text(b.el.querySelector(".r-runbook__draftnote")), "2 closed investigations of this rule in the notebook; a draft runbook appears once 3 have closed.");
  assert.deepEqual(ids(b.el), ["steps", "benign-conditions", "escalation-conditions"]);
});

test("from three closed investigations the draft sits before Steps: the label, the pivots with counts, the modal outcome, the reasons and Adopt", async () => {
  await closedOne(1, [TRIED], "benign", "the scanner");
  await closedOne(2, [TRIED, "Sensors that reported under this hostname"], "benign", "the scanner");
  await closedOne(3, ["Sensors that reported under this hostname"], "escalated", "an unknown source");
  const { el } = open();
  await el.ready;
  const d = draftSection(el);
  assert.ok(d, "the draft section");
  assert.deepEqual(ids(el), ["draft-runbook", "steps", "benign-conditions", "escalation-conditions"]);
  assert.ok(isSubsequence(ids(el), TOOL_ORDER));
  assert.equal(dom.text(d.querySelector("h2")), heading("draft-runbook", 2));
  assert.equal(dom.text(d.querySelector(".r-chip")), "from your last 3 investigations");
  const items = d.querySelectorAll(".r-runbook__draftstep").map((li) => dom.text(li));
  assert.deepEqual(items, [`${TRIED} 2 of 3`, "Sensors that reported under this hostname 2 of 3, in the runbook already"]);
  assert.equal(dom.text(d.querySelector(".r-runbook__draftoutcome")), "Closed as benign in 2 of 3.");
  const conds = d.querySelectorAll(".r-runbook__draftcond").map((p) => dom.text(p));
  assert.deepEqual(conds, ["Benign when. the scanner (2)", "Escalate when. an unknown source (1)"]);
  const adopt = d.querySelector(".r-runbook__adopt");
  assert.equal(dom.text(adopt), "Adopt");
  assert.equal(adopt.getAttribute("disabled"), null, "Adopt is live");
  assert.equal(adopt.getAttribute("title"), "3 additions to the runbook");
  assert.equal(rbStore.get(ruleKey.key).origin, "seed", "nothing written by drawing the draft");
});

test("Adopt writes the missing step before the close step and the conditions onto the lists; the page redraws edited, says how many investigations it learned from, and Adopt has nothing left", async () => {
  await closedOne(1, [TRIED], "benign", "the scanner");
  await closedOne(2, [TRIED], "benign", "the scanner");
  await closedOne(3, [TRIED], "benign", "the scanner");
  const { el } = open();
  await el.ready;
  const before = rbStore.get(ruleKey.key).steps.length;
  draftSection(el).querySelector(".r-runbook__adopt").click();
  for (let i = 0; i < 20 && rbStore.get(ruleKey.key).origin !== "edited"; i++) await settle();
  await settle();
  const rb = rbStore.get(ruleKey.key);
  assert.equal(rb.origin, "edited");
  assert.equal(rb.learned_from.investigations, 3);
  assert.equal(rb.steps.length, before + 1);
  assert.equal(rb.steps[rb.steps.length - 1].kind, "close");
  assert.equal(rb.steps[rb.steps.length - 2].pivot.edge, "aad_ip_users");
  assert.deepEqual(rb.benign_when.map((c) => c.text).slice(-1), ["the scanner"]);
  assert.match(dom.text(el.querySelector(".r-runbook__status")), /^Adopted from your last 3 investigations: 2 additions\.$/);
  assert.match(dom.text(el.querySelector(".r-title__chips")), /edited by you/);
  assert.match(dom.text(el), /3 of your investigations adopted on /);
  const step = el.querySelectorAll(".r-runbook__step").find((s) => dom.text(s.querySelector(".r-step__title")).includes(TRIED));
  assert.ok(step, "the adopted step is on the page, bound from the row");
  assert.match(dom.text(step), /src = 10\.1\.2\.3/);
  const adopt = draftSection(el).querySelector(".r-runbook__adopt");
  assert.equal(adopt.getAttribute("disabled"), "", "nothing left to adopt");
  assert.deepEqual(draftSection(el).querySelectorAll(".r-runbook__draftstep--present").length, 1);
});

test("a close on the page brings the third investigation in and the draft appears without a reload", async () => {
  await closedOne(1, [TRIED], "benign", "the scanner");
  await closedOne(2, [TRIED], "benign", "the scanner");
  const p = await notebook.record({ field: "dest", value: "WIN-DC01", from }, { origin: runbooks.originOf(ruleKey, "splunk") });
  await notebook.pivot({ origin: p.id, query: { text: "q", language: "SPL" }, name: TRIED });
  const { el } = open();
  await el.ready;
  assert.equal(draftSection(el), null);
  const close = el.querySelectorAll(".r-runbook__step").find((s) => s.dataset.kind === "close");
  close.querySelectorAll(".r-runbook__outcome").find((b) => b.dataset.outcome === "benign").click();
  for (let i = 0; i < 30 && !draftSection(el); i++) await settle();
  const d = draftSection(el);
  assert.ok(d, "the draft appeared after the close");
  assert.equal(dom.text(d.querySelector(".r-chip")), "from your last 3 investigations");
  assert.equal(dom.text(d.querySelector(".r-runbook__draftoutcome")), "Closed as benign in 3 of 3.");
});

after(() => restore());
