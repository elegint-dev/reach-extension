// The runbook page's stored runbook and edit mode (app/views/runbook.js,
// #/runbook/<key>?edit=1): the first open writes the seed to the store and
// the page reads the store after, the chip says seeded or edited by you,
// Edit and Done move through the URL, in edit mode every step is a
// question input with a note, a pivot select and move and remove
// controls, a change on any of them is one write the page redraws from,
// the condition lists and the notes are textareas, Add step appends,
// Reset to seed asks once and then puts the seed back, and the share row
// carries Export runbook when the share module is on.
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
const view = await import("../app/views/runbook.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const row = rows.splunk.notable_search_name;
const ruleKey = runbooks.ruleKeyFor(row, "splunk");
const hash = runbooks.href(ruleKey, row);

function drawerStub() {
  const d = {};
  for (const m of ["setTitle", "setSpl", "setParams", "setHazards", "setState", "copy"]) d[m] = () => {};
  return d;
}

function open(extra = {}) {
  const state = router.parse(hash);
  const navs = [];
  const ctx = { catalogue, route: state.route, params: { ...state.params, ...extra }, drawer: drawerStub(), setUrl() {}, setDrawerParamHandler() {}, navigate: (r, p) => navs.push([r, p]) };
  const el = view.render(ctx);
  document.body.appendChild(el);
  return { el, ctx, navs };
}

// The store's change event redraws the page; the redraw is synchronous
// once the write has resolved.
const settle = () => new Promise((r) => setTimeout(r, 0));

beforeEach(async () => {
  document.body.replaceChildren();
  await store.remove(rbStore.KEY);
  rbStore._reset();
  await rbStore.load();
});

test("the first open writes the seed to the store; the page reads the stored runbook after, so an edit shows on the next open", async () => {
  assert.equal(rbStore.has(ruleKey.key), false);
  const { el } = open();
  await el.ready;
  assert.equal(rbStore.has(ruleKey.key), true, "seeded on first open");
  assert.equal(rbStore.get(ruleKey.key).origin, "seed");
  const chips = el.querySelector(".r-title__chips").querySelectorAll(".r-chip").map(dom.text);
  assert.match(chips[0], /seeded from Splunk ESCU/);
  assert.match(dom.text(el), /Edit makes it yours/);
  await rbStore.update(ruleKey.key, { notes: "Check with the AD team first." });
  const { el: again } = open();
  await again.ready;
  const chips2 = again.querySelector(".r-title__chips").querySelectorAll(".r-chip").map(dom.text);
  assert.deepEqual(chips2.slice(0, 2), ["edited by you", "seeded from Splunk ESCU"]);
  assert.match(dom.text(again.querySelector(".r-runbook__notes")), /^Notes\. Check with the AD team first\.$/);
  assert.match(dom.text(again), /Edited by you on .*; seeded from Splunk ESCU on the first open/);
  assert.equal(again.querySelectorAll(".r-runbook__step").length, rbStore.get(ruleKey.key).steps.length);
});

test("a stored pivot step binds from the row the page was opened with, not the row it was seeded from", async () => {
  const { el } = open();
  await el.ready;
  const { el: other } = open({ dest: "SRV-02", aid: "" });
  await other.ready;
  const host = other.querySelectorAll(".r-runbook__step").find((s) => /Sensors that reported under this hostname/.test(dom.text(s)));
  assert.match(dom.text(host.querySelector(".r-runbook__bound")), /dest = SRV-02/);
  assert.match(dom.text(host.querySelector(".r-runbook__bound")), /needs aid from the row/);
});

test("Edit and Done move through the URL: Edit navigates with edit=1, Done drops it", async () => {
  const { el, navs } = open();
  await el.ready;
  const actions = el.querySelector(".r-actions").children;
  dom.fire(actions.find((b) => dom.text(b) === "Edit"), "click");
  assert.equal(navs.at(-1)[0], "runbook");
  assert.equal(navs.at(-1)[1].edit, "1");
  assert.equal(navs.at(-1)[1].key, ruleKey.key);
  const { el: editing, navs: navs2 } = open({ edit: "1" });
  await editing.ready;
  const acts = editing.querySelector(".r-actions").children.map(dom.text);
  assert.deepEqual(acts, ["Done", "Reset to seed"]);
  assert.match(dom.text(editing.querySelector(".r-scope")), /· editing$/);
  dom.fire(editing.querySelector(".r-actions").children[0], "click");
  assert.equal(navs2.at(-1)[1].edit, undefined);
});

test("edit mode: every step is a question input with a note, a pivot select and move and remove controls; a change is one write the page redraws from", async () => {
  const { el } = open({ edit: "1" });
  await el.ready;
  const steps = el.querySelectorAll(".r-runbook__step--edit");
  const n = rbStore.get(ruleKey.key).steps.length;
  assert.equal(steps.length, n);
  assert.equal(el.querySelectorAll(".r-runbook__check").length, 0, "no checkboxes while editing");
  const first = steps[0];
  const q = first.querySelector(".r-runbook__q");
  assert.equal(q.value, "Does the row match what the rule looks for?");
  assert.equal(first.querySelector(".r-runbook__ta").attributes["aria-label"], "Step 1 note");
  const sel = first.querySelector(".r-runbook__pivot");
  assert.equal(sel.children[0].value, "");
  assert.ok(sel.children.length > 5, "every pack pivot by entity type is offered");
  assert.equal(first.querySelectorAll("button").map(dom.text).join(" "), "↑ ↓ Remove");
  assert.equal("disabled" in first.querySelectorAll("button")[0].attributes, true, "the first step cannot move up");

  q.value = "Is this the rule's own trigger?";
  dom.fire(q, "change");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).steps[0].question, "Is this the rule's own trigger?");
  assert.equal(rbStore.get(ruleKey.key).origin, "edited");
  const redrawn = el.querySelectorAll(".r-runbook__step--edit")[0].querySelector(".r-runbook__q");
  assert.equal(redrawn.value, "Is this the rule's own trigger?", "the page redrew from the store");
  assert.equal(dom.text(el.querySelector(".r-title__chips").querySelectorAll(".r-chip")[0]), "edited by you");

  const why = el.querySelectorAll(".r-runbook__step--edit")[0].querySelector(".r-runbook__ta");
  why.value = "Read the SPL once.";
  dom.fire(why, "change");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).steps[0].why, "Read the SPL once.");

  const pick = el.querySelectorAll(".r-runbook__step--edit")[0].querySelector(".r-runbook__pivot");
  const option = pick.children.find((o) => /user_name/.test(dom.text(o)));
  pick.value = option.value;
  dom.fire(pick, "change");
  await settle();
  const s0 = rbStore.get(ruleKey.key).steps[0];
  assert.equal(s0.kind, "pivot");
  assert.equal(`${s0.pivot.packId}/${s0.pivot.edge}`, option.value);
  assert.match(dom.text(el.querySelectorAll(".r-runbook__step--edit")[0].querySelector(".r-runbook__bound")), /user = jdoe/);

  const down = el.querySelectorAll(".r-runbook__step--edit")[0].querySelectorAll("button")[1];
  dom.fire(down, "click");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).steps[1].id, "confirm");
  assert.equal(el.querySelectorAll(".r-runbook__step--edit")[1].attributes["data-step-id"], "confirm");

  dom.fire(el.querySelectorAll(".r-runbook__step--edit")[1].querySelectorAll("button")[2], "click");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).steps.length, n - 1);
  assert.equal(rbStore.get(ruleKey.key).steps.some((s) => s.id === "confirm"), false);
  assert.equal(el.querySelectorAll(".r-runbook__step--edit").length, n - 1);
});

test("edit mode: Add step appends a step, the condition lists and the notes are textareas written on change", async () => {
  const { el } = open({ edit: "1" });
  await el.ready;
  const n = rbStore.get(ruleKey.key).steps.length;
  dom.fire(el.querySelector(".r-runbook__add"), "click");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).steps.length, n + 1);
  assert.equal(rbStore.get(ruleKey.key).steps.at(-1).question, "New step");
  assert.equal(el.querySelectorAll(".r-runbook__step--edit").at(-1).querySelector(".r-runbook__q").value, "New step");

  const benign = el.querySelectorAll("textarea").find((t) => t.attributes["aria-label"] === "Benign conditions");
  assert.ok(benign.value.length > 0, "the seed's false positives are the lines");
  benign.value = "Tier-0 admins from the jump host\n\n  Scheduled AD audit  ";
  dom.fire(benign, "change");
  await settle();
  assert.deepEqual(rbStore.get(ruleKey.key).benign_when, [{ text: "Tier-0 admins from the jump host" }, { text: "Scheduled AD audit" }]);
  assert.match(dom.text(el.querySelectorAll("h2")[1]), /Benign conditions \(2\)/);

  const esc = el.querySelectorAll("textarea").find((t) => t.attributes["aria-label"] === "Escalation conditions");
  esc.value = "Any other host";
  dom.fire(esc, "change");
  await settle();
  assert.deepEqual(rbStore.get(ruleKey.key).escalate_when, [{ text: "Any other host" }]);

  const notes = el.querySelectorAll("textarea").find((t) => t.attributes["aria-label"] === "Notes");
  notes.value = "Ask IAM first.";
  dom.fire(notes, "change");
  await settle();
  assert.equal(rbStore.get(ruleKey.key).notes, "Ask IAM first.");
});

test("Reset to seed asks once, then puts the bundle's runbook back and the chip reads seeded again", async () => {
  const { el } = open({ edit: "1" });
  await el.ready;
  await rbStore.update(ruleKey.key, { notes: "gone" });
  await rbStore.addStep(ruleKey.key, { question: "extra" });
  await settle();
  assert.equal(dom.text(el.querySelector(".r-title__chips").querySelectorAll(".r-chip")[0]), "edited by you");
  const reset = el.querySelector(".r-runbook__reset");
  dom.fire(reset, "click");
  assert.equal(dom.text(reset), "Reset: sure?");
  assert.equal(rbStore.get(ruleKey.key).notes, "gone", "the first click only arms");
  dom.fire(reset, "click");
  await new Promise((r) => setTimeout(r, 50));
  const back = rbStore.get(ruleKey.key);
  assert.equal(back.origin, "seed");
  assert.equal(back.notes, "");
  assert.equal(back.steps.some((s) => s.question === "extra"), false);
  assert.match(dom.text(el.querySelector(".r-title__chips").querySelectorAll(".r-chip")[0]), /seeded from Splunk ESCU/);
});

test("an edit after arming Reset to seed disarms it: the redrawn button asks again before discarding", async () => {
  const { el } = open({ edit: "1" });
  await el.ready;
  await rbStore.update(ruleKey.key, { notes: "keep" });
  await settle();
  dom.fire(el.querySelector(".r-runbook__reset"), "click");
  assert.equal(dom.text(el.querySelector(".r-runbook__reset")), "Reset: sure?");
  await rbStore.addStep(ruleKey.key, { question: "after arming" });
  await settle();
  const reset = el.querySelector(".r-runbook__reset");
  assert.equal(dom.text(reset), "Reset to seed", "the redraw draws a disarmed button");
  dom.fire(reset, "click");
  await new Promise((r) => setTimeout(r, 50));
  const kept = rbStore.get(ruleKey.key);
  assert.equal(kept.notes, "keep", "one click after the edit only arms again");
  assert.ok(kept.steps.some((s) => s.question === "after arming"));
  assert.equal(dom.text(reset), "Reset: sure?");
  dom.fire(reset, "click");
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(rbStore.get(ruleKey.key).origin, "seed", "the second click resets");
});

test("the share row carries Export runbook only while the share module is on; nothing else on Splunk", async () => {
  const { el } = open();
  await el.ready;
  assert.equal(el.querySelector(".r-runbook__share"), null, "share is off by default");
  await store.set(modules.KEY, { enabled: { share: true } });
  await modules.hydrate();
  try {
    const { el: on } = open();
    await on.ready;
    assert.deepEqual(on.querySelector(".r-runbook__share").querySelectorAll("button").map(dom.text), ["Export runbook"]);
  } finally {
    await store.remove(modules.KEY);
    modules.reset();
    await modules.hydrate();
  }
});

after(() => restore());
