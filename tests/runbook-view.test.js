// The runbook page (app/views/runbook.js, #/runbook/<key>): the router
// parses the key, the registry mounts the route on both platforms, and the
// page walks the seeded steps in order with a checkbox each, the pivot
// steps bound from the URL's entity params and selected into the drawer,
// then Benign conditions and Escalation conditions; Hold and Mark benign
// on the row's primary entity are the title block's action row, every h2
// a registry entry. An
// unparseable key is the no-such-runbook page. Edit mode, the stored
// runbook and its share actions are tests/runbook-view-edit.test.js.
import "./_splunk.js";
import "./_bundle.js";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";

const restore = dom.install();
globalThis.document.head = new dom.Node("head");
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
const router = await import("../app/lib/router.js");
const modules = await import("../app/lib/modules.js");
const catalogue = await import("../app/lib/catalogue.js");
const runbooks = await import("../app/lib/runbooks.js");
const { heading } = await import("../app/lib/headings.js");
const view = await import("../app/views/runbook.js");
await catalogue.load();
await modules.hydrate();

const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
function drawerStub() {
  const calls = [];
  const d = {};
  for (const m of ["fill", "fail", "copy"]) d[m] = (...a) => calls.push([m, ...a]);
  d.calls = calls;
  return d;
}

function ctxFor(hash) {
  const state = router.parse(hash);
  const urls = [];
  return {
    ctx: { catalogue, route: state.route, params: state.params, drawer: drawerStub(), setUrl: (r, p) => urls.push(router.build(r, p)), setDrawerParamHandler() {}, navigate() {} },
    state,
    urls,
  };
}

test("the router parses #/runbook/<key> with the entity params, and the registry mounts the route on both platforms", () => {
  const row = rows.splunk.notable_search_name;
  const hash = runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row);
  const { route, params } = router.parse(hash);
  assert.equal(route, "runbook");
  assert.equal(params.key, "escu:name:disabled kerberos preauthentication discovery with getaduser");
  assert.equal(params.rule, "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser");
  assert.equal(params.dest, "WIN-DC01");
  assert.equal(router.build("runbook", { key: params.key }), "#/runbook/escu%3Aname%3Adisabled%20kerberos%20preauthentication%20discovery%20with%20getaduser");
  assert.equal(modules.routeOwner("runbook").id, "runbooks");
  assert.equal(modules.routeStatus("runbook", "splunk"), "on");
  assert.equal(modules.routeStatus("runbook", "sentinel"), "on");
});

test("the page walks the seeded steps in order, one checkbox each, with the pivot steps bound from the URL's entities", async () => {
  const row = rows.splunk.notable_search_name;
  const { ctx } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  const h1 = el.querySelector("h1");
  assert.equal(h1.attributes.title, "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser", "a name past two lines middle-ellipsizes with the full name in title");
  assert.match(dom.text(h1), /^Disabled Kerberos.*…/);
  await el.ready;
  const rb = await runbooks.seedFor(runbooks.ruleKeyFor(row, "splunk"), { row, platform: "splunk" });
  const h2s = el.querySelectorAll("h2").map((n) => dom.text(n));
  assert.deepEqual(h2s, [heading("steps", rb.steps.length), heading("benign-conditions", rb.benign_when.length), heading("escalation-conditions", rb.escalate_when.length)]);
  const steps = el.querySelectorAll(".r-runbook__step");
  assert.deepEqual(steps.map((s) => s.attributes["data-kind"]), rb.steps.map((s) => s.kind));
  assert.equal(el.querySelectorAll(".r-runbook__check").length, rb.steps.length, "a checkbox per step");
  assert.match(dom.text(el.querySelector(".r-title__chips")), /seeded from Splunk ESCU/);
  assert.match(dom.text(steps[0]), /Does the row match what the rule looks for\?/);
  const pivotSteps = steps.filter((s) => s.attributes["data-kind"] === "pivot");
  assert.ok(pivotSteps.length >= 3);
  assert.match(dom.text(pivotSteps[0]), /WIN-DC01/, "the entity value is in the step's question");
  assert.deepEqual(pivotSteps.map((s) => s.querySelectorAll("button").map((b) => dom.text(b))).flat(), pivotSteps.map(() => "Run"), "Splunk: a Run per pivot step");
  assert.match(dom.text(pivotSteps[0]), /aid bound from the row/);
});

test("Run selects the step's pivot into the drawer with SPL bound from the row and marks the step selected in the URL", async () => {
  const row = rows.splunk.notable_search_name;
  const { ctx, urls } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  await el.ready;
  const step = el.querySelectorAll(".r-runbook__step").find((s) => s.attributes["data-kind"] === "pivot");
  const run = step.querySelectorAll("button").find((b) => dom.text(b) === "Run");
  dom.fire(run, "click");
  const spl = ctx.drawer.calls.find((c) => c[0] === "fill");
  assert.ok(spl, "the drawer got the query");
  assert.match(spl[1].spl, /WIN-DC01/, "the entity value is in the query");
  assert.equal(ctx.drawer.calls.at(-1)[0], "fill");
  assert.ok(step.classList.contains("r-selected"));
  assert.match(urls.at(-1), /[?&]sel=pivot-dest-/);
});

test("Benign conditions and Escalation conditions list the conditions alone; Hold and Mark benign on the primary entity are the title block's action row, their bodies in the keep row under it", async () => {
  const row = rows.splunk.notable_search_name;
  const { ctx } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  await el.ready;
  const sections = el.querySelectorAll("section").filter((s) => s.querySelector("h2"));
  const benign = sections.find((s) => dom.text(s.querySelector("h2")) === heading("benign-conditions", 1));
  const escalate = sections.find((s) => dom.text(s.querySelector("h2")) === heading("escalation-conditions", 1));
  assert.match(dom.text(benign.querySelector("li")), /Administrators or power users/);
  assert.equal(benign.querySelector(".reach-benign"), null, "no Mark benign row under the conditions");
  assert.match(dom.text(escalate.querySelector("li")), /trigger is confirmed/);
  assert.equal(escalate.querySelector(".reach-hold"), null, "no Hold row under the conditions");
  const title = el.children[0];
  const actions = title.querySelector(".r-actions").children;
  assert.deepEqual(actions.slice(0, 2).map(dom.text), ["Hold", "Mark benign"]);
  assert.ok(actions[0].classList.contains("reach-hold__btn"));
  assert.ok(actions[1].classList.contains("reach-benign__btn"));
  const keep = title.querySelector(".r-title__keep");
  assert.ok(keep, "the keep row under the action row");
  assert.ok(keep.querySelector(".reach-hold") && keep.querySelector(".reach-benign"), "both bodies live there");
});

test("a Sigma-seeded runbook's seed line names the rule's own author, not a generic phrase", async () => {
  const row = rows.splunk.sigma_rule_id;
  const { ctx } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  await el.ready;
  const seedLine = el.querySelectorAll("p.r-secondary").map((n) => dom.text(n)).find((t) => /^Seeded from Sigma/.test(t));
  assert.ok(seedLine, "a seed line is drawn");
  assert.match(seedLine, /Austin Songer @austinsonger/, "the rule's own author, per the Detection Rule License's attribution requirement");
});

test("a rule no bundle carries is walked, not seeded: the head says so and Benign conditions is empty", async () => {
  const row = rows.splunk.renamed_search;
  const { ctx } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  await el.ready;
  assert.match(dom.text(el.querySelector(".r-title__chips")), /not in the bundled rules/);
  assert.match(dom.text(el.querySelector(".r-title__callout")), /Not seeded/, "the seed note is the callout slot");
  assert.match(dom.text(el), /No bundled rule index carries/);
  const benign = el.querySelectorAll("h2").find((n) => dom.text(n) === heading("benign-conditions", 0));
  assert.ok(benign, "Benign conditions (0)");
});

test("the title block is the view's first child before and after the seed: the rule's name, the seed chip and techniques, the scope line (runbook, the platform, the entities, the rule's page), then Hold, Mark benign, Run and Edit", async () => {
  const row = rows.splunk.notable_search_name;
  const { ctx } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const el = view.render(ctx);
  const before = el.children[0];
  assert.ok(before.classList.contains("r-title"), "the title block is first while the bundle is read");
  assert.equal(before.attributes["data-kind"], "runbook");
  assert.equal(dom.text(before.querySelector(".r-title__chips")), "reading the bundle");
  assert.equal(dom.text(before.querySelector(".r-scope")), "runbook · on Splunk");
  assert.equal(before.querySelector(".r-actions").children[0].attributes.disabled, "", "Run waits for the seed");
  assert.equal(before.querySelector(".r-actions").children[1].attributes.disabled, "", "so does Edit");
  await el.ready;
  const title = el.children[0];
  assert.notEqual(title, before, "the seeded block replaces the placeholder in place");
  assert.ok(title.classList.contains("r-title"));
  assert.equal(el.querySelectorAll(".r-title").length, 1);
  assert.equal(el.querySelectorAll("h1").length, 1);
  const chips = title.querySelector(".r-title__chips").querySelectorAll(".r-chip").map(dom.text);
  assert.match(chips[0], /seeded from Splunk ESCU/);
  assert.ok(chips.slice(1).every((c) => /T\d{4}/.test(c)), `techniques: ${chips.slice(1)}`);
  assert.match(dom.text(title.querySelector(".r-scope")), /^runbook · on Splunk · \d+ entit(y|ies) from the row · the rule's own page ↗$/);
  assert.match(title.querySelector(".r-scope").querySelector("a").attributes.href, /^https?:/, "the rule's own page is the scope line's link");
  assert.equal(title.querySelector(".r-title__callout"), null, "a seeded runbook has no callout");
  const actions = title.querySelector(".r-actions").children;
  assert.deepEqual(actions.map(dom.text), ["Hold", "Mark benign", "Run", "Edit"]);
  assert.equal("disabled" in actions[2].attributes, false);
  assert.equal("disabled" in actions[3].attributes, false, "Edit waits for the stored runbook");
  const h2s = el.querySelectorAll("h2").map(dom.text);
  assert.equal(h2s.length, 3, "the sections follow the title block");
});

test("Run in the title block selects the first pivot step into the drawer and opens the paste fold under the title block", async () => {
  const row = rows.splunk.notable_search_name;
  const { ctx, urls } = ctxFor(runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row));
  const savedWindow = globalThis.window;
  const scrolls = [];
  globalThis.window = { ...savedWindow, scrollY: 0, scrollTo: (x, y) => scrolls.push([x, y]) };
  const fold = document.createElement("details");
  fold.className = "r-paste";
  document.body.appendChild(fold);
  try {
    const el = view.render(ctx);
    await el.ready;
    dom.fire(el.children[0].querySelector(".r-actions").children.find((b) => dom.text(b) === "Run"), "click");
    const first = el.querySelectorAll(".r-runbook__step").find((s) => s.attributes["data-kind"] === "pivot");
    assert.ok(first.classList.contains("r-selected"));
    assert.match(urls.at(-1), /[?&]sel=pivot-/);
    assert.equal(ctx.drawer.calls.at(-1)[0], "fill");
    assert.equal(fold.open, true);
    assert.equal(scrolls.length, 1);
  } finally {
    fold.remove();
    globalThis.window = savedWindow;
  }
});

test("an unparseable key is the unknown template: No such runbook, the chip, the why in the scope line, Back and Start", () => {
  const { ctx } = ctxFor("#/runbook/whatever");
  const el = view.render(ctx);
  const title = el.children[0];
  assert.ok(title.classList.contains("r-title"));
  assert.equal(dom.text(el.querySelector("h1")), "No such runbook");
  assert.equal(dom.text(title.querySelector(".r-chip--state")), "no rule key");
  assert.match(dom.text(title.querySelector(".r-scope")), /^a runbook is keyed by the rule that fired/);
  assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Back", "Start"]);
});

after(() => restore());
