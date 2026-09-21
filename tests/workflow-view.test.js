// The workflow page on the panel: the title block first (the title, the
// kicker chip, the scope line naming the sourcetype the workflow starts
// from, When you are here in the callout slot, Run and Copy SPL as the
// actions), then the sections; a workflow no pack knows draws the unknown
// template.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { render } from "../app/views/workflow.js";

globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });

await catalogue.load();

function drawerStub() {
  const calls = [];
  const d = { calls };
  for (const m of ["fill", "fail", "copy"]) d[m] = (...a) => calls.push([m, ...a]);
  return d;
}

function ctx(params) {
  return { fields, catalogue, route: "workflow", params, drawer: drawerStub(), navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

test("the title block comes first with the kicker chip, the scope line linking the sourcetype, the callout and Run, Copy SPL; the kicker is not in an h1", () => {
  const restore = dom.install();
  try {
    const c = ctx({ id: "ioc", value: "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4" });
    const el = render(c);
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"), "the title block is the view's first child");
    assert.equal(title.getAttribute("data-kind"), "workflow");
    assert.equal(el.querySelectorAll("h1").length, 1);
    assert.match(dom.text(title.querySelector("h1")), /^I have an observable/);
    assert.deepEqual(title.querySelector(".r-title__chips").querySelectorAll(".r-chip").map(dom.text), ["⤳hash, IP, domain, filename → the process that produced it"]);
    const scope = title.querySelector(".r-scope");
    assert.equal(dom.text(scope), "on crowdstrike:events:sensor");
    assert.equal(scope.querySelector("a").getAttribute("href"), "#/st/crowdstrike%3Aevents%3Asensor");
    assert.equal(dom.text(title.querySelector(".r-title__callout").querySelector(".r-callout__label")), "When you are here");
    const actions = title.querySelector(".r-actions").children;
    assert.deepEqual(actions.map(dom.text), ["Run", "Copy SPL"]);
    dom.fire(actions[1], "click");
    assert.deepEqual(c.drawer.calls, [["copy"]], "Copy SPL takes the drawer's text");
    assert.equal(el.querySelector(".r-hold__head"), null);
  } finally {
    restore();
  }
});

test("a workflow reachable from more than one sourcetype names the first and counts the rest; one opened on a sourcetype names that one", () => {
  const restore = dom.install();
  try {
    const host = render(ctx({ id: "host" })).children[0];
    assert.equal(dom.text(host.querySelector(".r-scope")), "on crowdstrike:events:sensor · also on 1 more");
    const pid = render(ctx({ id: "pid", st: "crowdstrike:events:sensor" })).children[0];
    assert.equal(dom.text(pid.querySelector(".r-scope")), "on crowdstrike:events:sensor");
  } finally {
    restore();
  }
});

test("Run opens the paste fold under the title block and brings it under the frame; the render leaves it closed", () => {
  const restore = dom.install();
  const savedWindow = globalThis.window;
  try {
    const scrolls = [];
    globalThis.window = { scrollY: 0, scrollTo: (x, y) => scrolls.push([x, y]) };
    const fold = document.createElement("details");
    fold.className = "r-paste";
    document.body.appendChild(fold);
    const el = render(ctx({ id: "pid" }));
    if (el.afterMount) el.afterMount();
    assert.equal(fold.open, false, "a render fills the fold and leaves it closed");
    dom.fire(el.children[0].querySelector(".r-actions").children[0], "click");
    assert.equal(fold.open, true);
    assert.equal(scrolls.length, 1);
  } finally {
    globalThis.window = savedWindow;
    restore();
  }
});

test("a workflow no pack knows draws the unknown template: the id, the chip, the why in the scope line, Back and Start, the workflows listed", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ id: "nope" }));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.equal(dom.text(title.querySelector("h1")), "nope");
    assert.equal(dom.text(title.querySelector(".r-chip--state")), "no such workflow");
    assert.match(dom.text(title.querySelector(".r-scope")), /^\d+ workflows across the loaded packs$/);
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Back", "Start"]);
    assert.ok(el.querySelectorAll("a").some((a) => a.getAttribute("href") === "#/w/ioc"));
    assert.equal(el.querySelectorAll("h2").length, 0);
  } finally {
    restore();
  }
});
