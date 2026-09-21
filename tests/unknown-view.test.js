// The unknown template: the name, a chip saying what kind of absence this
// is, the why in the scope line, at most one callout, then Back, the
// alternative and Catalogue in the action row. The not-in-catalogue page
// draws it with Did you mean in the callout slot and Nearest names (N)
// under it; nothing about what the catalogue covers.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";
import { termsFor } from "../app/lib/platform.js";
import { render, absentPage, backAction } from "../app/views/unknown.js";

await catalogue.load();

const resolve = matcher(termsFor("splunk"));

function ctx(params, extra = {}) {
  return { fields, catalogue, route: "unknown", params, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, ...extra };
}

test("absentPage draws the title block with the chip, the why as the scope line, the callout in its slot and the actions last, then the sections", () => {
  const restore = dom.install();
  try {
    const note = document.createElement("div");
    note.className = "r-callout";
    const section = document.createElement("section");
    const el = absentPage({ name: "No such page", chip: "no such page", why: "no page at #/zzz", callout: note, actions: [backAction(() => {}), document.createElement("a")], sections: [section] });
    assert.ok(el.classList.contains("r-unknown"));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.equal(title.getAttribute("data-kind"), "page");
    assert.deepEqual(title.children.map((c) => `${c.tagName.toLowerCase()}.${c.className.split(" ")[0]}`), ["h1.r-title__h1", "div.r-title__chips", "p.r-scope", "div.r-title__callout", "div.r-actions"]);
    assert.equal(dom.text(title.querySelector(".r-chip")), "no such page");
    assert.equal(dom.text(title.querySelector(".r-scope")), "no page at #/zzz");
    assert.equal(el.children[1], section);
    const bare = absentPage({ name: "x", why: "y" });
    assert.equal(bare.querySelector(".r-title__chips"), null, "no chip row without a chip");
  } finally {
    restore();
  }
});

test("Back calls the router's back when given one and the browser's history otherwise", () => {
  const restore = dom.install();
  const saved = globalThis.window;
  try {
    let n = 0;
    dom.fire(backAction(() => { n += 1; }), "click");
    assert.equal(n, 1);
    let hist = 0;
    globalThis.window = { history: { back: () => { hist += 1; } } };
    dom.fire(backAction(), "click");
    assert.equal(hist, 1);
  } finally {
    globalThis.window = saved;
    restore();
  }
});

test("the not-in-catalogue page: the name, the chip, a one-line why, Did you mean in the callout slot, Back, Open the nearest name and Catalogue, then Nearest names (N)", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: "TargetProcesId" }));
    const title = el.children[0];
    assert.equal(dom.text(title.querySelector("h1")), "TargetProcesId");
    assert.equal(dom.text(title.querySelector(".r-chip")), "not in the catalogue");
    assert.match(dom.text(title.querySelector(".r-scope")), /^no field or event is called this among \d+ names on \d+ sourcetypes$/);
    assert.equal(dom.text(title.querySelector(".r-title__callout").querySelector(".r-callout__label")), "Did you mean");
    assert.match(dom.text(title.querySelector(".r-title__callout")), /TargetProcessId/);
    const actions = title.querySelector(".r-actions").children;
    assert.deepEqual(actions.map(dom.text), ["Back", "Open TargetProcessId", "Catalogue"]);
    assert.equal(actions[1].getAttribute("href"), "#/f/TargetProcessId");
    assert.equal(actions[2].getAttribute("href"), "#/catalogue");
    const h2s = el.querySelectorAll("h2").map(dom.text);
    assert.equal(h2s.length, 1);
    assert.match(h2s[0], /^Nearest names \(\d+\)$/);
    assert.equal(resolve(h2s[0]).id, "nearest-names");
    assert.ok(TOOL_ORDER.includes("nearest-names"));
    assert.equal(dom.text(el).includes("What this catalogue covers"), false);
    assert.equal(dom.text(el).includes("And what it does not"), false);
    assert.ok(el.querySelector("table"));
  } finally {
    restore();
  }
});

test("with nothing near the name the page draws no callout, Search as the alternative, the empty state under Nearest names (0) and no h2 of its own", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: "zzqqxxplomb" }));
    const title = el.children[0];
    assert.equal(title.querySelector(".r-title__callout"), null);
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Back", "Search", "Catalogue"]);
    assert.deepEqual(el.querySelectorAll("h2").map(dom.text), ["Nearest names (0)"]);
    const emptyEl = el.querySelector(".r-empty");
    assert.ok(emptyEl);
    assert.equal(emptyEl.querySelector("h2, h3"), null);
    assert.match(dom.text(emptyEl.querySelector("p")), /^Nothing is close to that/);
  } finally {
    restore();
  }
});

test("an event among the nearest names is a link only while the event route is mounted", () => {
  const restore = dom.install();
  try {
    const on = render(ctx({ name: "ProcessRollup" }));
    const eventLinks = on.querySelectorAll("a").filter((a) => (a.getAttribute("href") || "").startsWith("#/e/"));
    assert.ok(eventLinks.length > 0, "ProcessRollup2 is near ProcessRollup on Splunk");
    const off = render(ctx({ name: "ProcessRollup" }, { modules: { routes: () => ["catalogue", "sourcetype", "field", "value", "search", "unknown"] } }));
    assert.equal(off.querySelectorAll("a").filter((a) => (a.getAttribute("href") || "").startsWith("#/e/")).length, 0);
    assert.ok(dom.text(off).includes("ProcessRollup2"), "the name is still listed, as text");
  } finally {
    restore();
  }
});
