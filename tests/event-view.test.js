// The event page on the panel: the title block first (anchor and CIM chips,
// the scope line naming the sourcetype, the field count and the handles,
// Sample search and Sourcetype as the actions), then Meaning with the
// anchor and PID callouts, CIM mapping and Fields (N) with the role groups
// folded; an event the catalogue lacks draws the unknown template.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { ENTITY_ORDER, matcher } from "../app/lib/headings.js";
import { termsFor } from "../app/lib/platform.js";
import { render } from "../app/views/event.js";

globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });

await catalogue.load();

const resolve = matcher(termsFor("splunk"));
const drawer = { fill() {}, fail() {} };

function ctx(params) {
  return { fields, catalogue, route: "event", params, drawer, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
}

function subsequence(ids, order) {
  let at = 0;
  for (const id of ids) {
    const i = order.indexOf(id, at);
    if (i < 0) return false;
    at = i + 1;
  }
  return true;
}

test("the title block comes first with the anchor and CIM chips, the scope line and the two actions; the h2s are Meaning, CIM mapping, Fields (N) in the entity order", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: "ProcessRollup2" }));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.equal(title.getAttribute("data-kind"), "event");
    assert.equal(dom.text(title.querySelector("h1")), "ProcessRollup2");
    assert.deepEqual(title.querySelector(".r-title__chips").querySelectorAll(".r-chip").map(dom.text), ["≡anchor event", "CIM normalized"]);
    const scope = dom.text(title.querySelector(".r-scope"));
    assert.match(scope, /^crowdstrike:events:sensor · \d+ fields · 2 handles$/);
    assert.equal(title.querySelector(".r-scope").querySelectorAll("span").find((n) => /handles/.test(dom.text(n))).getAttribute("title"), "TargetProcessId, ParentProcessId");
    const stLink = title.querySelector(".r-scope").querySelector("a");
    assert.equal(stLink.getAttribute("href"), "#/st/crowdstrike%3Aevents%3Asensor");
    // The name ellipsizes to keep the scope line to one at 320; the full name stays in title.
    assert.equal(stLink.getAttribute("class"), "r-scope__name");
    assert.equal(stLink.getAttribute("title"), "crowdstrike:events:sensor");
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Sample search", "Sourcetype →"]);
    const h2s = el.querySelectorAll("h2").map(dom.text);
    assert.deepEqual(h2s, ["Meaning", "CIM mapping", "Fields (58)"]);
    const ids = h2s.map((t) => resolve(t)).map((e) => e && e.id);
    assert.ok(ids.every(Boolean));
    assert.ok(subsequence(ids, ENTITY_ORDER));
    const meaning = el.querySelectorAll("section")[0];
    assert.deepEqual(meaning.querySelectorAll(".r-callout__label").map(dom.text), ["Anchor event", "Both PID spaces"], "the callouts live in Meaning, not the title block");
    assert.deepEqual(meaning.querySelectorAll("a").map((a) => a.getAttribute("href")), ["#/f/TargetProcessId?st=crowdstrike%3Aevents%3Asensor", "#/f/ParentProcessId?st=crowdstrike%3Aevents%3Asensor"], "the handles link from Meaning");
    assert.equal(title.querySelector(".r-title__callout"), null);
  } finally {
    restore();
  }
});

test("Fields (N) folds every role group closed on the panel, the role and its count in the summary, and every field links into its sourcetype", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: "DnsRequest" }));
    const groups = el.querySelectorAll(".r-rolelist__group");
    assert.ok(groups.length > 2);
    for (const g of groups) {
      assert.equal(g.tagName, "DETAILS");
      assert.equal(g.open, false);
      assert.match(dom.text(g.querySelector("summary")), /^[a-z_]+ \d+$/);
      for (const a of g.querySelectorAll("a")) assert.match(a.getAttribute("href"), /^#\/f\/[^?]+\?st=crowdstrike%3Aevents%3Asensor$/);
    }
    assert.equal(el.querySelectorAll("h2").some((n) => /Fields on this event/.test(dom.text(n))), false);
  } finally {
    restore();
  }
});

test("Sample search opens the paste fold under the title block and brings it under the frame; the fold stays closed on render", () => {
  const restore = dom.install();
  const savedWindow = globalThis.window;
  try {
    const scrolls = [];
    globalThis.window = { scrollY: 0, scrollTo: (x, y) => scrolls.push([x, y]) };
    const fold = document.createElement("details");
    fold.className = "r-paste";
    document.body.appendChild(fold);
    const el = render(ctx({ name: "ProcessRollup2" }));
    if (el.afterMount) el.afterMount();
    assert.equal(fold.open, false, "a render fills the fold and leaves it closed");
    const sample = el.querySelector(".r-actions").children.find((b) => dom.text(b) === "Sample search");
    dom.fire(sample, "click");
    assert.equal(fold.open, true);
    assert.equal(scrolls.length, 1);
  } finally {
    globalThis.window = savedWindow;
    restore();
  }
});

test("an event the catalogue lacks draws the unknown template: the name, the chip, the why in the scope line, Back, Nearest names and Catalogue", () => {
  const restore = dom.install();
  try {
    let backs = 0;
    const c = ctx({ name: "NoSuchEvent" });
    c.goBack = () => { backs += 1; };
    const el = render(c);
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.equal(dom.text(title.querySelector("h1")), "NoSuchEvent");
    assert.equal(dom.text(title.querySelector(".r-chip")), "not in the catalogue");
    assert.match(dom.text(title.querySelector(".r-scope")), /no event by that name/);
    const actions = title.querySelector(".r-actions").children;
    assert.deepEqual(actions.map(dom.text), ["Back", "Nearest names", "Catalogue"]);
    assert.equal(actions[1].getAttribute("href"), "#/unknown/NoSuchEvent");
    dom.fire(actions[0], "click");
    assert.equal(backs, 1, "Back is the router's back");
    assert.equal(el.querySelectorAll("h2").length, 0);
  } finally {
    restore();
  }
});
