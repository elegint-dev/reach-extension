// A hunt has no entry to start from, so the sourcetype page it runs on is
// its way in: forSourcetype lists it on its containers, apart from the
// value pivots, and the page draws it under its own line. A value pivot
// is still listed only where one of its entries is.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import * as workflows from "../app/lib/workflows.js";
import { render } from "../app/views/sourcetype.js";

globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });
await catalogue.load();

const ST = "crowdstrike:events:sensor";

function ctx(params) {
  return { fields, catalogue, route: "sourcetype", params, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules };
}

test("forSourcetype lists the hunt on the container its searches run on, after the value pivots, and nowhere else", () => {
  const rows = workflows.forSourcetype(ST);
  assert.deepEqual(rows.map((w) => w.id), ["pid", "process", "host", "ioc", "hunt_mac_signing"]);
  assert.deepEqual(rows.map((w) => w.hunt), [false, false, false, false, true]);
  assert.ok(workflows.forSourcetype("aws:cloudtrail").every((w) => w.id !== "hunt_mac_signing"));
  assert.ok(workflows.forSourcetype("aws:cloudtrail").every((w) => w.hunt === false));
});

test("a value pivot is listed on its entries' sourcetypes, not on every container it lands on", () => {
  const ct = workflows.list().find((w) => w.id === "ct_principal");
  assert.ok(ct.containers.length, "the pivot resolves onto a container");
  assert.equal(ct.hunt, false);
  for (const st of ct.containers) if (!ct.entries.some((e) => e.sourcetype === st)) assert.ok(workflows.forSourcetype(st).every((w) => w.id !== "ct_principal"), st);
});

test("the sourcetype page draws the hunt under its own line, after the pivots, linking to the workflow route", () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: ST }));
    const section = el.querySelector(".r-workflows--hunts").parentNode;
    assert.equal(dom.text(section.querySelector("h2")), "Workflows");
    const pivots = section.querySelector(".r-workflows--pivots").querySelectorAll("a").map((a) => a.getAttribute("href"));
    assert.deepEqual(pivots, ["#/w/pid", "#/w/process", "#/w/host", "#/w/ioc"]);
    const hunts = section.querySelector(".r-workflows--hunts").querySelectorAll("a").map((a) => a.getAttribute("href"));
    assert.deepEqual(hunts, ["#/w/hunt_mac_signing"]);
    const lines = section.querySelectorAll("p").map(dom.text);
    assert.match(lines[0], /^Start from a value you are holding/);
    assert.match(lines[1], /^A hunt starts from no value/);
    assert.ok(section.children.indexOf(section.querySelector(".r-workflows--pivots")) < section.children.indexOf(section.querySelector(".r-workflows--hunts")));
  } finally {
    restore();
  }
});
