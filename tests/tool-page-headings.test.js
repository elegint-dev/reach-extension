// Every tool page draws the title block as its first child and every h2 it
// draws is a registry entry, in the tool master's order (C1, C3, C4). The
// workflow and runbook pages are held to the same master. Splunk words; the
// Sentinel views are held in tool-page-headings-sentinel.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as dom from "./_dom.js";
import * as fields from "../app/lib/pack-fields.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as search from "../app/lib/search.js";
import * as modules from "../app/lib/modules.js";
import * as runbooks from "../app/lib/runbooks.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
await catalogue.load();
await modules.hydrate();
const views = {
  catalogue: await import("../app/views/catalogue.js"),
  packs: await import("../app/views/packs.js"),
  search: await import("../app/views/search.js"),
  share: await import("../app/views/share.js"),
  discover: await import("../app/views/discover.js"),
  start: await import("../app/views/start.js"),
  unknown: await import("../app/views/unknown.js"),
  workflow: await import("../app/views/workflow.js"),
  runbook: await import("../app/views/runbook.js"),
};
const resolve = matcher();
const drawer = () => Object.fromEntries(["fill", "fail", "copy"].map((m) => [m, () => {}]));
const ctx = { fields, catalogue, search, modules, params: {}, cards: [], drawer: drawer(), setUrl() {}, navigate() {}, back() {}, goBack() {}, openSettings() {}, focusSearch() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
const alertRows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
const runbookParams = (row) => {
  const hash = runbooks.href(runbooks.ruleKeyFor(row, "splunk"), row);
  const q = new URLSearchParams(hash.split("?")[1] || "");
  return { key: decodeURIComponent(hash.slice("#/runbook/".length).split("?")[0]), ...Object.fromEntries(q) };
};
// The runbook's sections arrive with the seed: wait for the first h2, up to a second.
async function seeded(el) {
  for (let i = 0; i < 50 && !el.querySelector("h2"); i += 1) await new Promise((r) => setTimeout(r, 20));
}
const ROUTES = [
  ["catalogue", {}],
  ["packs", {}],
  ["search", { q: "Process" }],
  ["search", { q: "zzz-nothing-like-this" }],
  ["search", {}],
  ["share", {}],
  ["discover", {}],
  ["start", {}],
  ["unknown", { name: "NoSuchField" }],
  ["unknown", { name: "ProcesRollup2" }],
  ["workflow", { id: "ioc", value: "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4" }],
  ["workflow", { id: "pid", st: "crowdstrike:events:sensor" }],
  ["workflow", { id: "host" }],
  ["workflow", { id: "nope" }],
  ["runbook", runbookParams(alertRows.splunk.notable_search_name)],
  ["runbook", runbookParams(alertRows.splunk.renamed_search)],
  ["runbook", { key: "whatever" }],
];
// The tool template defines no action row for the packs and search pages.
const NO_ACTIONS = new Set(["packs", "search"]);

function isSubsequence(seq, master) {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
}

for (const [route, params] of ROUTES) {
  test(`${route} ${JSON.stringify(params)}: title block first, registry h2s in the tool master's order, no h2 inside an empty state or a drawer`, async () => {
    const el = views[route].render({ ...ctx, params, drawer: drawer() });
    if (el.afterMount) el.afterMount();
    if (route === "runbook" && params.rule) await seeded(el);
    const first = el.children.find((c) => c.tagName !== "#TEXT");
    assert.ok(first && first.classList.contains("r-title"), `${route}: the title block is the view's first child`);
    assert.ok(first.querySelector("h1"), "an h1");
    assert.ok(first.querySelector(".r-scope"), "a scope line");
    if (!NO_ACTIONS.has(route)) assert.ok(first.querySelector(".r-actions"), "an action row");
    const h2s = el.querySelectorAll("h2");
    const ids = h2s.map((n) => (resolve(dom.text(n)) || { id: `unregistered: ${dom.text(n)}` }).id);
    assert.ok(ids.every((id) => !id.startsWith("unregistered")), ids.join(", "));
    assert.ok(isSubsequence(ids, TOOL_ORDER), `${ids} is not a subsequence of the tool master`);
    for (const n of h2s) assert.equal(n.closest(".r-empty, .r-drawer, .r-cov__feed"), null, `h2 "${dom.text(n)}" inside an excluded block`);
    assert.equal(el.querySelectorAll(".r-empty").some((e) => e.querySelector("h2")), false);
    // A fold's summary directly under a section is a heading too (C3).
    for (const d of el.querySelectorAll("details")) {
      const sum = d.children.find((c) => c.tagName === "SUMMARY");
      if (!sum || !d.parentNode || !d.parentNode.classList.contains("r-section")) continue;
      assert.ok(resolve(dom.text(sum)), `${route}: summary "${dom.text(sum)}" is not a registry entry`);
    }
  });
}

test("the workflow page draws Inputs (N), Searches (N), Expected results, Disambiguation and Troubleshooting from the registry, the searches counted from the results on offer", () => {
  const el = views.workflow.render({ ...ctx, params: { id: "pid", st: "crowdstrike:events:sensor" }, drawer: drawer() });
  if (el.afterMount) el.afterMount();
  const h2s = el.querySelectorAll("h2").map((n) => dom.text(n));
  assert.match(h2s[0], /^Inputs \(\d+\)$/);
  assert.match(h2s[1], /^Searches \([1-9]\d*\)$/, "the results are counted once the page mounts");
  assert.deepEqual(h2s.slice(2), ["Expected results", "Disambiguation", "Troubleshooting"]);
  assert.equal(el.querySelectorAll("summary").length, 0, "no question folds on the page");
});

test("the unknown page draws the chip, the one-line why and Back, the alternative, Catalogue; the two catalogue prose sections are gone, not renamed", () => {
  const el = views.unknown.render({ ...ctx, params: { name: "ProcesRollup2" } });
  const first = el.children[0];
  assert.equal(dom.text(first.querySelector("h1")), "ProcesRollup2");
  assert.equal(dom.text(first.querySelector(".r-chip--state")), "not in the catalogue");
  assert.equal(first.querySelectorAll(".r-scope").length, 1);
  const actions = first.querySelector(".r-actions").children.map((n) => dom.text(n));
  assert.equal(actions[0], "Back");
  assert.match(actions[1], /^Open ProcessRollup2$/, "the alternative is the nearest name");
  assert.equal(actions[2], "Catalogue");
  assert.ok(first.querySelector(".r-title__callout"), "Did you mean sits in the callout slot");
  const text = dom.text(el);
  assert.equal(text.includes("What this catalogue covers"), false);
  assert.equal(text.includes("And what it does not"), false);
  assert.equal(el.querySelectorAll("h3").length, 0);
  assert.deepEqual(el.querySelectorAll("h2").map((n) => dom.text(n).replace(/\d+/, "N")), ["Nearest names (N)"]);
});

test("the unknown page with nothing near offers Search as the alternative and no heading inside the empty state", () => {
  const el = views.unknown.render({ ...ctx, params: { name: "zzzzqqqq" } });
  const actions = el.children[0].querySelector(".r-actions").children.map((n) => dom.text(n));
  assert.deepEqual(actions, ["Back", "Search", "Catalogue"]);
  assert.equal(el.children[0].querySelector(".r-title__callout"), null);
  const emptyEl = el.querySelector(".r-empty");
  assert.ok(emptyEl);
  assert.equal(emptyEl.querySelector("h2, h3"), null);
  assert.ok(modules.routes().includes("workflow"), "the workflow route mounts on Splunk");
  assert.ok(emptyEl.querySelectorAll("a").some((a) => a.getAttribute("href") === "#/w/ioc"), "the paste-a-value move links the ioc workflow");
});

test("a long nearest name is middle-ellipsized on the alternative button with the full name in title", () => {
  const el = views.unknown.render({ ...ctx, params: { name: "AccessoryConnectionTypeX" } });
  const alt = el.children[0].querySelector(".r-actions").children[1];
  assert.match(dom.text(alt), /^Open .+…/);
  assert.ok(dom.text(alt).length <= "Open ".length + 18);
  assert.match(alt.getAttribute("title"), /^AccessoryConnectionType: /);
});

process.on("exit", restore);
