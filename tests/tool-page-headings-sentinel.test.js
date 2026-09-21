// The tool pages under Sentinel's words: the title block first, every h2 a
// registry entry in the tool master's order (the runbook page included),
// and Discover naming its mode (you run each KQL and paste the cell back)
// with Open step 1 and Copy all queries as its actions.
import "./_sentinel.js";
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
import * as workflows from "../app/lib/workflows.js";
import { TOOL_ORDER, matcher } from "../app/lib/headings.js";

const restore = dom.install();
globalThis.window = globalThis.window || { location: { hash: "" }, addEventListener() {}, removeEventListener() {}, matchMedia: () => ({ matches: false }) };
await catalogue.load();
await modules.hydrate();
const views = {
  catalogue: await import("../app/views/catalogue.js"),
  discover: await import("../app/views/discover.js"),
  share: await import("../app/views/share.js"),
  start: await import("../app/views/start.js"),
  unknown: await import("../app/views/unknown.js"),
};
const resolve = matcher();
const ctx = { fields, catalogue, search, modules, params: { name: "NoSuchColumn" }, cards: [], setUrl() {}, navigate() {}, back() {}, openSettings() {}, focusSearch() {} };

function isSubsequence(seq, master) {
  let i = 0;
  for (const id of seq) {
    const at = master.indexOf(id, i);
    if (at < 0) return false;
    i = at + 1;
  }
  return true;
}

for (const route of Object.keys(views)) {
  test(`${route} on Sentinel: title block first, registry h2s in the tool master's order`, () => {
    const el = views[route].render({ ...ctx });
    const first = el.children.find((c) => c.tagName !== "#TEXT");
    assert.ok(first && first.classList.contains("r-title"), `${route}: the title block is the view's first child`);
    const ids = el.querySelectorAll("h2").map((n) => (resolve(dom.text(n)) || { id: `unregistered: ${dom.text(n)}` }).id);
    assert.ok(ids.every((id) => !id.startsWith("unregistered")), ids.join(", "));
    assert.ok(isSubsequence(ids, TOOL_ORDER), `${ids} is not a subsequence of the tool master`);
  });
}

test("the runbook page on Sentinel draws Steps (N), Benign conditions (N) and Escalation conditions (N) from the registry, in the tool master's order", async () => {
  const view = await import("../app/views/runbook.js");
  const rows = JSON.parse(await readFile(new URL("./fixtures/alert-rows.json", import.meta.url), "utf8"));
  const row = rows.sentinel.security_alert;
  const hash = runbooks.href(runbooks.ruleKeyFor(row, "sentinel"), row);
  const params = { key: decodeURIComponent(hash.slice("#/runbook/".length).split("?")[0]), ...Object.fromEntries(new URLSearchParams(hash.split("?")[1] || "")) };
  const drawer = Object.fromEntries(["setTitle", "setSpl", "setParams", "setHazards", "setState", "copy"].map((m) => [m, () => {}]));
  const el = view.render({ ...ctx, params, drawer, goBack() {}, setDrawerParamHandler() {} });
  for (let i = 0; i < 50 && !el.querySelector("h2"); i += 1) await new Promise((r) => setTimeout(r, 20));
  assert.ok(el.children[0].classList.contains("r-title"));
  const ids = el.querySelectorAll("h2").map((n) => (resolve(dom.text(n)) || { id: `unregistered: ${dom.text(n)}` }).id);
  assert.deepEqual(ids, ["steps", "benign-conditions", "escalation-conditions"]);
  assert.ok(isSubsequence(ids, TOOL_ORDER));
});

test("Discover on Sentinel is the recipe: the scope names the mode, the actions are Open step 1 and Copy all queries, the sections Workspace, Queries, Pasted results, Discovered tables (N)", () => {
  const el = views.discover.render({ ...ctx });
  const first = el.children[0];
  assert.match(dom.text(first.querySelector(".r-scope")), /you run each KQL and paste the cell back$/);
  assert.deepEqual(first.querySelector(".r-actions").children.map((n) => dom.text(n)), ["Open step 1 ↗", "Copy all queries"]);
  assert.deepEqual(el.querySelectorAll("h2").map((n) => dom.text(n)), ["Workspace", "Queries", "Pasted results", "Discovered tables (0)"]);
});

test("the catalogue on Sentinel heads its list Tables (N) and links Discover from its action row", () => {
  const el = views.catalogue.render({ ...ctx });
  const first = el.children[0];
  assert.ok(first.querySelector(".r-actions").querySelectorAll("a").some((a) => a.getAttribute("href") === "#/discover"));
  assert.match(dom.text(el.querySelectorAll("h2")[0]), /^Tables \(\d+\)$/);
});

test("the unknown page on Sentinel uses column and tables in its why line and never links a Splunk workflow", () => {
  const el = views.unknown.render({ ...ctx, params: { name: "zzzzqqqq" } });
  const first = el.children[0];
  assert.match(dom.text(first.querySelector(".r-scope")), /no column or event is called this among \d+ names on \d+ tables/);
  assert.deepEqual(first.querySelector(".r-actions").children.map((n) => dom.text(n)), ["Back", "Search", "Catalogue"]);
  assert.equal(modules.routes().includes("workflow"), true, "the workflow route mounts on Sentinel for pack hunts");
  const emptyEl = el.querySelector(".r-empty");
  assert.ok(emptyEl);
  assert.ok(emptyEl.querySelectorAll("a").length < el.querySelectorAll("a").length, "the empty state keeps its search move");
  assert.equal(el.querySelectorAll("a").some((a) => /^#\/w\//.test(a.getAttribute("href") || "")), false);
});

test("on Sentinel the workflow list carries pack workflows that render there and none of the FDR five", () => {
  const ids = workflows.list().map((w) => w.id);
  assert.ok(ids.includes("hunt_mac_signing"));
  for (const id of ["pid", "process", "host", "detection", "ioc"]) assert.ok(!ids.includes(id), id);
  assert.equal(workflows.get("ioc", ctx), null);
});

process.on("exit", restore);
