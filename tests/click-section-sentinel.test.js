// click-section.js on Sentinel: the same sectionFor the Splunk popups
// call, over the grid's context, with the blade's hooks (click-sentinel.js).
// The bands come out in the same registry order; what differs is what the
// modules own on this platform and what the hooks add (the pivot line,
// the table picker, the workspace note). A click never holds here either.
import "./_sentinel.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { h } from "../app/components/h.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as modules from "../app/lib/modules.js";
import * as runbooks from "../app/lib/runbooks.js";
import * as runtime from "../app/lib/runtime.js";
import * as enrich from "../app/lib/enrich.js";
import { source as kevSource } from "../app/lib/enrich/kev.js";
import * as packs from "../app/lib/packs.js";
import * as pivot from "../app/lib/pivot.js";
import * as kql from "../app/lib/kql.js";
import * as workflows from "../app/lib/workflows.js";
import * as notebook from "../app/lib/notebook.js";
import * as pinned from "../app/lib/pinned.js";
import * as investigation from "../app/lib/investigation.js";
import * as store from "../app/lib/store.js";
import * as ui from "../app/lib/popup-ui.js";
import { KEYS } from "../app/lib/storage-keys.js";
import { BANDS } from "../app/lib/modules.js";
import { clickContext } from "../app/lib/click-context.js";
import { sectionFor } from "../app/lib/click-section.js";
import * as sentinelHooks from "../app/lib/click-sentinel.js";

const restore = dom.install();
const settle = (ms = 10) => new Promise((r) => setTimeout(r, ms));
test.after(async () => {
  await settle(100);
  restore();
});
await catalogue.load();
await modules.hydrate();
enrich.register(kevSource);

const bridge = { apply: async () => ({ ok: true }), kqlReady: async () => false };
const lib = { catalogue, modules, runbooks, keys: KEYS, runtime, enrich, packs, pivot, kql, workflows, notebook, bridge, ui, h };
const workspace = { name: "soc-ws", resourceId: "/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/soc-ws" };
const picked = [];
const hooks = sentinelHooks.hooks(lib, { workspace, rerender: (t) => picked.push(t) });
const noWorkspace = sentinelHooks.hooks(lib, { workspace: null });

const el = (tag, attrs = {}, kids = []) => {
  const n = new dom.Node(tag);
  for (const [k, v] of Object.entries(attrs)) if (k === "class") n.className = v; else n.setAttribute(k, v);
  for (const k of kids) n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
  return n;
};
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";

function bladeCell({ table = "ReachCrowdStrike_CL", column = "SHA256HashData", value = HASH } = {}) {
  const headers = ["TimeGenerated", "Type", column, "EventSimpleName", "EventPlatform"];
  const cells = ["2026-09-20T10:00:00Z", table, value, "ProcessRollup2", "Mac"];
  const head = el("div", { role: "row", "aria-rowindex": "1" }, headers.map((name, i) => el("div", { role: "columnheader", "aria-colindex": String(i + 1) }, [name])));
  const body = el("div", { role: "row", "aria-rowindex": "2" }, cells.map((v, i) => el("div", { role: "gridcell", "aria-colindex": String(i + 1) }, [v])));
  const grid = el("div", { class: "ag-root", role: "grid" }, [head, body]);
  document.body.replaceChildren(grid);
  return { cell: body.children[2], header: head.children[2] };
}

const ctxFor = (target, extra = {}) => clickContext("sentinel", target, { discriminators: catalogue.discriminators(), known: catalogue.sourcetypes().map((s) => s.name), infer: (n, a) => catalogue.inferSourcetype(n, a), runbooks: modules.on("runbooks", "sentinel"), scope: workspace.name, ...extra });
const bands = (section) => section.children.filter((c) => c.dataset.band).map((c) => c.dataset.band);
const HEAD_CLASSES = ["reach-badge", "reach-scope", "reach-head", "reach-runbook", "reach-benign", "reach-hold"];
const headParts = (section) => section.children.filter((c) => !c.dataset.band).map((c) => HEAD_CLASSES.find((x) => c.classList.contains(x)) || c.className);
const pins = () => (notebook.current() ? notebook.current().entries.filter((e) => e.kind === "pin") : []);
const click = (kind, name, value = "") => ({ kind, name, value });

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  pinned.clear();
  investigation.clear();
  picked.length = 0;
});

test("a value click draws the head parts, then the sections in BANDS order, every one a band the modules own on Sentinel", async () => {
  const { cell } = bladeCell();
  const out = await sectionFor({ platform: "sentinel", click: click("value", "SHA256HashData", HASH), ctx: ctxFor(cell), lib, hooks });
  assert.deepEqual(headParts(out.el), ["reach-badge", "reach-head", "reach-hold", "reach-benign"]);
  const ids = bands(out.el);
  assert.deepEqual(ids, BANDS.filter((id) => ids.includes(id)), "registry order");
  assert.ok(ids.every((id) => modules.bands("sentinel").includes(id)));
  assert.ok(!ids.includes("workflows"), "the Workflows band is the module's Splunk-only choice");
  assert.ok(ids.includes("meaning") && ids.includes("pivots"));
  assert.equal(dom.text(out.el.querySelector(".reach-scope")), "on ReachCrowdStrike_CL · ProcessRollup2");
  assert.match(dom.text(out.el.querySelector('[data-band="pivots"]')), /No guided workflow on Sentinel/);
  assert.ok(out.el.querySelectorAll('[data-band="pivots"] details.reach-edge').length > 0, "one disclosure per pack edge");
});

test("a column click draws the same walk with no value line, no verdict, no action row, no enrichment and no pattern; the pivots by name", async () => {
  const { header } = bladeCell();
  const out = await sectionFor({ platform: "sentinel", click: click("field", "SHA256HashData"), ctx: ctxFor(header), lib, hooks });
  assert.deepEqual(headParts(out.el), ["reach-badge", "reach-head"]);
  assert.equal(out.el.querySelector(".reach-hold__btn"), null);
  assert.equal(out.el.querySelector(".reach-value"), null);
  const ids = bands(out.el);
  assert.ok(ids.includes("meaning") && ids.includes("pivots"));
  assert.ok(!ids.includes("verdict") && !ids.includes("enrich") && !ids.includes("pattern"));
  assert.match(dom.text(out.el.querySelector('[data-band="pivots"]')), /Right-click a value for the KQL/);
  assert.equal(out.el.querySelectorAll('[data-band="pivots"] details').length, 0, "by name, not a fold per edge");
});

test("no Type on the page: a column bound on one table places the click on it (basis column); a column bound nowhere gets the picker, which redraws with the picked table", async () => {
  const bound = bladeCell({ table: "", column: "CommandLine", value: "/bin/sh -c id" });
  const placed = await sectionFor({ platform: "sentinel", click: click("value", "CommandLine", "/bin/sh -c id"), ctx: ctxFor(bound.cell), lib, hooks });
  assert.equal(dom.text(placed.el.querySelector(".reach-scope")), "on ReachCrowdStrike_CL · ProcessRollup2, the one table with a column CommandLine");
  const shared = bladeCell({ table: "", column: "SHA256HashData" });
  const several = await sectionFor({ platform: "sentinel", click: click("value", "SHA256HashData", HASH), ctx: ctxFor(shared.cell), lib, hooks });
  assert.match(dom.text(several.el.querySelector(".reach-scope")), /^table unknown here/);
  assert.match(dom.text(several.el.querySelector(".reach-head")), /SHA256HashData is a column on 2 tables/);
  const loose = bladeCell({ table: "", column: "zz_nowhere" });
  const out = await sectionFor({ platform: "sentinel", click: click("value", "zz_nowhere", "x"), ctx: ctxFor(loose.cell), lib, hooks });
  assert.match(dom.text(out.el.querySelector(".reach-scope")), /^table unknown here/);
  const sel = out.el.querySelector("select.reach-input");
  assert.ok(sel && sel.children.length > 1, "the catalogue's tables to pick from");
  sel.value = "SecurityAlert";
  dom.fire(sel, "change");
  assert.deepEqual(picked, ["SecurityAlert"]);
  const again = await sectionFor({ platform: "sentinel", click: click("value", "zz_nowhere", "x"), ctx: ctxFor(loose.cell, { forcedTable: "SecurityAlert" }), lib, hooks });
  assert.equal(dom.text(again.el.querySelector(".reach-scope")), "on SecurityAlert, not catalogued");
  // A header click on the same column: no action row, no edges, and the
  // picker still there under Meaning, never a section dropped as empty.
  const header = await sectionFor({ platform: "sentinel", click: click("field", "zz_nowhere"), ctx: ctxFor(loose.header), lib, hooks });
  assert.ok(header && header.el.querySelector("select.reach-input"), "the picker is reachable from a column click");
  assert.deepEqual(bands(header.el), ["meaning"]);
});

test("the workspace is scope: its absence is a note under the scope line, and a held pin carries the name as the pin's scope", async () => {
  const { cell } = bladeCell();
  const out = await sectionFor({ platform: "sentinel", click: click("value", "SHA256HashData", HASH), ctx: ctxFor(cell, { scope: null }), lib, hooks: noWorkspace });
  assert.match(dom.text(out.el.querySelector(".reach-head")), /Workspace not seen yet/);
  const seen = await sectionFor({ platform: "sentinel", click: click("value", "SHA256HashData", HASH), ctx: ctxFor(cell), lib, hooks });
  assert.doesNotMatch(dom.text(seen.el.querySelector(".reach-head")), /Workspace not seen yet/);
  assert.equal(pins().length, 0, "rendering held nothing");
  assert.deepEqual(pinned.all(), {});
  assert.deepEqual(investigation.all(), {});
  dom.fire(seen.el.querySelector(".reach-hold__btn"), "click");
  await settle();
  assert.equal(pins().length, 1);
  assert.equal(pins()[0].from.container, "ReachCrowdStrike_CL");
  assert.equal(pins()[0].from.scope, "soc-ws");
  assert.equal(pins()[0].from.search, undefined, "no visible editor: no search on the pin");
  assert.match(dom.text(seen.el.querySelector(".reach-hold__where")), /search: unavailable here/);
});
