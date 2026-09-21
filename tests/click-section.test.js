// click-section.js: one assembler for the REACH section on every host.
// sectionFor walks modules.bands(platform) once (modules.js BANDS) over
// the context click-context.js read, draws each band from the popup-ui
// block, and asks the hooks only for what the host itself adds. A value
// click and a field click on the same row differ by the value bands
// alone; the side panel's take is one line; a click never holds.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { fakeChrome } from "./_chrome.js";
import { h } from "../app/components/h.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { resolve } from "../app/lib/field-resolve.js";
import * as reachability from "../app/lib/reachability.js";
import * as modules from "../app/lib/modules.js";
import * as runbooks from "../app/lib/runbooks.js";
import * as runtime from "../app/lib/runtime.js";
import * as enrich from "../app/lib/enrich.js";
import { source as kevSource } from "../app/lib/enrich/kev.js";
import * as packs from "../app/lib/packs.js";
import * as pivot from "../app/lib/pivot.js";
import * as workflows from "../app/lib/workflows.js";
import * as notebook from "../app/lib/notebook.js";
import * as pinned from "../app/lib/pinned.js";
import * as investigation from "../app/lib/investigation.js";
import * as store from "../app/lib/store.js";
import * as spl from "../app/lib/spl.js";
import * as fdrQueries from "../app/lib/fdr-queries.js";
import * as ui from "../app/lib/popup-ui.js";
import { KEYS } from "../app/lib/storage-keys.js";
import { BANDS } from "../app/lib/modules.js";
import { clickContext } from "../app/lib/click-context.js";
import { sectionFor, packEdgeRows } from "../app/lib/click-section.js";
import * as splunkHooks from "../app/lib/click-splunk.js";

const restore = dom.install();
const settle = (ms = 10) => new Promise((r) => setTimeout(r, ms));
test.after(async () => {
  await settle(100); // the bands' own late fills (values sidecar, verdict tier) finish before the document goes
  restore();
});
await catalogue.load();
await modules.hydrate();
enrich.register(kevSource); // the bundled source the content scripts register before a click

const bridge = { apply: async () => ({ ok: true }), kqlReady: async () => false, read: async () => ({ ok: false, text: "" }) };
const lib = { catalogue, fields, resolve, ...reachability, modules, runbooks, keys: KEYS, runtime, enrich, packs, pivot, workflows, notebook, bridge, spl, fdrQueries, ui, h, live: null };
const splunk = splunkHooks.hooks(lib);

const el = (tag, attrs = {}, kids = []) => {
  const n = new dom.Node(tag);
  for (const [k, v] of Object.entries(attrs)) if (k === "class") n.className = v; else n.setAttribute(k, v);
  for (const k of kids) n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
  return n;
};
const HASH = "ba4038fd20e474c047be8aad5bfacdb1bfc1ddbe12f803f473b7918d8d819436";

function splunkRow({ sourcetype = "crowdstrike:events:sensor", field = "SHA256HashData", value = HASH } = {}) {
  const fv = (name, v) => el("a", { class: "f-v", "data-field-name": name }, [v]);
  const clicked = fv(field, value);
  const links = [fv("host", "wk-1"), fv("source", "/x"), sourcetype ? fv("sourcetype", sourcetype) : null, fv("index", "fdr"), fv("event_simpleName", "ProcessRollup2"), fv("event_platform", "Mac"), fv("aid", "aid1")].filter(Boolean);
  const row = el("tr", { class: "shared-eventsviewer-list-body-row" }, [el("td", {}, [el("table", {}, [el("tr", {}, [el("td", {}, [clicked])])]), el("table", { class: "fields" }, links)])]);
  document.body.replaceChildren(row);
  return clicked;
}

const ctxFor = (target, extra = {}) => clickContext("splunk", target, { discriminators: catalogue.discriminators(), runbooks: modules.on("runbooks", "splunk"), ...extra });
const bands = (section) => section.children.filter((c) => c.dataset.band).map((c) => c.dataset.band);
const HEAD_CLASSES = ["reach-badge", "reach-scope", "reach-head", "reach-runbook", "reach-benign", "reach-hold"];
const headParts = (section) => section.children.filter((c) => !c.dataset.band).map((c) => HEAD_CLASSES.find((x) => c.classList.contains(x)) || c.className);
const pins = () => (notebook.current() ? notebook.current().entries.filter((e) => e.kind === "pin") : []);

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  pinned.clear();
  investigation.clear();
});

test("a Splunk value click draws the head parts, then the sections in BANDS order, every one a band the modules own", async () => {
  const target = splunkRow();
  const out = await sectionFor({ platform: "splunk", click: { kind: "value", name: "SHA256HashData", value: HASH }, ctx: ctxFor(target), lib, hooks: splunk });
  assert.equal(out.panel, false);
  assert.equal(out.el.className, "reach-section");
  assert.deepEqual(headParts(out.el), ["reach-badge", "reach-scope", "reach-hold", "reach-benign"]);
  const ids = bands(out.el);
  assert.deepEqual(ids, BANDS.filter((id) => ids.includes(id)), "registry order");
  assert.deepEqual(ids, ["verdict", "meaning", "everywhere", "enrich", "pivots", "workflows"]);
  assert.ok(modules.bands("splunk").includes("pivots"));
  assert.equal(dom.text(out.el.querySelector(".reach-scope")), "on crowdstrike:events:sensor · ProcessRollup2");
});

test("a field click draws the same walk with no value line, no verdict, no action row, no enrichment and no pattern", async () => {
  const target = splunkRow();
  const key = await sectionFor({ platform: "splunk", click: { kind: "field", name: "SHA256HashData", value: "" }, ctx: ctxFor(target), lib, hooks: splunk });
  assert.deepEqual(headParts(key.el), ["reach-badge", "reach-scope"]);
  assert.deepEqual(bands(key.el), ["meaning", "everywhere", "pivots", "workflows"]);
  assert.equal(key.el.querySelector(".reach-value"), null);
  assert.equal(key.el.querySelector(".reach-hold__btn"), null);
  assert.match(dom.text(key.el.querySelector('[data-band="pivots"]')), /Click a value for the SPL/);
});

test("the side panel takes the click: the answer is the one line the page shows, with no band drawn", async () => {
  const c = fakeChrome({ answer: (msg) => (msg.type === "reach:selection" ? { panel: true } : null) });
  const undo = c.install();
  try {
    const target = splunkRow();
    const out = await sectionFor({ platform: "splunk", click: { kind: "value", name: "SHA256HashData", value: HASH }, ctx: ctxFor(target), lib, hooks: splunk });
    assert.equal(out.panel, true);
    assert.ok(out.el.classList.contains("reach-section--panelline"));
    assert.deepEqual(bands(out.el), []);
    const sent = c.messages.find((m) => m.type === "reach:selection").selection;
    assert.equal(sent.sourcetype, "crowdstrike:events:sensor");
    assert.equal(sent.index, "fdr");
    assert.equal(sent.event.aid, "aid1");
    assert.equal(sent.provenance.scope, "fdr");
  } finally {
    undo();
  }
});

test("nothing known anywhere: a value click keeps Hold and the enrichment row, the sidebar's field gets nothing, a key in an event still gets a section", async () => {
  const target = splunkRow({ sourcetype: null, field: "zz_unknown_field", value: "CVE-2021-44228" });
  const value = await sectionFor({ platform: "splunk", click: { kind: "value", name: "zz_unknown_field", value: "CVE-2021-44228" }, ctx: ctxFor(target), lib, hooks: splunk });
  assert.deepEqual(headParts(value.el), ["reach-badge", "reach-scope", "reach-hold", "reach-benign"]);
  assert.deepEqual(bands(value.el), ["enrich"]);
  assert.equal(dom.text(value.el.querySelector(".reach-scope")), "field not catalogued");
  document.body.replaceChildren();
  const popdown = await sectionFor({ platform: "splunk", click: { kind: "field", name: "zz_unknown_field", value: "" }, ctx: ctxFor(null), lib, hooks: splunk });
  assert.equal(popdown, null, "the host's popdown is left alone");
  const key = await sectionFor({ platform: "splunk", click: { kind: "field", name: "zz_unknown_field", value: "" }, ctx: ctxFor(splunkRow({ sourcetype: null, field: "zz_unknown_field" })), lib, hooks: splunk });
  assert.ok(key && bands(key.el).includes("meaning"));
});

test("rendering a section writes neither the notebook, the pinned store nor the held facts; only the Hold button does", async () => {
  const target = splunkRow();
  const out = await sectionFor({ platform: "splunk", click: { kind: "value", name: "SHA256HashData", value: HASH }, ctx: ctxFor(target), lib, hooks: splunk });
  assert.equal(pins().length, 0);
  assert.deepEqual(pinned.all(), {});
  assert.deepEqual(investigation.all(), {});
  const btn = out.el.querySelector(".reach-hold__btn");
  assert.ok(btn, "the Hold button is drawn, not pressed");
  dom.fire(btn, "click");
  await settle();
  assert.equal(pins().length, 1, "the button writes the pin");
  assert.equal(pins()[0].from.container, "crowdstrike:events:sensor");
  assert.equal(pins()[0].from.scope, "fdr");
});

test("Hold's search is the editor reader, asked on the click and never at render", async () => {
  const target = splunkRow();
  let asked = 0;
  const ctx = ctxFor(target, { readEditor: async () => { asked++; return { ok: true, text: "search index=fdr | head 1" }; } });
  const out = await sectionFor({ platform: "splunk", click: { kind: "value", name: "SHA256HashData", value: HASH }, ctx, lib, hooks: splunk });
  assert.equal(asked, 0, "render reads nothing off the editor");
  assert.doesNotMatch(dom.text(out.el.querySelector(".reach-hold__where")), /search: unavailable here/);
  dom.fire(out.el.querySelector(".reach-hold__btn"), "click");
  await settle();
  assert.equal(asked, 1);
  assert.equal(pins()[0].from.search.text, "search index=fdr | head 1");
});

test("pack edge parameters: the Splunk hooks bind the scope ahead of the row's fields, the Sentinel hooks default the window after them", () => {
  const seen = [];
  const fake = { packs: { params: () => ({ aid: { from_field: "aid" }, index: { from_field: "index" }, earliest: { placeholder: "-24h" } }) } };
  const m = { lib: fake, ctx: { read: (n) => ({ aid: "aid1", index: "row-index" })[n] || null }, edges: [{ packId: "p", src: { sourcetype: "st" }, dst: { sourcetype: "st" }, label: "e", basis: "confirmed" }], value: "v", container: "st" };
  const control = (edge, params) => { seen.push(params); return h("div"); };
  const open = (rows) => rows[0].listeners.toggle[0]({ target: { open: true } });
  open(packEdgeRows(m, control, { before: (params) => { params.index = "configured"; } }));
  assert.deepEqual(seen[0], { value: "v", index: "configured", aid: "aid1" }, "a scope the settings hold wins over a row column of the same name");
  open(packEdgeRows(m, control, { after: (params, meta) => { if (params.earliest === undefined) params.earliest = meta.earliest.placeholder; } }));
  assert.deepEqual(seen[1], { value: "v", aid: "aid1", index: "row-index", earliest: "-24h" }, "the row's own fields win over a default");
});
