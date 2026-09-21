// click-context.js: one shape for a click's context on both hosts. The
// Splunk reader (context.js) answers off the event row's default-field
// links, the Sentinel reader (sentinel-context.js) off the grid's Type
// cell and headers, and both come back with the same keys, the alert
// fields under the platform's own container key, and read(name) for the
// row's other fields.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import { SHAPE, clickContext, conform } from "../app/lib/click-context.js";
import { VERDICT_FIELDS, ALERT_FIELDS } from "../app/lib/bands/verdict.js";

const restore = dom.install();
test.after(() => restore());

const el = (tag, attrs = {}, kids = []) => {
  const n = new dom.Node(tag);
  for (const [k, v] of Object.entries(attrs)) if (k === "class") n.className = v; else n.setAttribute(k, v);
  for (const k of kids) n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
  return n;
};

// A Splunk events-viewer row: the clicked value in a nested table, the
// default-field links at the bottom.
function splunkRow({ sourcetype = "crowdstrike:events:sensor", index = "fdr", disc = ["event_simpleName", "ProcessRollup2"], fields = {} } = {}) {
  const fv = (name, v) => el("a", { class: "f-v", "data-field-name": name }, [v]);
  const clicked = fv("SHA256HashData", "abc");
  const links = [fv("host", "wk-1"), fv("source", "/x"), sourcetype ? fv("sourcetype", sourcetype) : null, index ? fv("index", index) : null, disc ? fv(disc[0], disc[1]) : null, ...Object.entries(fields).map(([k, v]) => fv(k, v))].filter(Boolean);
  const time = el("span", { class: "formated-time", "data-time-iso": "2022-07-27T10:42:41.056+00:00" }, ["7/27/22"]);
  const row = el("tr", { class: "shared-eventsviewer-list-body-row" }, [el("td", {}, [time, el("table", {}, [el("tr", {}, [el("td", {}, [clicked])])]), el("table", { class: "fields" }, links)])]);
  return { row, clicked };
}

// A Logs blade grid: headers with aria-colindex, one row of gridcells.
function bladeGrid({ headers = ["TimeGenerated", "Type", "SHA256HashData", "AlertName"], cells = ["2026-09-20T10:00:00Z", "ReachCrowdStrike_CL", "abc", ""], type = true } = {}) {
  const head = el("div", { role: "row", "aria-rowindex": "1" }, headers.map((name, i) => el("div", { role: "columnheader", "aria-colindex": String(i + 1) }, [name])));
  const body = el("div", { role: "row", "aria-rowindex": "2" }, cells.map((v, i) => el("div", { role: "gridcell", "aria-colindex": String(i + 1) }, [v])));
  const grid = el("div", { class: "ag-root", role: "grid" }, [head, body]);
  return { grid, cell: (i) => body.children[i], header: (i) => head.children[i] };
}

test("both readers answer every key of the shape, and nothing a band reads is missing", () => {
  const { row, clicked } = splunkRow();
  document.body.replaceChildren(row);
  const splunk = clickContext("splunk", clicked, { discriminators: { "crowdstrike:events:sensor": "event_simpleName" } });
  const { grid, cell } = bladeGrid();
  document.body.replaceChildren(grid);
  const sentinel = clickContext("sentinel", cell(2), { discriminators: {}, known: ["ReachCrowdStrike_CL"] });
  for (const ctx of [splunk, sentinel]) for (const k of SHAPE) assert.ok(k in ctx, `${ctx.platform} carries ${k}`);
  assert.deepEqual(Object.keys(conform({})).sort(), [...SHAPE].sort());
  assert.equal(typeof splunk.read, "function");
  assert.equal(typeof sentinel.searchNow, "function");
});

test("Splunk: the container, scope, discriminator, event and row fields come off the clicked row, and the alert fields carry the sourcetype", () => {
  const { row, clicked } = splunkRow({ fields: { search_name: "ESCU - x", dest: "wk-1", aid: "aid1" } });
  document.body.replaceChildren(row);
  const ctx = clickContext("splunk", clicked, { discriminators: { "crowdstrike:events:sensor": "event_simpleName" }, runbooks: true });
  assert.equal(ctx.container, "crowdstrike:events:sensor");
  assert.equal(ctx.scope, "fdr");
  assert.deepEqual(ctx.basis, { container: "row", scope: "row" });
  assert.deepEqual(ctx.discriminator, { field: "event_simpleName", value: "ProcessRollup2" });
  assert.deepEqual(ctx.candidates, ["crowdstrike:events:sensor"]);
  assert.equal(ctx.event.time, "2022-07-27T10:42:41.056+00:00");
  assert.match(ctx.event.summary, /crowdstrike:events:sensor · ProcessRollup2 event/);
  assert.equal(ctx.read("aid"), "aid1");
  assert.equal(ctx.read("nope"), null);
  assert.ok(ALERT_FIELDS.includes("search_name") && VERDICT_FIELDS.includes("aid"));
  assert.equal(ctx.alertRow.search_name, "ESCU - x");
  assert.equal(ctx.alertRow.sourcetype, "crowdstrike:events:sensor", "the alert row names the container under Splunk's key");
  assert.equal(ctx.eventFields.aid, "aid1");
  assert.equal(ctx.eventFields.search_name, "ESCU - x", "the alert fields ride with the event fields");
});

test("Splunk: with runbooks off the alert fields are not read, and the verdict fields still are", () => {
  const { row, clicked } = splunkRow({ fields: { search_name: "ESCU - x", aid: "aid1" } });
  document.body.replaceChildren(row);
  const ctx = clickContext("splunk", clicked, { runbooks: false });
  assert.deepEqual(ctx.alertRow, {});
  assert.equal(ctx.eventFields.aid, "aid1");
  assert.equal(ctx.eventFields.search_name, undefined);
});

test("Splunk: no element is the page: one sourcetype on the page is the container, several are candidates, and there is no row to read", () => {
  const a = splunkRow({ sourcetype: "aws:cloudtrail" });
  document.body.replaceChildren(a.row);
  const one = clickContext("splunk", null, {});
  assert.equal(one.container, "aws:cloudtrail");
  assert.equal(one.basis.container, "page");
  assert.equal(one.read("sourcetype"), null);
  assert.equal(one.row, null);
  const b = splunkRow({ sourcetype: "crowdstrike:events:sensor" });
  document.body.replaceChildren(a.row, b.row);
  const mixed = clickContext("splunk", null, {});
  assert.equal(mixed.container, null);
  assert.deepEqual(mixed.candidates, ["aws:cloudtrail", "crowdstrike:events:sensor"]);
  assert.deepEqual(mixed.eventFields, {});
});

test("Sentinel: a cell's container is the row's Type, the column its header, the scope the caller's workspace, and the alert fields carry Type", () => {
  const { grid, cell } = bladeGrid({ cells: ["2026-09-20T10:00:00Z", "SecurityAlert", "abc", "Suspicious sign-in"] });
  document.body.replaceChildren(grid);
  const ctx = clickContext("sentinel", cell(2), { discriminators: {}, known: ["SecurityAlert"], scope: "soc-ws", runbooks: true });
  assert.equal(ctx.container, "SecurityAlert");
  assert.equal(ctx.kind, "value");
  assert.equal(ctx.value, "abc");
  assert.deepEqual(ctx.column, { column: "SHA256HashData", path: "SHA256HashData", header: ctx.column.header });
  assert.equal(ctx.scope, "soc-ws");
  assert.deepEqual(ctx.basis, { container: "row", scope: "workspace" });
  assert.equal(ctx.event.time, "2026-09-20T10:00:00Z");
  assert.equal(ctx.read("AlertName"), "Suspicious sign-in");
  assert.equal(ctx.alertRow.AlertName, "Suspicious sign-in");
  assert.equal(ctx.alertRow.Type, "SecurityAlert", "the alert row names the container under Sentinel's key");
  assert.equal(ctx.alertRow.sourcetype, undefined);
});

test("Sentinel: a column header is a field click with no row to read and no event fields", () => {
  const { grid, header } = bladeGrid();
  document.body.replaceChildren(grid);
  const ctx = clickContext("sentinel", header(2), { discriminators: {}, known: ["ReachCrowdStrike_CL"], runbooks: true });
  assert.equal(ctx.kind, "field");
  assert.equal(ctx.column.path, "SHA256HashData");
  assert.equal(ctx.value, "");
  assert.equal(ctx.read("Type"), null);
  assert.deepEqual(ctx.eventFields, {});
  assert.equal(ctx.container, "ReachCrowdStrike_CL", "one Type on the page places a header click");
  assert.equal(ctx.basis.container, "page");
});

test("Sentinel: with no Type on the page the caller's infer() names the table from the column, basis column; a picked table is basis user", () => {
  const { grid, cell } = bladeGrid({ headers: ["TimeGenerated", "Aid", "SHA256HashData"], cells: ["t", "a1", "abc"] });
  document.body.replaceChildren(grid);
  const infer = (name) => (name === "SHA256HashData" ? { sourcetype: "ReachCrowdStrike_CL", concept: "hash", basis: "column" } : null);
  const inferred = clickContext("sentinel", cell(2), { discriminators: { ReachCrowdStrike_CL: "EventSimpleName" }, known: ["ReachCrowdStrike_CL"], infer });
  assert.equal(inferred.container, "ReachCrowdStrike_CL");
  assert.equal(inferred.basis.container, "column");
  const several = clickContext("sentinel", cell(2), { known: [], infer: () => ({ sourcetypes: ["A_CL", "B_CL"], concept: "hash" }) });
  assert.equal(several.container, null);
  assert.deepEqual(several.inferred, { sourcetypes: ["A_CL", "B_CL"], concept: "hash" });
  const picked = clickContext("sentinel", cell(2), { known: [], forcedTable: "B_CL" });
  assert.equal(picked.container, "B_CL");
  assert.equal(picked.basis.container, "user");
});

test("searchNow: Splunk asks the editor first and keeps the page's job id; Sentinel answers the editor text it read at the click", async () => {
  const { row, clicked } = splunkRow();
  document.body.replaceChildren(row);
  const doc = document;
  doc.defaultView = { location: { search: "?q=search%20index%3Dfdr&sid=123" } };
  const bridged = clickContext("splunk", clicked, { readEditor: async () => ({ ok: true, text: "search index=fdr | head 1" }) });
  assert.deepEqual(await bridged.searchNow(), { text: "search index=fdr | head 1", sid: "123" });
  const refused = clickContext("splunk", clicked, { readEditor: async () => { throw new Error("no editor"); } });
  assert.deepEqual(await refused.searchNow(), { text: "search index=fdr", sid: "123" });
  delete doc.defaultView;
  const { grid, cell } = bladeGrid();
  document.body.replaceChildren(grid);
  const sentinel = clickContext("sentinel", cell(2), {});
  assert.equal(sentinel.search, null, "no visible editor: no search");
  assert.equal(await sentinel.searchNow(), null);
});
