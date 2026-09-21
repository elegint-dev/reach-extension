// The field page's scope line names the record type the click carried,
// resolved through the bundle's older event names, and never an unrelated
// event picked because the corpus registered the field elsewhere.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import { render } from "../app/views/field.js";

await catalogue.load();
dom.install();

const ST = "crowdstrike:events:sensor";
const HANDLE_OPEN = "ProcessHandleOpDetectInfo";
const BUNDLE_NAME = "FalconProcessHandleOpDetectInfo";

function draw(params) {
  const writes = [];
  const drawer = { setTitle() {}, setParams() {}, setHazards() {}, setSpl() {}, setMacros() {}, setState() {} };
  const ctx = { fields, catalogue, params, drawer, setUrl: (view, p) => writes.push(p), navigate() {}, href: () => "#", openSettings() {}, setDrawerParamHandler() {}, setDrawerCopyHandler() {} };
  const el = render(ctx);
  document.body.replaceChildren(el);
  const scopeEl = el.querySelector(".r-scope");
  const eventLinks = scopeEl.querySelectorAll("a").map((a) => a.getAttribute("href")).filter((href) => href.startsWith("#/e/"));
  return { el, writes, scope: dom.text(scopeEl).replace(/ · also on \d+ more$/, ""), eventLinks };
}

test("the bundle resolves a sensor event by its bare name to its older Falcon-prefixed record", () => {
  assert.equal(fields.eventName(HANDLE_OPEN), BUNDLE_NAME);
  assert.equal(fields.eventName(BUNDLE_NAME), BUNDLE_NAME);
  assert.equal(fields.eventName("ProcessRollup2"), "ProcessRollup2");
  assert.equal(fields.eventName("NoSuchEvent"), null);
  assert.equal(fields.event(HANDLE_OPEN), fields.event(BUNDLE_NAME));
  assert.ok(fields.event(HANDLE_OPEN));
});

test("a click on a record type the bundle knows by its own name is the scope line's record type", () => {
  const { scope, writes } = draw({ name: "SHA256HashData", st: ST, on: "ProcessRollup2" });
  assert.equal(scope, `on ${ST} · ProcessRollup2`);
  assert.deepEqual(writes, []);
});

test("a click on the handle-open event names it on the scope line although the bundle lists the field under the older name", () => {
  for (const name of ["DesiredAccess", "TargetProcessId"]) {
    const { el, scope, writes, eventLinks } = draw({ name, st: ST, on: HANDLE_OPEN });
    assert.equal(scope, `on ${ST} · ${HANDLE_OPEN}`, name);
    assert.deepEqual(writes, [], `${name}: the URL keeps the click's record type`);
    assert.deepEqual(eventLinks, [`#/e/${HANDLE_OPEN}`], `${name}: the record type links to its event page`);
    assert.match(dom.text(el), new RegExp(`Free on ${BUNDLE_NAME}`), `${name}: the co-fields block keys on the bundle's record`);
  }
});

test("a click on a record type the corpus never saw the field on still names that record type, with the ledger unselected", () => {
  const { el, scope, writes } = draw({ name: "SourceProcessId", st: ST, on: HANDLE_OPEN });
  assert.equal(scope, `on ${ST} · ${HANDLE_OPEN}`);
  assert.doesNotMatch(scope, /ProcessRollup2/);
  assert.deepEqual(writes, []);
  assert.doesNotMatch(dom.text(el), /Free on /, "no co-fields block for a record the field is not registered on");
});

// The handle-open event carries RawProcessId (the OS pid of the process
// that opened the handle), so the sidecar registers the field on it and
// the ledger keys on that record: e_raw_pid leads One join away.
test("RawProcessId on the handle-open event is a registered record: the ledger reads Search-time lookups (1) and One join away (3) with e_raw_pid first", () => {
  assert.ok(fields.field("RawProcessId").events.includes(BUNDLE_NAME));
  assert.ok(fields.event(BUNDLE_NAME).fields.includes("RawProcessId"));
  const { el, scope } = draw({ name: "RawProcessId", st: ST, on: HANDLE_OPEN });
  assert.equal(scope, `on ${ST} · ${HANDLE_OPEN}`);
  assert.match(dom.text(el), new RegExp(`Free on ${BUNDLE_NAME}`));
  const bands = el.querySelectorAll("h3").map((n) => dom.text(n).replace(/^\W+/, ""));
  assert.ok(bands.includes("On the record15"), bands.join(", "));
  assert.ok(bands.includes("Search-time lookups1"), bands.join(", "));
  assert.ok(bands.includes("One join away3"), bands.join(", "));
  const joins = dom.walk(el, (n) => n.dataset && /^e_/.test(n.dataset.rowId || "")).map((r) => r.dataset.rowId);
  assert.deepEqual(joins, ["e_aid_to_aidmaster", "e_raw_pid", "e_context_to_target", "e_parent_to_target"]);
});

test("a page opened without a record type takes the first registered event and writes it into the URL", () => {
  const { scope, writes } = draw({ name: "RawProcessId", st: ST });
  assert.equal(scope, `on ${ST} · AgenticSessionStart`);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].on, "AgenticSessionStart");
});

test("a click naming a record type the bundle has never heard of keeps it on the scope line as text", () => {
  const { scope, writes, eventLinks } = draw({ name: "RawProcessId", st: ST, on: "NoSuchEvent" });
  assert.equal(scope, `on ${ST} · NoSuchEvent`);
  assert.deepEqual(writes, []);
  assert.deepEqual(eventLinks, []);
});
