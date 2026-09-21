// Parity of the pack-rendered FDR searches against the golden fixture
// tests/fixtures/fdr-queries.json, which holds what the shape functions
// that used to live in app/lib/spl.js, now app/lib/fdr-queries.js, rendered: every kind the views
// construct and every bundle edge, over the parameter sets in
// _fdr-cases.js, inline and macro. The fixture is frozen; it is not
// regenerated from the code under test. The edges come from the frozen
// tests/fixtures/fdr-edges.json, so the cases hold wherever the join
// graph lives.
//
// Inline: spl, hazards, missing, form and sourcetype byte for byte, and
// the error code and message where the old renderer threw. Macro: the
// text and the parameters it leaves unbound (the drawer shows the macro
// tab's text only); a null macro entry means the old renderer fell back
// to the inline text, which the adapter must still do.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as fdr from "../app/lib/fdr-queries.js";
import { KINDS, EDGE_PARAMS, paramSets } from "./_fdr-cases.js";

await catalogue.load();

const cases = JSON.parse(readFileSync(new URL("./fixtures/fdr-queries.json", import.meta.url), "utf8"));
const EDGES = JSON.parse(readFileSync(new URL("./fixtures/fdr-edges.json", import.meta.url), "utf8"));
const edgeById = (id) => EDGES.find((e) => e.id === id) || null;

function render(pivot, params, opts) {
  try {
    const out = fdr.generate(pivot, params, opts);
    return { spl: out.spl, hazards: out.hazards.map((h) => ({ level: h.level, text: h.text })), missing: out.missing, form: out.form, sourcetype: out.sourcetype };
  } catch (err) {
    return { error: { name: err.name, code: err.code, message: err.message } };
  }
}

function pivotOf(c) {
  return c.pivot.kind === "edge" ? { kind: "edge", edge: edgeById(c.pivot.edge) } : { kind: c.pivot.kind };
}

test("the fixture covers every kind and every bundle edge under every parameter set", () => {
  const ids = new Set(cases.map((c) => c.id));
  for (const [kind, spec] of Object.entries(KINDS)) for (const { name } of paramSets(spec)) assert.ok(ids.has(`${kind} ${name}`), `${kind} ${name}`);
  for (const edge of EDGES) for (const { name } of paramSets(EDGE_PARAMS)) assert.ok(ids.has(`edge ${edge.id} ${name}`), `${edge.id} ${name}`);
  assert.equal(cases.length, 127);
});

for (const c of cases) {
  test(`inline parity: ${c.id}`, () => {
    const got = render(pivotOf(c), c.params);
    if (c.inline.error) {
      assert.ok(got.error, `expected ${c.inline.error.code}, got a search`);
      assert.equal(got.error.name, "SplError");
      assert.equal(got.error.code, c.inline.error.code);
      assert.equal(got.error.message, c.inline.error.message);
      return;
    }
    assert.deepEqual(got, c.inline);
  });
  test(`macro parity: ${c.id}`, () => {
    const got = render(pivotOf(c), c.params, { form: "macro" });
    if (c.inline.error) {
      assert.equal(got.error && got.error.code, c.inline.error.code);
      return;
    }
    if (c.macro === null) {
      assert.equal(got.form, "inline");
      assert.equal(got.spl, c.inline.spl);
      return;
    }
    assert.equal(got.form, "macro");
    assert.equal(got.spl, c.macro.spl);
    assert.deepEqual(got.missing, c.macro.missing);
    assert.equal(got.sourcetype, c.macro.sourcetype);
  });
}

test("every FDR search is a query of the crowdstrike-falcon pack, one per shape the bundle reaches", () => {
  const pack = packs.pack("crowdstrike-falcon");
  // The pack's own hunts (hunt_*) are workflow searches, not FDR shapes.
  const ids = pack.queries.map((q) => q.id).filter((id) => !id.startsWith("hunt_"));
  assert.deepEqual(ids, ["cs_trace", "cs_process_events", "cs_process_table", "cs_pid_lookup", "cs_tpid_to_pid", "cs_host_lookup", "cs_event_sample", "cs_process_anchor", "cs_tree", "cs_os_pid", "cs_host_record", "cs_file_record", "cs_user_record", "cs_detection_host"]);
  const reached = new Set();
  for (const kind of Object.keys(KINDS)) reached.add(fdr.targetFor({ kind }).query);
  for (const edge of EDGES) reached.add(fdr.targetFor({ kind: "edge", edge }).query);
  assert.deepEqual([...reached].sort(), ids.slice().sort());
  assert.deepEqual(pack.macros, ["cs_index", "cs_trace_process", "cs_process_table", "cs_pid_lookup", "cs_process_events"]);
});

test("a query runs on the container the caller names and refuses one it was not written for", () => {
  const sample = packs.query("crowdstrike-falcon", "cs_event_sample");
  assert.equal(sample.dst.sourcetype, "crowdstrike:events:sensor");
  assert.deepEqual(sample.containers, ["crowdstrike:events:sensor", "crowdstrike:events:external"]);
  assert.equal(packs.query("crowdstrike-falcon", "cs_event_sample", { container: "crowdstrike:events:external" }).dst.sourcetype, "crowdstrike:events:external");
  assert.equal(packs.query("crowdstrike-falcon", "cs_event_sample", { container: "crowdstrike:appinfo" }), null);
  assert.equal(packs.query("crowdstrike-falcon", "nope"), null);
  assert.equal(packs.query("aws-cloudtrail", "cs_trace"), null);
  assert.throws(() => fdr.generate({ kind: "event_sample" }, { event: "DnsRequest", sourcetype: "crowdstrike:appinfo" }), (e) => e.name === "SplError" && e.code === "bad_pivot");
});

test("the spec adapter refuses what the old renderer refused", () => {
  assert.throws(() => fdr.generate(null), (e) => e.code === "bad_pivot");
  assert.throws(() => fdr.generate({ kind: "decode" }, { field: "x" }), (e) => e.code === "unknown_kind");
  assert.throws(() => fdr.generate({ kind: "edge" }), (e) => e.code === "bad_pivot");
  assert.throws(() => fdr.generate({ kind: "edge", edge: { id: "e_nope", src: "x" } }), (e) => e.code === "bad_pivot");
});

// it_aef7e874: the macro tab needs to know which of the pack's macros a
// rendered form calls, so it can check them against conf-macros.
test("macrosFor: the macro form always needs the index macro too, even though it never appears in its own text", () => {
  const params = { field: "SHA256HashString", value: "x", earliest: "-1h" };
  assert.deepEqual(fdr.macrosFor({ kind: "trace" }, params, { form: "macro" }), ["cs_index", "cs_trace_process"]);
});

test("macrosFor: the inline form only needs the index macro when nothing bound an index", () => {
  const params = { field: "SHA256HashString", value: "x", earliest: "-1h" };
  assert.deepEqual(fdr.macrosFor({ kind: "trace" }, params, { form: "inline" }), ["cs_index"]);
  assert.deepEqual(fdr.macrosFor({ kind: "trace" }, { ...params, index: "crowdstrike" }, { form: "inline" }), []);
  // A bound index does not spare the macro form: it never substitutes one.
  assert.deepEqual(fdr.macrosFor({ kind: "trace" }, { ...params, index: "crowdstrike" }, { form: "macro" }), ["cs_index", "cs_trace_process"]);
});

test("macrosFor: a kind with no macro form answers [], and an unresolvable spec never throws", () => {
  assert.deepEqual(fdr.macrosFor({ kind: "host_lookup" }, { aid: "x", earliest: "-1h" }, { form: "macro" }), []);
  assert.deepEqual(fdr.macrosFor({ kind: "nope" }, {}, { form: "macro" }), []);
  assert.deepEqual(fdr.macrosFor(null, {}, { form: "macro" }), []);
});
