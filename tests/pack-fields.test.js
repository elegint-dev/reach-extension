// The crowdstrike-falcon pack's fields sidecar: listed in index.json with
// its byte size and containers, under the budget, valid, carrying no
// audit key and a route paragraph only where the composer cannot make
// one; fetched for a container it lists and for nothing else.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as fields from "../app/lib/pack-fields.js";

const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url), "utf8"));
const entry = index.fields.find((e) => e.pack === "crowdstrike-falcon");
const text = await readFile(new URL(`../app/packs/${entry.file}`, import.meta.url), "utf8");
const doc = JSON.parse(text);

test("index.json lists the sidecar with its byte size, under the budget, and the five containers it describes", () => {
  assert.equal(index.fields.length, 1);
  assert.equal(entry.file, "crowdstrike-falcon.fields.json");
  assert.equal(Buffer.byteLength(text, "utf8"), entry.bytes);
  assert.ok(entry.bytes <= fields.BUDGET_BYTES, `${entry.bytes} over ${fields.BUDGET_BYTES}`);
  assert.deepEqual(entry.containers, ["crowdstrike:appinfo", "crowdstrike:events:external", "crowdstrike:events:sensor", "crowdstrike:inventory:aidmaster", "crowdstrike:userinfo"]);
});

test("the shipped sidecar validates, names its pack and carries 1792 fields, 275 record types, 9 edges and the build's counts", () => {
  assert.deepEqual(fields.validateDocument(doc), []);
  assert.equal(doc.format, fields.FORMAT);
  assert.equal(doc.version, fields.VERSION);
  assert.equal(doc.pack, "crowdstrike-falcon");
  assert.equal(doc.source.ta_version, "3.2.0");
  assert.equal(Object.keys(doc.fields).length, 1792);
  assert.equal(Object.keys(doc.records).length, 275);
  assert.equal(doc.edges.length, 9);
  assert.equal(doc.counts.fields, 1792);
  assert.equal(doc.counts.events, 275);
  assert.equal(doc.counts.decode_tables, Object.values(doc.fields).filter((r) => r.decode).length);
});

test("no shipped record carries an audit key, and a route paragraph rides only on the 32 records the composer cannot make", () => {
  const withAudit = Object.values(doc.fields).filter((r) => "audit" in r);
  assert.deepEqual(withAudit, []);
  const kept = Object.values(doc.fields).filter((r) => "explain" in r.route);
  assert.equal(kept.length, 32);
  for (const r of kept) assert.equal(r.route.summary, "derived", r.name);
});

const SMALL = () => ({
  format: fields.FORMAT,
  version: fields.VERSION,
  pack: "crowdstrike-falcon",
  counts: { fields: 3, events: 2 },
  fields: {
    A: { name: "A", layer: "raw_fdr", role: "other", events: ["ProcessRollup2"], decode: null, route: { summary: "direct_anchor", by_event: { ProcessRollup2: { route: "direct_anchor" } }, derived_from: [] } },
    B: { name: "B", layer: "raw_fdr", role: "other", events: ["Event_DetectionSummaryEvent"], decode: { lookup: "x.csv", meaning_field: "B_meaning", values: { 1: "one" } }, route: { summary: "host_only", by_event: { Event_DetectionSummaryEvent: { route: "host_only" } }, derived_from: [] } },
    C: { name: "C", layer: "ta_derived", role: "enum_label", events: [], decode: null, route: { summary: "derived", by_event: {}, derived_from: [], explain: "kept as written" } },
    aid: { name: "aid", layer: "raw_fdr", role: "agent_id", events: ["ProcessRollup2"], decode: null, route: { summary: "one_hop", by_event: {}, derived_from: [] } },
    aid_hostname: { name: "aid_hostname", layer: "ta_derived", role: "other", events: [], decode: null, route: { summary: "derived", by_event: {}, derived_from: [] } },
  },
  records: {
    ProcessRollup2: { name: "ProcessRollup2", sourcetype: "crowdstrike:events:sensor", fields: ["A", "aid"], fields_by_role: { other: ["A"], agent_id: ["aid"] }, is_anchor: true, handles: ["TargetProcessId"] },
    FalconProcessHandleOpDetectInfo: { name: "FalconProcessHandleOpDetectInfo", sourcetype: "crowdstrike:events:sensor", fields: ["aid"], is_anchor: false, handles: [] },
    Event_DetectionSummaryEvent: { name: "Event_DetectionSummaryEvent", sourcetype: "crowdstrike:events:external", fields: ["B"], is_anchor: false, handles: [] },
  },
  edges: [
    { id: "e_aid_to_aidmaster", kind: "host_enrichment", src: "aid", src_sourcetype: "crowdstrike:events:sensor", dst: "aidmaster.aid", dst_sourcetype: "crowdstrike:inventory:aidmaster", target_label: "the host record", basis: "confirmed_ta", yields: ["aid_hostname"], mechanism: "search_time_lookup", automatic_on: ["crowdstrike:events:sensor"] },
  ],
});

test("registration composes every record's route paragraph from its own record types, so readers see the build's shape", () => {
  fields._reset();
  fields.register("crowdstrike-falcon", SMALL());
  assert.ok(fields.loaded());
  assert.ok(fields.ready("crowdstrike-falcon"));
  assert.match(fields.field("A").route.explain, /^This field appears on a process-creation event/);
  assert.match(fields.field("B").route.explain, /^This field rides only on detection summary events/);
  assert.equal(fields.field("C").route.explain, "kept as written");
  assert.deepEqual(fields.names(), ["A", "B", "C", "aid", "aid_hostname"]);
  assert.deepEqual(fields.decode("B"), { lookup: "x.csv", meaning_field: "B_meaning", values: { 1: "one" } });
  assert.equal(fields.decode("A"), null);
  assert.deepEqual(fields.fieldsWithRole("enum_label"), ["C"]);
  assert.equal(fields.packOf("B"), "crowdstrike-falcon");
  assert.equal(fields.packOf("Z"), null);
  assert.equal(fields.field("__proto__"), null);
  assert.equal(fields.counts().fields, 3);
  assert.equal(fields.counts().edges_confirmed, 0, "a count the build did not write reads as zero");
  fields._reset();
});

test("a field's sourcetypes come from its record types, the TA's CIM targets and the join graph's destinations", () => {
  fields._reset();
  fields.register("crowdstrike-falcon", SMALL());
  assert.deepEqual(fields.sourcetypes(), ["crowdstrike:events:external", "crowdstrike:events:sensor", "crowdstrike:inventory:aidmaster"]);
  assert.deepEqual(fields.sourcetypesFor("aid"), ["crowdstrike:events:sensor", "crowdstrike:inventory:aidmaster"]);
  assert.deepEqual(fields.sourcetypesFor("aid_hostname"), ["crowdstrike:inventory:aidmaster"], "a yield rides on the edge's destination");
  assert.equal(fields.fieldOn("crowdstrike:events:sensor", "A").scope, "sourcetype");
  assert.equal(fields.fieldOn("crowdstrike:events:external", "A"), null, "known not to be there");
  assert.equal(fields.fieldOn("aws:cloudtrail", "C").scope, "unscoped", "never observed anywhere");
  assert.equal(fields.fieldOn("aws:cloudtrail", "Z"), null);
  assert.deepEqual(fields.eventsOn("crowdstrike:events:sensor"), ["FalconProcessHandleOpDetectInfo", "ProcessRollup2"]);
  assert.equal(fields.eventName("ProcessHandleOpDetectInfo"), "FalconProcessHandleOpDetectInfo", "a bare sensor name resolves to its older Falcon-prefixed record");
  assert.equal(fields.event("ProcessHandleOpDetectInfo").sourcetype, "crowdstrike:events:sensor");
  assert.equal(fields.eventName("Nope"), null);
  assert.deepEqual(fields.coFields("A", "ProcessRollup2"), [{ role: "agent_id", fields: ["aid"], fills: null }]);
  assert.deepEqual(fields.searchIndex().events, ["Event_DetectionSummaryEvent", "FalconProcessHandleOpDetectInfo", "ProcessRollup2"]);
  assert.equal(fields.edges().length, 1);
  assert.equal(fields.edge("e_aid_to_aidmaster").target_label, "the host record");
  assert.deepEqual(fields.edgesFor("aidmaster.aid").map((e) => e.id), ["e_aid_to_aidmaster"]);
  assert.deepEqual(fields.edgesFor("aid").map((e) => e.id), ["e_aid_to_aidmaster"]);
  assert.deepEqual(fields.edgesFor("Z"), []);
  fields._reset();
});

test("validation refuses an unknown key, an audit key, a foreign layer and a record under another name", () => {
  const base = () => ({ format: fields.FORMAT, version: fields.VERSION, pack: "p", fields: { A: { name: "A", layer: "raw_fdr", role: "other", events: [], decode: null, route: { summary: "unobserved", by_event: {}, derived_from: [] } } } });
  assert.deepEqual(fields.validateDocument(base()), []);
  let d = base();
  d.fields.A.audit = { sample_events_seen: {} };
  assert.match(fields.validateDocument(d).join("; "), /unknown key "audit"/);
  d = base();
  d.extra = 1;
  assert.match(fields.validateDocument(d).join("; "), /unknown key "extra"/);
  d = base();
  d.fields.A.layer = "cim6";
  assert.match(fields.validateDocument(d).join("; "), /layer must be/);
  d = base();
  d.fields.A.name = "B";
  assert.match(fields.validateDocument(d).join("; "), /name must be "A"/);
  d = base();
  d.fields.A.route.summary = "sideways";
  assert.match(fields.validateDocument(d).join("; "), /summary must be one of/);
  d = base();
  d.fields = JSON.parse('{"__proto__": {"name": "__proto__"}}');
  assert.match(fields.validateDocument(d).join("; "), /unsafe key/);
  d = base();
  d.records = { E: { name: "E", fields: [] } };
  assert.match(fields.validateDocument(d).join("; "), /records.E: sourcetype is required/);
  d = base();
  d.records = { E: { name: "F", sourcetype: "s", fields: [], extra: 1 } };
  assert.match(fields.validateDocument(d).join("; "), /records.E: unknown key "extra"; records.E: name must be "E"/);
  d = base();
  d.edges = [{ id: "e", kind: "k", src: "A", dst: null, basis: "asserted", target_label: "t" }, { id: "e", kind: "k", src: "A", dst: "B", basis: "asserted", target_label: "t" }];
  assert.match(fields.validateDocument(d).join("; "), /edges\[1\]: duplicate id e/);
  d = base();
  d.edges = [{ id: "e", kind: "k", src: "A", dst: 3, basis: "asserted", target_label: "t", spl: "x" }];
  assert.match(fields.validateDocument(d).join("; "), /unknown key "spl".*dst must be a field name or null/);
  assert.throws(() => fields.register("other", base()), /names pack p/);
  fields._reset();
});

test("loadFor fetches the sidecar for a container it lists once, and nothing for a container it does not", async () => {
  fields._reset();
  const fetched = [];
  const inner = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    fetched.push(String(url).replace(/^.*\/app\/packs\//, ""));
    return inner(url, opts);
  };
  try {
    await fields.loadFor("aws:cloudtrail");
    assert.deepEqual(fetched.filter((f) => f.endsWith(".fields.json")), []);
    assert.equal(fields.loaded(), false);
    await Promise.all([fields.loadFor("crowdstrike:events:sensor"), fields.loadFor("crowdstrike:inventory:aidmaster")]);
    assert.deepEqual(fetched.filter((f) => f.endsWith(".fields.json")), ["crowdstrike-falcon.fields.json"]);
    assert.ok(fields.ready("crowdstrike-falcon"));
    assert.equal(fields.field("TargetProcessId").role, "process_id");
    await fields.loadFor("crowdstrike:events:external");
    assert.equal(fetched.filter((f) => f.endsWith(".fields.json")).length, 1, "one fetch for three containers");
    assert.deepEqual(await fields.packsFor("crowdstrike:userinfo"), ["crowdstrike-falcon"]);
    assert.deepEqual(await fields.packsFor("Okta_CL"), []);
  } finally {
    globalThis.fetch = inner;
    fields._reset();
  }
});
