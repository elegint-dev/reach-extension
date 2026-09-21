import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { classify, classOf, CLASSES, LABELS, ADVICE, PLATFORM_FIELDS } from "../app/lib/efficiency.js";
import { build, TERM_BARE } from "../app/lib/ladder.js";

const fx = JSON.parse(readFileSync(new URL("./fixtures/efficiency-env.json", import.meta.url), "utf8"));
const splunk = fx.splunk.fields;
const sentinel = fx.sentinel.fields;

const resolve = (fields) => (n) => (fields[n] ? { provenance: fields[n].provenance, profile: fields[n].profile, declared: fields[n].declared } : null);
const cls = (name, extra = {}) => classify({ column: name, platform: "spl", provenance: splunk[name] && splunk[name].provenance, profile: splunk[name] && splunk[name].profile, resolve: resolve(splunk), ...extra });

// The provenance to class table: one row per way a field comes to exist.
const TABLE = [
  ["Image", "search_time", "discovery", /EXTRACT- regex/],
  ["Account_Name", "search_time", "discovery", /REPORT- transform sysmon-account/],
  ["risk_score", "calculated", "discovery", /EVAL.*from EventCode/],
  ["asset_owner", "lookup_output", "discovery", /lookup assets/],
  ["both", "lookup_output", "discovery", /lookup t/],
  ["seen_only", "raw_token", "default", /automatic key=value/],
  ["never_seen", "search_time", "default", /run Provenance/],
];

for (const [name, expected, source, evidence] of TABLE) {
  test(`efficiency: ${name} classifies as ${expected} from ${source}`, () => {
    const c = cls(name);
    assert.equal(c.class, expected);
    assert.equal(c.source, source);
    assert.ok(c.evidence.some((e) => evidence.test(e)), `evidence names the reason: ${c.evidence.join(" / ")}`);
    assert.equal(c.label, LABELS[expected]);
    assert.equal(c.advice, ADVICE.spl[expected]);
  });
}

test("efficiency: the platform's own fields are indexed on both platforms", () => {
  for (const f of PLATFORM_FIELDS.spl) assert.equal(classify({ column: f, platform: "spl" }).class, "indexed", f);
  for (const f of PLATFORM_FIELDS.kql) assert.equal(classify({ column: f, platform: "kql" }).class, "indexed", f);
  assert.equal(classify({ column: "index", platform: "spl", provenance: [{ kind: "calculated" }] }).class, "indexed", "a stanza cannot demote index");
});

test("efficiency: an alias resolves to its source's class, through a chain, and stops on a loop", () => {
  const user = cls("user");
  assert.equal(user.class, "search_time");
  assert.match(user.evidence[0], /alias of Account_Name/);
  assert.match(user.evidence[1], /REPORT- transform/);
  const dest = cls("dest");
  assert.equal(dest.class, "indexed", "dest -> ComputerName -> host");
  assert.equal(dest.evidence.length, 3);
  assert.equal(cls("loop_a").class, "search_time");
});

test("efficiency: the last search-time writer wins (lookup over calculated over alias over extraction)", () => {
  const prov = [{ kind: "extracted", regex: "(?<x>.)" }, { kind: "alias", from: "host" }, { kind: "calculated", statement: "1" }, { kind: "lookup", transform: "t" }];
  assert.equal(classify({ column: "x", platform: "spl", provenance: prov }).class, "lookup_output");
  assert.equal(classify({ column: "x", platform: "spl", provenance: prov.slice(0, 3) }).class, "calculated");
  assert.equal(classify({ column: "x", platform: "spl", provenance: prov.slice(0, 2) }).class, "indexed", "alias of host");
  assert.equal(classify({ column: "x", platform: "spl", provenance: prov.slice(0, 1) }).class, "search_time");
});

test("efficiency: a pack binding's declared provenance stands in when discovery has not run", () => {
  const b = (kind) => classify({ column: "x", platform: "spl", binding: { provenance: { kind, cite: { url: "https://example.com" } } } });
  assert.equal(b("indexed").class, "indexed");
  assert.equal(b("extracted").class, "raw_token");
  assert.equal(b("alias").class, "search_time");
  assert.equal(b("calculated").class, "calculated");
  assert.equal(b("lookup").class, "lookup_output");
  assert.equal(b("connector").class, "indexed");
  assert.equal(b("indexed").source, "pack");
  assert.equal(b("indexed").cite.url, "https://example.com");
  // Discovery outranks the pack's word.
  assert.equal(classify({ column: "x", platform: "spl", binding: { provenance: { kind: "indexed" } }, provenance: [{ kind: "calculated" }] }).class, "calculated");
});

test("efficiency: the props stanza decides between indexed and raw token when no stanza names the field", () => {
  assert.equal(classify({ column: "x", platform: "spl", props: { indexed_extractions: "json" } }).class, "indexed");
  assert.equal(classify({ column: "x", platform: "spl", props: { kv_mode: "json" } }).class, "raw_token");
  assert.equal(classify({ column: "x", platform: "spl", props: { kv_mode: "none" } }).class, "search_time");
  assert.equal(classify({ column: "x", platform: "spl", props: { indexed_extractions: "json" }, provenance: [{ kind: "calculated" }] }).class, "calculated", "a declaring stanza still wins");
});

test("efficiency: the FDR bundle's layer classes a field the pack and discovery do not", () => {
  assert.equal(classify({ column: "x", platform: "spl", layer: "raw_fdr" }).class, "raw_token");
  assert.equal(classify({ column: "x", platform: "spl", layer: "ta_derived" }).class, "calculated");
  assert.equal(classify({ column: "x", platform: "spl", layer: "cim" }).class, "search_time");
});

test("efficiency: Sentinel classes come from the declared type, a dotted column is a dynamic path", () => {
  const k = (name) => classify({ column: name, platform: "kql", declared: sentinel[name] && sentinel[name].declared, profile: sentinel[name] && sentinel[name].profile });
  assert.equal(k("OperationName").class, "indexed");
  assert.equal(k("InitiatedBy").class, "search_time");
  assert.equal(k("InitiatedBy.user.userPrincipalName").class, "search_time");
  assert.match(k("InitiatedBy.user.userPrincipalName").evidence[0], /path into a dynamic column/);
  assert.equal(k("TimeGenerated").class, "indexed");
  assert.equal(k("Unread").class, "indexed");
  assert.equal(k("Unread").source, "default");
  assert.equal(k("OperationName").advice, ADVICE.kql.indexed);
  assert.equal(k("OperationName").termable, false, "TERM() is Splunk's");
});

test("efficiency: a pipeline-derived field is what the caller says it is", () => {
  const c = classify({ column: "x", platform: "spl", derived: true, provenance: [{ kind: "lookup" }] });
  assert.equal(c.class, "pipeline_derived");
});

test("efficiency: every class is one the ladder reads as fieldClass, and only indexed or raw token lets TERM() on", () => {
  const ladderClasses = ["indexed", "raw_token", "search_time", "calculated", "lookup_output", "pipeline_derived"];
  assert.deepEqual([...CLASSES], ladderClasses);
  for (const c of CLASSES) {
    const rungs = build("cmd.exe", { platform: "spl", field: "Image", fieldClass: c });
    const hasTerm = rungs.some((r) => r.construct === "term");
    assert.equal(hasTerm, c === "indexed" || c === "raw_token", `${c}: TERM() ${hasTerm ? "offered" : "withheld"}`);
  }
  assert.ok(TERM_BARE.test("cmd.exe"));
  assert.equal(classify({ column: "seen_only", platform: "spl", profile: {} }).termable, true);
  assert.equal(classify({ column: "x", platform: "spl", provenance: [{ kind: "calculated" }] }).termable, false);
});

test("efficiency: classOf reads a catalogue view and reaches the container's other fields for an alias", () => {
  const view = { name: "dest", provenance: splunk.dest.provenance, binding: null, profile: null, pack: { layer: "raw_fdr" } };
  const c = classOf(view, { platform: "spl", resolve: (n) => (splunk[n] ? { provenance: splunk[n].provenance } : null) });
  assert.equal(c.class, "indexed");
  assert.equal(classOf(null, { platform: "kql" }).class, "indexed");
});
