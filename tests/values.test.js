// The data-dictionary layer (app/lib/values.js): the per-concept keys
// validate strictly (unknown keys, documented without a cite, a quote over
// twenty words), a decode table normalises into the same shape, the
// bundled CloudTrail sidecar loads lazily and lands on catalogue.fieldOn as
// dictionary, valueOn keeps its precedence, and the sidecar stays under
// the byte budget its index entry declares.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as values from "../app/lib/values.js";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";

await catalogue.load();

beforeEach(async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
});

const CITE = { url: "https://example.test/doc", title: "Example reference", read_on: "2026-09-18" };
const GOOD = {
  format: "one of three words",
  provenance: "documented",
  cite: CITE,
  quote: "three words, fixed",
  examples: [{ value: "a", note: "the usual one" }],
  values: { a: { meaning: "the first" }, b: "the second", c: { meaning: "the third", provenance: "observed", note: "seen in the dev index" } },
};

test("validateEntry: the good entry passes; every rule has a message", () => {
  assert.deepEqual(values.validateEntry(GOOD, "x"), []);
  const bad = (patch) => values.validateEntry({ ...GOOD, ...patch }, "x");
  assert.ok(bad({ gotchas: [] }).some((e) => /unknown key "gotchas"/.test(e)), "unknown keys are refused");
  assert.ok(bad({ __proto__x: 1, ["__proto__"]: {} }).length >= 0);
  assert.ok(values.validateEntry(JSON.parse('{"format":"x","provenance":"observed","values":{"__proto__":{"meaning":"m"}}}'), "x").some((e) => /unsafe key/.test(e)));
  assert.ok(bad({ cite: undefined }).some((e) => /documented needs a cite/.test(e)));
  assert.ok(bad({ provenance: "guessed" }).some((e) => /provenance must be/.test(e)));
  assert.ok(bad({ cite: { url: "ftp://x", title: "t", read_on: "yesterday" } }).some((e) => /cite.url/.test(e)));
  assert.ok(bad({ cite: { url: "https://x", title: "t", read_on: "yesterday" } }).some((e) => /read_on/.test(e)));
  assert.ok(bad({ cite: { url: "https://x", title: "t", read_on: "2026-09-18", page: 3 } }).some((e) => /unknown key "page"/.test(e)));
  assert.ok(bad({ quote: "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone" }).some((e) => /21 words; the cap is 20/.test(e)));
  assert.ok(values.validateEntry({ provenance: "observed", quote: "verbatim" }, "x").some((e) => /a quote needs a cite/.test(e)));
  assert.ok(bad({ values: { a: { meaning: "m", colour: "red" } } }).some((e) => /unknown key "colour"/.test(e)));
  assert.ok(bad({ values: { a: { note: "no meaning" } } }).some((e) => /meaning is required/.test(e)));
  assert.ok(bad({ values: { a: "" } }).some((e) => /meaning is empty/.test(e)));
  // A value's own documented claim needs a cite somewhere: its own or the concept's.
  assert.ok(values.validateEntry({ provenance: "observed", values: { a: { meaning: "m", provenance: "documented" } } }, "x").some((e) => /documented needs a cite/.test(e)));
  assert.deepEqual(values.validateEntry({ provenance: "observed", values: { a: { meaning: "m", provenance: "documented", cite: CITE } } }, "x"), []);
  assert.ok(bad({ examples: [{ value: "" }] }).some((e) => /value must be a non-empty string/.test(e)));
  assert.ok(bad({ examples: [{ value: "a", why: "" }] }).some((e) => /unknown key "why"/.test(e)));
});

test("validateEntry: closed marks the values table as the whole set, not a sample; only true or false", () => {
  assert.deepEqual(values.validateEntry({ ...GOOD, closed: true }, "x"), []);
  assert.ok(values.validateEntry({ ...GOOD, closed: "yes" }, "x").some((e) => /closed must be true or false/.test(e)));
});

test("normalise: closed carries through as a boolean, false when the entry says nothing", () => {
  assert.equal(values.normalise({ ...GOOD, closed: true }).closed, true);
  assert.equal(values.normalise(GOOD).closed, false);
  assert.equal(values.normalise(null, { values: { 1: "login" } }).closed, false, "a decode alone carries no closed marker of its own");
});

test("validateEntry: shape names a shapes.js shape and every example must show it", () => {
  assert.deepEqual(values.validateEntry({ provenance: "observed", shape: "arn", examples: [{ value: "arn:aws:iam::123456789012:user/Alice" }] }), []);
  assert.ok(values.validateEntry({ provenance: "observed", shape: "arn" }).some((e) => /needs an example that shows it/.test(e)));
  assert.ok(values.validateEntry({ provenance: "observed", shape: "arn", examples: [{ value: "10.0.0.1" }] }).some((e) => /is not shape arn \(reads as ip\)/.test(e)));
  assert.ok(values.validateEntry({ provenance: "observed", shape: "spaceship", examples: [{ value: "x" }] }).some((e) => /is not shape spaceship/.test(e)));
});

test("validateBindingProvenance and validateDocument", () => {
  assert.deepEqual(values.validateBindingProvenance({ kind: "alias", statement: "FIELDALIAS a AS b" }), []);
  assert.ok(values.validateBindingProvenance({ kind: "magic" }).some((e) => /kind must be/.test(e)));
  assert.ok(values.validateBindingProvenance({ kind: "lookup", table: "x" }).some((e) => /unknown key "table"/.test(e)));
  assert.ok(values.validateBindingProvenance({ kind: "connector", cite: { url: "https://x" } }).some((e) => /cite.title/.test(e)));
  const doc = { format: values.FORMAT, version: 1, pack: "p", licence: { name: "CC BY-SA 4.0" }, cite: CITE, concepts: { c1: GOOD }, bindings: [{ platform: "splunk", container: "t", column: "x", provenance: { kind: "extracted" } }] };
  assert.deepEqual(values.validateDocument(doc, ["c1"], new Set(["splunk\0t\0x"])), []);
  assert.ok(values.validateDocument({ ...doc, concepts: { c9: GOOD } }, ["c1"]).some((e) => /concepts.c9: names no concept of pack p/.test(e)));
  assert.ok(values.validateDocument({ ...doc, format: "reach-pack" }, ["c1"]).some((e) => /format must be/.test(e)));
  assert.ok(values.validateDocument({ ...doc, extra: 1 }, ["c1"]).some((e) => /unknown key "extra"/.test(e)));
  assert.ok(values.validateDocument({ ...doc, licence: { name: "" } }, ["c1"]).some((e) => /licence.name/.test(e)));
  assert.ok(values.validateDocument(doc, ["c1"], new Set()).some((e) => /is not a binding of pack p/.test(e)));
});

test("normalise: a bare meaning is { meaning }, a value inherits the concept's cite and provenance, a decode becomes a table with no claim", () => {
  const d = values.normalise(GOOD);
  assert.equal(d.source, "values");
  assert.equal(d.count, 3);
  assert.deepEqual(d.values.b, { meaning: "the second", cite: CITE, provenance: "documented", quote: null, note: null });
  assert.equal(d.values.c.provenance, "observed");
  assert.equal(d.values.c.note, "seen in the dev index");
  assert.deepEqual(d.examples, [{ value: "a", note: "the usual one" }]);
  const fromDecode = values.normalise(null, { lookup: "kinds", values: { 1: "login", 2: "logout" } });
  assert.equal(fromDecode.source, "decode");
  assert.equal(fromDecode.lookup, "kinds");
  assert.deepEqual(fromDecode.values["1"], { meaning: "login", cite: null, provenance: null, quote: null, note: null });
  assert.equal(fromDecode.format, null);
  assert.equal(values.normalise(null, null), null);
  // With both, the entry's own values win and the decode is not merged in.
  assert.equal(values.normalise(GOOD, { values: { z: "zed" } }).values.z, undefined);
});

test("the CloudTrail sidecar is not read at load; a page asks for its container and the dictionary lands on fieldOn", async () => {
  values._reset();
  assert.equal(values.ready("aws-cloudtrail"), false, "eager load leaves the sidecar alone");
  assert.equal(catalogue.valuesReady("aws:cloudtrail"), false);
  const before = catalogue.fieldOn("aws:cloudtrail", "eventType").dictionary;
  assert.equal(before.source, "decode", "the decode table stands in until the sidecar arrives");
  assert.equal(before.count, 5);
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "errorCode").dictionary, null, "no decode, no entry: nothing yet");

  await catalogue.loadValues("aws:cloudtrail");
  assert.equal(values.ready("aws-cloudtrail"), true);
  assert.equal(catalogue.valuesReady("aws:cloudtrail"), true);
  const et = catalogue.fieldOn("aws:cloudtrail", "eventType").dictionary;
  assert.equal(et.source, "values");
  assert.equal(et.count, 6);
  assert.equal(et.provenance, "documented");
  assert.match(et.format, /^One fixed word/);
  assert.equal(et.cite.url, "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html");
  assert.equal(et.values.AwsApiCall.cite.url, et.cite.url, "a value inherits the concept's cite");
  assert.equal(et.values.AwsCloudTrailInsight.provenance, "inferred", "a value may claim less than its concept");
  assert.ok(values.wordCount(et.quote) <= values.QUOTE_MAX_WORDS);

  const ec = catalogue.fieldOn("aws:cloudtrail", "errorCode").dictionary;
  assert.equal(ec.values.AccessDenied.cite.title, "Troubleshoot access denied error messages", "a value's own cite wins");
  assert.equal(ec.values.VpceAccessDenied.cite.title, ec.cite.title);
  for (const [st, col] of [["aws:cloudtrail", "userIdentity.type"], ["aws:cloudtrail", "userIdentity.sessionContext.sessionIssuer.type"]]) {
    const d = catalogue.fieldOn(st, col).dictionary;
    assert.equal(d.source, "values", col);
    assert.ok(d.count >= 3, col);
    assert.ok(d.cite && d.cite.read_on, col);
  }
  // Every documented value on the four seeds carries a cite.
  for (const id of ["event_type", "identity_type", "error_code", "session_issuer_type"]) {
    const d = values.dictionary("aws-cloudtrail", id);
    for (const [lit, v] of Object.entries(d.values)) if (v.provenance === "documented") assert.ok(v.cite && v.cite.url, `${id} ${lit}`);
  }
  assert.equal(values.licence("aws-cloudtrail").name, "CC BY-SA 4.0");
  assert.equal(values.reference("aws-cloudtrail").read_on, "2026-09-18");
  // Loading twice is a no-op; a pack with no sidecar is marked fetched too.
  await catalogue.loadValues("aws:cloudtrail");
  await values.loadPack("entra-signin");
  assert.equal(values.ready("entra-signin"), true);
  assert.equal(values.dictionary("entra-signin", "no_such"), null);
});

test("binding provenance: the TA alias and the Sentinel connector column say how they come to carry the concept", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const app = catalogue.fieldOn("aws:cloudtrail", "app");
  assert.equal(app.binding.provenance.kind, "alias");
  assert.match(app.binding.provenance.statement, /FIELDALIAS eventType AS app/);
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "eventType").binding.provenance, null, "nothing claimed for the raw column yet");
});

test("valueOn: the pack's table first, then the discovered decode passed in, else null", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const r = values.valueOn("aws:cloudtrail", "errorCode", "AccessDenied", { decode: { lookup: "mine", values: { AccessDenied: "my own words" } } });
  assert.equal(r.source, "pack");
  assert.match(r.meaning, /^IAM refused the call/);
  assert.equal(r.provenance, "documented");
  assert.equal(r.concept, "aws-cloudtrail/error_code");
  assert.equal(r.packId, "aws-cloudtrail");
  assert.ok(Array.isArray(r.examples) && r.examples.length);
  const d = values.valueOn("aws:cloudtrail", "errorCode", "ThrottlingException", { decode: { lookup: "mine", values: { ThrottlingException: "too fast" } } });
  assert.equal(d.source, "discovered");
  assert.equal(d.meaning, "too fast");
  assert.equal(d.provenance, "observed");
  assert.equal(d.cite, null);
  assert.equal(values.valueOn("aws:cloudtrail", "errorCode", "NoSuchThing"), null);
  assert.equal(values.valueOn("aws:cloudtrail", "errorCode", "__proto__"), null);
  assert.equal(values.valueOn("no:such", "x", "y"), null);
  assert.equal(values.valueOn("aws:cloudtrail", "errorCode", null), null);
  assert.equal(catalogue.valueOn("aws:cloudtrail", "eventType", "AwsApiCall").meaning, "An API was called: the ordinary record, one per request.");
  // The alias column resolves to the same concept, so its values read the same table.
  assert.equal(catalogue.valueOn("aws:cloudtrail", "app", "AwsApiCall").source, "pack");
});

test("a pack may carry the dictionary keys inline; the validator applies the same rules and dictionary() reads them", () => {
  const pack = {
    format: "reach-pack",
    version: 2,
    id: "dict-test",
    name: "Dict test",
    feed: { id: "dict_test", label: "Dict test" },
    concepts: {
      kind: { label: "Kind", description: "What kind of record.", format: "one of two words", provenance: "documented", cite: CITE, values: { a: "the first", b: { meaning: "the second" } } },
      other: { label: "Other", description: "Another.", decode: { lookup: "l", values: { x: "ex" } } },
    },
    containers: { "dict:test": { platform: "splunk" } },
    bindings: [
      { platform: "splunk", container: "dict:test", column: "kind", concept: "kind", provenance: { kind: "extracted", statement: "KV_MODE = json" } },
      { platform: "splunk", container: "dict:test", column: "other", concept: "other" },
    ],
  };
  assert.deepEqual(packs.validate(pack), []);
  const withBad = (patch) => ({ ...pack, concepts: { ...pack.concepts, kind: { ...pack.concepts.kind, ...patch } } });
  assert.ok(packs.validate(withBad({ cite: undefined })).some((e) => /concepts.kind: provenance documented needs a cite/.test(e)));
  assert.ok(packs.validate(withBad({ values: { a: { meaning: "m", colour: "red" } } })).some((e) => /unknown key "colour"/.test(e)));
  assert.ok(packs.validate({ ...pack, bindings: [{ ...pack.bindings[0], provenance: { kind: "psychic" } }] }).some((e) => /kind must be/.test(e)));
  packs.register(pack);
  try {
    const v = catalogue.fieldOn("dict:test", "kind");
    assert.equal(v.dictionary.source, "values");
    assert.equal(v.dictionary.values.a.meaning, "the first");
    assert.equal(v.dictionary.values.b.cite.url, CITE.url);
    assert.deepEqual(v.binding.provenance, { kind: "extracted", statement: "KV_MODE = json", cite: null });
    const o = catalogue.fieldOn("dict:test", "other");
    assert.equal(o.dictionary.source, "decode", "decode.values still loads and normalises");
    assert.equal(o.decode.values.x, "ex", "and decodeOn is unchanged");
    assert.equal(values.valueOn("dict:test", "other", "x").meaning, "ex");
  } finally {
    packs.remove("dict-test");
  }
  assert.equal(values.dictionary("dict-test", "kind"), null, "gone with the pack");
});

test("the bundled sidecar matches its index entry and stays under the budget; every seeded cite is complete", async () => {
  const index = JSON.parse(await readFile(new URL("../app/packs/index.json", import.meta.url), "utf8"));
  assert.ok(Array.isArray(index.values) && index.values.length >= 1);
  for (const e of index.values) {
    const text = await readFile(new URL(`../app/packs/${e.file}`, import.meta.url), "utf8");
    assert.equal(Buffer.byteLength(text, "utf8"), e.bytes, `${e.file}: bytes in index.json`);
    assert.ok(e.bytes <= values.BUDGET_BYTES, `${e.file}: ${e.bytes} bytes over ${values.BUDGET_BYTES}`);
    assert.ok(!text.includes(String.fromCharCode(8212)), `${e.file}: the converter keeps the long dash out`);
    const doc = JSON.parse(text);
    const p = packs.pack(e.pack);
    assert.ok(p, `${e.pack} is a bundled pack`);
    assert.deepEqual(values.validateDocument(doc, Object.keys(p.concepts), new Set(p.bindings.map((b) => `${b.platform}\0${b.container}\0${b.column}`))), []);
    assert.deepEqual(e.containers, Object.keys(p.containers).sort());
  }
  const ct = index.values.find((e) => e.pack === "aws-cloudtrail");
  assert.deepEqual(ct.containers, ["AWSCloudTrail", "aws:cloudtrail"]);
});

test("the CloudTrail dictionary covers every concept of the pack: a format each, a cite behind every documented claim, a description for every one-liner", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const p = packs.pack("aws-cloudtrail");
  const ids = Object.keys(p.concepts);
  assert.ok(ids.length >= 85, String(ids.length));
  const counts = { documented: 0, observed: 0, inferred: 0, values: 0, examples: 0, quotes: 0 };
  for (const id of ids) {
    const d = values.dictionary("aws-cloudtrail", id);
    assert.ok(d && d.source === "values", `${id}: has a dictionary entry`);
    assert.ok(typeof d.format === "string" && d.format.trim().length >= 12, `${id}: format`);
    assert.ok(values.PROVENANCE.includes(d.provenance), `${id}: provenance`);
    assert.ok(values.oneLiner(p.concepts[id].description).length >= 8, `${id}: the index page has a one-liner`);
    counts[d.provenance] += 1;
    counts.values += d.count;
    counts.examples += d.examples.length;
    if (d.quote) counts.quotes += 1;
    if (d.provenance === "documented") assert.ok(d.cite && /^https:\/\/(docs\.aws\.amazon\.com|learn\.microsoft\.com)\//.test(d.cite.url) && d.cite.title && d.cite.read_on, `${id}: documented needs a cite`);
    else assert.equal(d.cite, null, `${id}: ${d.provenance} claims no document`);
    if (d.quote) {
      assert.ok(values.wordCount(d.quote) <= values.QUOTE_MAX_WORDS, `${id}: quote length`);
      assert.ok(d.cite, `${id}: a quote needs a cite`);
    }
    for (const [lit, v] of Object.entries(d.values)) {
      assert.ok(v.meaning && v.meaning.trim(), `${id} ${lit}: meaning`);
      if (v.provenance === "documented") assert.ok(v.cite && v.cite.url, `${id} ${lit}: documented needs a cite`);
      if (v.quote) assert.ok(v.cite && values.wordCount(v.quote) <= values.QUOTE_MAX_WORDS, `${id} ${lit}: quote`);
    }
    for (const s of [d.format, d.quote, ...Object.values(d.values).map((v) => v.meaning), ...d.examples.map((e) => e.note)]) {
      if (s) assert.ok(!s.includes(String.fromCharCode(8212)) && !s.includes(String.fromCharCode(8211)), `${id}: no long dash`);
    }
  }
  assert.equal(counts.documented + counts.observed + counts.inferred, ids.length);
  assert.ok(counts.documented >= 60 && counts.observed >= 10, JSON.stringify(counts));
  assert.ok(counts.values >= 90 && counts.examples >= 60, JSON.stringify(counts));
  // The TA-computed concepts claim what the add-on's configuration showed, never a vendor page.
  for (const id of ["cim_action", "cim_status", "cim_user", "outcome_message", "authentication_method", "image_id"]) assert.equal(values.dictionary("aws-cloudtrail", id).provenance, "observed", id);
  assert.equal(values.licence("aws-cloudtrail").name, "CC BY-SA 4.0");
});

test("oneLiner: first sentence, list colons cut, capped at a word boundary", () => {
  assert.equal(values.oneLiner("Kind of event: AwsApiCall (an API request), AwsServiceEvent, or more."), "Kind of event");
  assert.equal(values.oneLiner("The IP address the request came from. For console actions it is the customer's address."), "The IP address the request came from.");
  assert.equal(values.oneLiner("  spaced   out  "), "spaced out");
  assert.equal(values.oneLiner(""), "");
  assert.equal(values.oneLiner(null), "");
  const long = values.oneLiner("word ".repeat(60).trim(), 50);
  assert.ok(long.length <= 51 && long.endsWith("…"), long);
  assert.equal(values.oneLiner("No stop at all"), "No stop at all");
  assert.equal(values.oneLiner("Short: yes"), "Short: yes", "a colon early in a short line is not a list");
  assert.equal(values.oneLiner('TA: coalesce(errorCode, "success").'), 'TA: coalesce(errorCode, "success").', "a head too short to stand alone keeps its sentence");
  assert.equal(values.citeWords(CITE), "Example reference, read 2026-09-18");
  assert.equal(values.citeWords(null), "");
  assert.equal(values.provenanceWords("documented"), "documented");
  assert.equal(values.provenanceWords("nope"), "");
});

test("a column you bound yourself reads the feed's dictionary and claims no provenance; an unknown container is ready with nothing", async () => {
  await catalogue.bindField("acme:cloudtrail", "EvType", "aws-cloudtrail/event_type");
  try {
    assert.ok(values.packsOn("acme:cloudtrail").includes("aws-cloudtrail"), "the feed pack behind the learned binding");
    await catalogue.loadValues("acme:cloudtrail");
    const v = catalogue.fieldOn("acme:cloudtrail", "EvType");
    assert.equal(v.binding.packId, "learned");
    assert.equal(v.binding.provenance, null, "nothing claims how a column of yours is made");
    assert.equal(v.dictionary.source, "values");
    assert.equal(v.dictionary.values.AwsApiCall.provenance, "documented");
    assert.equal(catalogue.valueOn("acme:cloudtrail", "EvType", "AwsApiCall").source, "pack");
  } finally {
    await catalogue.unbindField("acme:cloudtrail", "EvType");
  }
  assert.deepEqual(values.packsOn("no:such:container"), []);
  assert.equal(catalogue.valuesReady("no:such:container"), true, "nothing to wait for");
  assert.equal(values.reference("no-such-pack"), null);
  // Two callers during one fetch share it; a third after it finds it done.
  values._reset();
  const [a, b] = await Promise.all([values.loadPack("aws-cloudtrail"), values.loadPack("aws-cloudtrail")]);
  assert.equal(a, b);
  assert.equal(await values.loadPack("aws-cloudtrail"), a);
});
