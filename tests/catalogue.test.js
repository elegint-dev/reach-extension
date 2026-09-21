import "./_splunk.js"; // Splunk-only code under test: the FDR bundle, SPL packs
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as store from "../app/lib/store.js";
import * as layer from "../app/lib/layer.js";
import * as catalogue from "../app/lib/catalogue.js";

// node has neither chrome.storage nor localStorage → store.js's memory backend.
assert.equal(store.backend(), "memory");
await catalogue.load();

beforeEach(async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 1, sourcetypes: {} }, { mode: "replace" });
});

test("pack sourcetypes are listed with source 'pack'", () => {
  const sensor = catalogue.sourcetype("crowdstrike:events:sensor");
  assert.ok(sensor);
  assert.deepEqual(sensor.sources, ["pack"]);
  assert.equal(sensor.discriminator, "event_simpleName");
  assert.equal(catalogue.sourcetype("acme:widgets"), null);
});

test("fieldOn merges pack meaning, and a user annotation wins", async () => {
  const before = catalogue.fieldOn("crowdstrike:events:sensor", "IntegrityLevel");
  assert.equal(before.meaning.source, "pack");
  assert.equal(before.scope, "sourcetype");
  assert.equal(before.user, null);

  await catalogue.annotate("crowdstrike:events:sensor", "IntegrityLevel", { description: "Token integrity level; 12288 is HIGH.", tags: ["auth"], sensitivity: "internal" });
  const after = catalogue.fieldOn("crowdstrike:events:sensor", "IntegrityLevel");
  assert.equal(after.meaning.source, "user");
  assert.equal(after.meaning.description, "Token integrity level; 12288 is HIGH.");
  assert.deepEqual(after.taxonomy.tags, ["auth"]);
  assert.equal(after.taxonomy.role, "enum"); // pack role still there
  assert.equal(after.taxonomy.roleSource, "pack");
  assert.ok(after.pack, "pack record still attached");
});

test("an annotation on an uncatalogued sourcetype creates it in the user layer", async () => {
  assert.equal(catalogue.fieldOn("acme:widgets", "widgetName"), null);
  await catalogue.annotate("acme:widgets", "widgetName", { description: "The API call.", role: "enum" });
  const v = catalogue.fieldOn("acme:widgets", "widgetName");
  assert.equal(v.scope, "user");
  assert.equal(v.pack, null);
  assert.equal(v.meaning.source, "user");
  assert.equal(v.taxonomy.roleSource, "user");
  const st = catalogue.sourcetype("acme:widgets");
  assert.deepEqual(st.sources, ["user"]);
  assert.deepEqual(catalogue.fieldsOn("acme:widgets"), ["widgetName"]);
});

test("the CloudTrail collision stays fixed with the user layer present", async () => {
  await catalogue.annotate("aws:cloudtrail", "eventName", { description: "x" });
  // UserName is an FDR field; nothing in the user layer puts it on CloudTrail.
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "UserName"), null);
});

test("clearing every key removes the annotation and an empty sourcetype", async () => {
  await catalogue.annotate("acme:widgets", "widgetName", { description: "x" });
  await catalogue.annotate("acme:widgets", "widgetName", { description: null });
  assert.equal(catalogue.userAnnotation("acme:widgets", "widgetName"), null);
  assert.equal(catalogue.sourcetype("acme:widgets"), null);
});

test("export → import round-trips; merge keeps the newer annotation", async () => {
  // acme:widgets is bound to no concept, so these notes stay keyed (sourcetype, field).
  await catalogue.annotate("acme:widgets", "eventName", { description: "mine" });
  const mine = catalogue.exportUser();
  assert.equal(mine.format, "reach-catalogue");
  assert.equal(mine.version, 2);

  const theirs = JSON.parse(JSON.stringify(mine));
  theirs.sourcetypes["acme:widgets"].fields.eventName = { description: "theirs, newer", updated_at: "2999-01-01T00:00:00Z" };
  theirs.sourcetypes["acme:widgets"].fields.eventSource = { description: "only theirs", updated_at: "2020-01-01T00:00:00Z" };
  theirs.sourcetypes["acme:widgets"].fields.eventID = { description: "theirs, older", updated_at: "2000-01-01T00:00:00Z" };
  await catalogue.annotate("acme:widgets", "eventID", { description: "mine, newer" });

  const r = await catalogue.importUser(theirs, { mode: "merge" });
  assert.deepEqual(r, { added: 1, updated: 1, kept: 1, sourcetypes: 1, concepts: 0, bindings: { added: 0, updated: 0, kept: 0 }, notes: { added: 1, updated: 1, kept: 1 } });
  assert.equal(catalogue.fieldOn("acme:widgets", "eventName").meaning.description, "theirs, newer");
  assert.equal(catalogue.fieldOn("acme:widgets", "eventSource").meaning.description, "only theirs");
  assert.equal(catalogue.fieldOn("acme:widgets", "eventID").meaning.description, "mine, newer");
});

test("import rejects a foreign document", async () => {
  await assert.rejects(() => catalogue.importUser({ hello: 1 }), /Not a Reach catalogue export/);
});

test("a crafted __proto__ sourcetype key in a merge import is dropped, not merged onto Object.prototype", async () => {
  // A JSON STRING, parsed: not an object literal. `{ __proto__: x }` as JS
  // source sets the object's prototype at creation time rather than adding
  // an own property, so JSON.stringify-ing a literal like that would drop
  // the key before it ever reached importUser, masking the very bug this
  // guards against. JSON.parse of real text (how an imported file arrives)
  // has no such special case: "__proto__" comes through as a normal key,
  // and `user.sourcetypes[st] = user.sourcetypes[st] || {fields:{}}` for
  // st === "__proto__" reads/writes the object's actual [[Prototype]]
  // instead: `mine` ends up bound to the real Object.prototype, and every
  // later `mine.fields[f] = …` pollutes it globally.
  const evil = JSON.parse('{"format":"reach-catalogue","version":1,"sourcetypes":{"__proto__":{"fields":{"polluted":{"description":"pwned"}}}}}');
  assert.deepEqual(Object.keys(evil.sourcetypes), ["__proto__"]); // guards the repro itself
  await catalogue.importUser(evil, { mode: "merge" });
  assert.equal(Object.prototype.fields, undefined, "Object.prototype must stay clean");
});

test("a crafted __proto__ field name in a merge import is skipped", async () => {
  const evil = JSON.parse(
    '{"format":"reach-catalogue","version":1,"sourcetypes":{"aws:cloudtrail":{"fields":{' +
      '"__proto__":{"description":"pwned","updated_at":"2999-01-01T00:00:00Z"},' +
      '"eventName":{"description":"fine"}' +
      "}}}}",
  );
  assert.deepEqual(Object.keys(evil.sourcetypes["aws:cloudtrail"].fields), ["__proto__", "eventName"]); // guards the repro
  await catalogue.importUser(evil, { mode: "merge" });
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "eventName").meaning.description, "fine");
});

test("fieldEverywhere lists every sourcetype carrying a name, best-filled first, with what each layer says", async () => {
  await layer.update("https://splunk.example", (env) => {
    env.sourcetypes = {
      "acme:widgets": { indexes: ["main"], count: 10, fields: { user: { profile: { count: 3, fill: 0.03, distinct: 2, sample: 100, top: [], measured_at: "2026-09-17T00:00:00Z", window: "-7d" } } } },
      "acme:gadgets": { indexes: ["main"], count: 10, fields: { user: { profile: { count: 94, fill: 0.94, distinct: 40, sample: 100, top: [], measured_at: "2026-09-17T00:00:00Z", window: "-7d" } } } },
    };
  });
  await catalogue.annotate("acme:notes", "user", { description: "The caller." });
  try {
    const rows = catalogue.fieldEverywhere("user");
    const by = Object.fromEntries(rows.map((r) => [r.sourcetype, r]));
    assert.ok(by["acme:gadgets"] && by["acme:widgets"] && by["acme:notes"], "every layer's sourcetype is present");
    assert.ok(rows.findIndex((r) => r.sourcetype === "acme:gadgets") < rows.findIndex((r) => r.sourcetype === "acme:widgets"), "best fill first");
    assert.equal(rows[rows.length - 1].fill, null, "unmeasured sourcetypes sort last");
    assert.deepEqual(by["acme:gadgets"].sources, ["discovered"]);
    assert.equal(by["acme:gadgets"].fill, 0.94);
    assert.deepEqual(by["acme:notes"].sources, ["user"]);
    assert.equal(by["acme:notes"].described, true);
    assert.equal(by["acme:widgets"].described, false);
    // The FDR bundle's `user` (a CIM field) rides on its pack sourcetypes too.
    assert.ok(rows.some((r) => r.sources.includes("pack")), "pack sourcetypes are included");
    assert.equal(catalogue.fieldEverywhere("no_such_field_anywhere").length, 0);
  } finally {
    await layer.forget("https://splunk.example");
  }
});

test("fieldOn carries the sourcetype's discovered props (INDEXED_EXTRACTIONS, KV_MODE) for efficiency.js's fallback", async () => {
  await layer.update("https://splunk.example", (env) => {
    env.sourcetypes = {
      "acme:widgets": { indexes: ["main"], count: 10, fields: { user: { profile: { count: 3, fill: 0.03, distinct: 2, sample: 100, top: [], measured_at: "2026-09-17T00:00:00Z", window: "-7d" } } }, props: { indexed_extractions: "json", kv_mode: "none" } },
    };
  });
  try {
    const view = catalogue.fieldOn("acme:widgets", "user");
    assert.deepEqual(view.props, { indexed_extractions: "json", kv_mode: "none" });
    assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "aid").props, null, "a sourcetype with no discovered props carries none");
  } finally {
    await layer.forget("https://splunk.example");
  }
});

test("searchIndex spans every layer and is rebuilt after a change", async () => {
  const before = catalogue.searchIndex();
  assert.ok(before.fields.includes("eventName"), "pack field present");
  assert.ok(!before.fields.includes("widgetName"));
  await catalogue.annotate("acme:widgets", "widgetName", { description: "x" });
  const after = catalogue.searchIndex();
  assert.ok(after.fields.includes("widgetName"), "user-layer field appears after annotate");
  assert.ok(after.sourcetypes.includes("acme:widgets"));
  assert.ok(after.events.length > 0, "FDR events carried through");
});
