import "./_splunk.js"; // Splunk-only code under test: the FDR bundle, SPL packs
import "./_bundle.js";
import { test, before } from "node:test";
import assert from "node:assert/strict";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as concepts from "../app/lib/concepts.js";

const PACK = {
  format: "reach-pack",
  version: 2,
  id: "test-feed",
  name: "Test feed",
  pack_version: "0.0.1",
  params: { earliest: { placeholder: "-24h", hint: "index time" } },
  hazards: { h1: { level: "caution", text: "careful" } },
  feed: { id: "test", label: "Test feed", description: "A test feed", tags: ["test"], discriminator: "kind" },
  concepts: {
    actor: { label: "Actor", type: "user_id", description: "Who did it", role: "user_id", tags: ["identity"], sensitivity: "pii" },
    kind: { label: "Kind", type: "enum", description: "What kind of record", role: "enum", decode: { lookup: "test_kinds", meaning_field: "kind_label", values: { "1": "login", "2": "logout" } } },
    user_name: { label: "User name", type: "user_name", description: "NOT FDR's UserName", role: "user_id" },
  },
  containers: { "test:feed": { platform: "splunk", kind: "vendor", description: "A test feed", tags: ["test"] } },
  bindings: [
    { platform: "splunk", container: "test:feed", column: "actor", concept: "actor" },
    { platform: "splunk", container: "test:feed", column: "kind", concept: "kind" },
    { platform: "splunk", container: "test:feed", column: "UserName", concept: "user_name" },
  ],
  edges: [
    {
      id: "t_actor_activity",
      kind: "actor",
      label: "Everything this actor did",
      src: { concept: "actor" },
      dst: { concept: "actor" },
      basis: "confirmed",
      cardinality: "1:n",
      scope: [],
      hazards: ["h1"],
    },
  ],
  templates: [
    { edge: "t_actor_activity", container: "test:feed", spl: { required: ["value", "earliest"], lines: ["search $index$ $sourcetype$ earliest=$earliest:time$ actor=$value$", "| stats count by kind"] } },
  ],
};

before(async () => {
  await catalogue.load();
  packs.register(PACK);
  await catalogue.importUser({ format: "reach-catalogue", version: 1, sourcetypes: {} }, { mode: "replace" });
});

test("validate rejects bad packs with reasons", () => {
  assert.deepEqual(packs.validate({ ...PACK, format: "nope" }).length > 0, true);
  assert.ok(packs.validate({ ...PACK, version: 1 }).some((e) => /version must be 2/.test(e)), "the version-1 shape is not a pack any more");
  assert.ok(packs.validate({ ...PACK, edges: [{ ...PACK.edges[0], basis: "guess" }] }).some((e) => /basis/.test(e)));
  assert.ok(packs.validate({ ...PACK, edges: [{ ...PACK.edges[0], hazards: ["missing"] }] }).some((e) => /unknown hazard/.test(e)));
  assert.ok(packs.validate({ ...PACK, bindings: [...PACK.bindings, { platform: "splunk", container: "test:feed", column: "__proto__", concept: "actor" }] }).some((e) => /column is required/.test(e)));
  assert.throws(() => packs.register({ ...PACK, id: "Bad Id" }), /rejected/);
  // cim is typed: an object with data_models (a CIM field) or targets (a raw field), arrays of names.
  const withCim = (cim) => ({ ...PACK, concepts: { ...PACK.concepts, actor: { ...PACK.concepts.actor, cim } } });
  assert.equal(packs.validate(withCim({ data_models: ["Authentication"], from: ["raw_actor"] })).length, 0);
  assert.equal(packs.validate(withCim({ targets: ["user"] })).length, 0);
  assert.ok(packs.validate(withCim({})).some((e) => /cim needs data_models or targets/.test(e)));
  assert.ok(packs.validate(withCim({ data_models: "Authentication" })).some((e) => /cim.data_models must be an array/.test(e)));
  assert.ok(packs.validate(withCim("Authentication")).some((e) => /cim must be an object/.test(e)));
});

test("list() shows every registered pack, the Falcon pack with its five FDR sourcetypes and six workflows, and no legacy entry", () => {
  const l = packs.list();
  assert.ok(!l.some((p) => p.legacy !== undefined || p.id === "crowdstrike-fdr"));
  const falcon = l.find((p) => p.id === "crowdstrike-falcon");
  assert.deepEqual(falcon.sourcetypes, ["crowdstrike:appinfo", "crowdstrike:events:external", "crowdstrike:events:sensor", "crowdstrike:inventory:aidmaster", "crowdstrike:userinfo"]);
  assert.equal(falcon.workflows, 6);
  const t = l.find((p) => p.id === "test-feed");
  assert.equal(t.fields, 3);
  assert.equal(t.edges, 1);
  assert.deepEqual(t.sourcetypes, ["test:feed"]);
});

test("catalogue: a pack field's meaning, role, tags, decode and discriminator come through", () => {
  const st = catalogue.sourcetype("test:feed");
  assert.deepEqual(st.sources, ["pack"]);
  assert.equal(st.description, "A test feed");
  assert.equal(st.discriminator, "kind");
  assert.equal(st.packId, "test-feed");

  const v = catalogue.fieldOn("test:feed", "actor");
  assert.equal(v.meaning.description, "Who did it");
  assert.equal(v.meaning.source, "pack");
  assert.equal(v.meaning.packId, "test-feed");
  assert.equal(v.taxonomy.role, "user_id");
  assert.deepEqual(v.taxonomy.tags, ["identity"]);
  assert.equal(v.taxonomy.sensitivity, "pii");
  assert.equal(v.scope, "sourcetype");
  assert.equal(v.pack, null);

  assert.deepEqual(catalogue.fieldOn("test:feed", "kind").decode.values, { "1": "login", "2": "logout" });
  assert.equal(catalogue.discriminators()["test:feed"], "kind");
  assert.deepEqual(catalogue.fieldsOn("test:feed"), ["UserName", "actor", "kind"]);
});

test("the same field name on another feed is not the FDR record", () => {
  const v = catalogue.fieldOn("test:feed", "UserName");
  assert.equal(v.meaning.description, "NOT FDR's UserName");
  assert.equal(v.pack, null, "no FDR record leaks across sourcetypes");
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "actor"), null);
});

test("user notes override a pack; clearing them restores the pack", async () => {
  await catalogue.annotate("test:feed", "actor", { description: "mine", role: "identifier" });
  let v = catalogue.fieldOn("test:feed", "actor");
  assert.equal(v.meaning.source, "user");
  assert.equal(v.taxonomy.role, "identifier");
  assert.equal(v.taxonomy.roleSource, "user");
  await catalogue.annotate("test:feed", "actor", { description: null, role: null });
  v = catalogue.fieldOn("test:feed", "actor");
  assert.equal(v.meaning.source, "pack");
  assert.equal(v.taxonomy.role, "user_id");
});

test("edgesFrom returns the pack's edges with the pack id", () => {
  const es = catalogue.edgesFrom("test:feed", "actor");
  assert.equal(es.length, 1);
  assert.equal(es[0].packId, "test-feed");
  assert.deepEqual(catalogue.edgesFrom("test:feed", "kind"), []);
  assert.deepEqual(packs.paramMeta("test-feed", "earliest"), { label: "earliest", placeholder: "-24h", hint: "index time", from_field: null });
});

test("the bundled CloudTrail pack loads, validates, and answers through the catalogue", () => {
  const ct = packs.list().find((p) => p.id === "aws-cloudtrail");
  assert.ok(ct, "aws-cloudtrail is bundled");
  assert.ok(ct.fields >= 80 && ct.edges >= 12, `${ct.fields} concepts, ${ct.edges} edges`);
  assert.equal(ct.version, 2);
  const st = catalogue.sourcetype("aws:cloudtrail");
  assert.ok(st.sources.includes("pack"));
  assert.equal(st.discriminator, "eventName");

  const arn = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(arn.meaning.source, "pack");
  assert.equal(arn.meaning.packId, "aws-cloudtrail");
  assert.equal(arn.taxonomy.role, "user_id");
  const edges = catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn");
  assert.ok(edges.map((e) => e.id).includes("ct_principal_activity"));
  assert.ok(edges.map((e) => e.id).includes("ct_console_logins"));

  // The collision that started the refactor, now with two packs loaded:
  // CloudTrail's userIdentity.userName is CloudTrail's, FDR's UserName is FDR's.
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "userIdentity.userName").meaning.packId, "aws-cloudtrail");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "UserName"), null);
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "userIdentity.userName"), null);

  // CIM both ways: the CIM field names its models and what it is derived
  // from; the raw field names what it lands on.
  const src = catalogue.fieldOn("aws:cloudtrail", "src");
  assert.deepEqual(src.cim, { data_models: ["Change", "Authentication"], from: ["sourceIPAddress"] });
  const sip = catalogue.fieldOn("aws:cloudtrail", "sourceIPAddress");
  assert.deepEqual(sip.cim, { targets: ["src", "src_ip"] });
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "requestID").cim, null);
});

test("every within-feed CloudTrail edge is compiled from its intent on aws:cloudtrail, renders for its own parameters and lints", async () => {
  const { generate } = await import("../app/lib/pivot.js");
  const p = packs.pack("aws-cloudtrail");
  const all = packs.edgesOn("aws:cloudtrail").filter((e) => e.packId === "aws-cloudtrail");
  assert.equal(p.templates.length, 0, "the hand-written SPL was retired once every edge had an intent");
  assert.equal(all.length, p.edges.filter((e) => e.intent).length, "one compiled view per intent");
  assert.ok(all.every((e) => e.compiled && e.spl));
  const within = all.filter((e) => !e.union);
  const cross = all.filter((e) => e.union);
  assert.deepEqual(cross.map((e) => e.id), ["ct_ip_elsewhere"]);
  for (const e of within) {
    const r = generate(e, { index: "main", value: "v", earliest: "-24h", latest: "now", account: "123456789012" }, { pack: p });
    assert.ok(r.spl.startsWith("search index=main sourcetype=aws:cloudtrail earliest=-24h"), `${e.id}: ${r.spl.split("\n")[0]}`);
    assert.deepEqual(r.missing, [], e.id);
    assert.ok(r.spl.includes('"v"'), e.id);
  }
  // The cross-feed view is a union over every sourcetype carrying a
  // source_ip, this one first; every bundled pack that binds one joins it
  // (the exact text over the six core packs is pinned in compile-spl).
  const r = generate(cross[0], { index: "main", value: "203.0.113.9", earliest: "-24h", latest: "now" }, { pack: p });
  const search = r.spl.split("\n")[2];
  assert.ok(search.startsWith('  ((sourcetype=aws:cloudtrail sourceIPAddress="203.0.113.9") OR ('), search);
  for (const clause of ['(sourcetype=azure:aad:signin ipAddress="203.0.113.9")', '(sourcetype=crowdstrike:events:sensor aip="203.0.113.9")', '(sourcetype=gws:reports:login ipAddress="203.0.113.9")', '(sourcetype=OktaIM2:log (src_ip="203.0.113.9" OR client.ipAddress="203.0.113.9"))']) assert.ok(search.includes(clause), clause);
  const sourcetypes = [...search.matchAll(/\(sourcetype=([^ ]+) /g)].map((m) => m[1]);
  assert.deepEqual(sourcetypes, [...new Set(sourcetypes)], "each container once");
  assert.equal(sourcetypes.length, concepts.containersOfType("splunk", "source_ip").length, "one clause per container the type lands on");
  assert.match(r.spl, /\| eval principal=coalesce\('userIdentity.arn', /);
  assert.match(r.spl, /\| table _time sourcetype record_type principal outcome user_agent$/);
  assert.deepEqual(r.missing, []);
});

test("a cross-feed edge validates against the bundled packs alone: a learned binding never changes whether a pack loads", async () => {
  const before = packs.validate(packs.pack("aws-cloudtrail"));
  assert.deepEqual(before, []);
  // A column of the user's own sourcetype bound to source_ip joins the union at render time...
  await catalogue.bindField("acme:widgets", "client_ip", "aws-cloudtrail/source_ip");
  try {
    const view = packs.edgesFrom("aws:cloudtrail", "sourceIPAddress").find((e) => e.id === "ct_ip_elsewhere");
    assert.ok(view.union.includes("acme:widgets"), view.union.join(","));
    // ...and validation still sees the same pack.
    assert.deepEqual(packs.validate(packs.pack("aws-cloudtrail")), []);
    assert.ok(packs.edgesFrom("acme:widgets", "client_ip").some((e) => e.id === "ct_ip_elsewhere" && e.union[0] === "acme:widgets"), "offered from the learned column, leading its own union");
  } finally {
    await catalogue.unbindField("acme:widgets", "client_ip");
  }
  assert.ok(!packs.edgesFrom("aws:cloudtrail", "sourceIPAddress").find((e) => e.id === "ct_ip_elsewhere").union.includes("acme:widgets"));
});

test("a v2 pack's queries validate: ids, containers, a language, known hazards, declared guard names, and a render on every container", () => {
  const falcon = packs.pack("crowdstrike-falcon");
  assert.equal(packs.validate(falcon).length, 0);
  assert.equal(falcon.queries.length, 16);
  const q = falcon.queries.find((x) => x.id === "cs_event_sample");
  // The pack's other queries stay: its workflow names two of them.
  const withQ = (patch) => ({ ...falcon, queries: [...falcon.queries.filter((x) => x.id !== q.id), { ...q, ...patch }] });
  assert.ok(packs.validate(withQ({ id: "Bad Id" })).some((e) => /id must be/.test(e)));
  assert.ok(packs.validate({ ...falcon, queries: [q, q] }).some((e) => /duplicate query id/.test(e)));
  assert.ok(packs.validate(withQ({ containers: [] })).some((e) => /containers must name/.test(e)));
  assert.ok(packs.validate(withQ({ spl: undefined })).some((e) => /spl or kql is required/.test(e)));
  // A query in both languages renders each on its own containers; a KQL block needs a table it can name.
  assert.ok(packs.validate(withQ({ kql: { lines: ["$table$"] } })).some((e) => /cs_event_sample@crowdstrike:events:sensor: /.test(e)));
  assert.deepEqual(packs.validate(withQ({ kql: { containers: ["ReachCrowdStrike_CL"], lines: ["$table$", "| where TimeGenerated > ago(1d)"] } })), []);
  assert.ok(packs.validate(withQ({ kql: { containers: [], lines: ["$table$"] } })).some((e) => /kql.containers must name/.test(e)));
  assert.ok(packs.validate(withQ({ spl: { ...q.spl, hazards: ["no_such"] } })).some((e) => /unknown hazard no_such/.test(e)));
  assert.ok(packs.validate(withQ({ hazards: ["no_such"] })).some((e) => /unknown hazard no_such/.test(e)));
  assert.ok(packs.validate(withQ({ hazards: [{ ref: "no_such", unless: ["aid"] }] })).some((e) => /unknown hazard no_such/.test(e)));
  assert.ok(packs.validate(withQ({ spl: { ...q.spl, guard: { all: ["nope"], code: "g", message: "m" } } })).some((e) => /guard names nope/.test(e)));
  assert.ok(packs.validate(withQ({ spl: { ...q.spl, lines: [...q.spl.lines, "| mvexpand x"] } })).some((e) => /cs_event_sample@crowdstrike:events:sensor: .*mvexpand/.test(e)));
  assert.ok(packs.validate({ ...falcon, queries: "x" }).some((e) => /queries must be an array/.test(e)));
  // The containers a query names need not be bound by the pack; they are
  // where the search runs. The pack declares the inventory sourcetypes with a
  // description, so the catalogue lists them, and its fields sidecar describes them.
  assert.ok(falcon.containers["crowdstrike:appinfo"]);
  assert.match(packs.sourcetype("crowdstrike:appinfo").description, /^Application inventory keyed by SHA256/);
  assert.equal(packs.sourcetype("crowdstrike:appinfo").discriminator, null);
});

test("packs.query shapes a query for pivot.generate with its hazards resolved and their gates kept", () => {
  const q = packs.query("crowdstrike-falcon", "cs_trace");
  assert.equal(q.packId, "crowdstrike-falcon");
  assert.equal(q.basis, "confirmed");
  assert.deepEqual(q.src, { sourcetype: "crowdstrike:events:sensor", field: null });
  assert.deepEqual(q.dst, q.src);
  assert.ok(Array.isArray(q.spl.lines) && q.spl.macro.lines.length === 1);
  const gated = q.hazards.find((h) => h.unless && h.unless.includes("aid"));
  assert.ok(gated && /cs_trace_process scans/.test(gated.text));
  assert.ok(q.hazards.every((h) => typeof h === "object" && h.text));
  assert.equal(packs.query("crowdstrike-falcon", "cs_trace", { container: "crowdstrike:events:external" }), null);
});
