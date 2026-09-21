import "./_splunk.js"; // Splunk-only code under test: the FDR bundle is loaded, SPL templates render
import "./_bundle.js";
import "./_core-packs.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as taxonomy from "../app/lib/taxonomy.js";
import * as concepts from "../app/lib/concepts.js";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";
import { generate } from "../app/lib/pivot.js";

await catalogue.load();

beforeEach(async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
});

const ARN = "aws-cloudtrail/principal_arn";

test("taxonomy: a type carries its label, default role, shape and hazards", () => {
  const t = taxonomy.type("source_ip");
  assert.equal(t.label, "Source address");
  assert.equal(t.role, "ip");
  assert.equal(t.shape, "ip");
  assert.deepEqual(t.hazards.map((h) => h.id), ["nat_vpn"]);
  assert.equal(taxonomy.type("no_such_type"), null);
  assert.ok(taxonomy.types().length > 20);
  assert.ok(taxonomy.validate({ format: "reach-taxonomy", version: 1, types: { a: { label: "A", hazards: ["nope"] } } }).some((e) => /unknown hazard/.test(e)));
});

test("binding resolution both ways: four spellings on two platforms are one concept", () => {
  const splunk = concepts.resolve("splunk", "aws:cloudtrail", "userIdentity.arn");
  assert.equal(splunk.key, ARN);
  assert.equal(splunk.concept.label, "Principal ARN");
  assert.equal(splunk.concept.type, "principal");
  for (const [container, column] of [["AWSCloudTrail", "UserIdentityArn"], ["ReachCloudTrail_CL", "PrincipalArn"], ["ReachCloudTrail_CL", "UserIdentity.arn"]]) {
    const r = concepts.resolve("sentinel", container, column);
    assert.equal(r && r.key, ARN, `${container}/${column}`);
    assert.equal(r.concept.description, splunk.concept.description, "one description for every spelling");
  }
  assert.equal(concepts.resolve("splunk", "aws:cloudtrail", "PrincipalArn"), null, "a Sentinel spelling does not resolve on Splunk");
  const all = concepts.bindingsOf(ARN);
  assert.ok(all.length >= 4);
  assert.equal(all[0].packId, "aws-cloudtrail", "the owning pack's bindings come first");
  assert.deepEqual(concepts.bindingsOf(ARN, "splunk").map((b) => `${b.container}/${b.column}`), ["aws:cloudtrail/userIdentity.arn"]);
});

test("a TA alias is a binding of the raw field's concept, with its own note", () => {
  const raw = concepts.resolve("splunk", "aws:cloudtrail", "sourceIPAddress");
  const alias = concepts.resolve("splunk", "aws:cloudtrail", "src_ip");
  assert.equal(alias.key, raw.key);
  assert.equal(alias.binding.alias_of, "sourceIPAddress");
  assert.match(alias.binding.note, /alias of sourceIPAddress/);
  assert.equal(raw.binding.alias_of, null);
  const v = catalogue.fieldOn("aws:cloudtrail", "src_ip");
  assert.equal(v.binding.alias_of, "sourceIPAddress");
  assert.equal(v.meaning.description, catalogue.fieldOn("aws:cloudtrail", "sourceIPAddress").meaning.description);
  assert.deepEqual(v.cim, { data_models: ["Change", "Authentication"], from: ["sourceIPAddress"] }, "the alias keeps its own CIM slot");
});

test("when two packs bind one column, the pack that owns the concept wins", () => {
  packs.register({
    format: "reach-pack",
    version: 2,
    id: "test-overlay",
    name: "Overlay",
    feed: { id: "overlay" },
    concepts: { thing: { label: "Thing", type: "text", description: "A thing." } },
    bindings: [
      { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn", concept: ARN, note: "overlay says so" },
      { platform: "splunk", container: "aws:cloudtrail", column: "eventName", concept: "thing" },
      { platform: "splunk", container: "acme:widgets", column: "w", concept: "thing" },
    ],
  });
  const r = concepts.resolve("splunk", "aws:cloudtrail", "userIdentity.arn");
  assert.equal(r.binding.packId, "aws-cloudtrail");
  assert.equal(r.binding.note, null);
  // Both own their concept: the first registered stands.
  assert.equal(concepts.resolve("splunk", "aws:cloudtrail", "eventName").key, "aws-cloudtrail/event_name");
  assert.equal(concepts.resolve("splunk", "acme:widgets", "w").key, "test-overlay/thing");
  assert.equal(catalogue.fieldOn("acme:widgets", "w").concept.label, "Thing");
});

test("a pack is validated for structure and every template lints; the version-1 shape is refused", () => {
  const v2 = packs.pack("aws-cloudtrail");
  assert.equal(v2.version, packs.VERSION);
  assert.equal(packs.validate(v2).length, 0);
  const bad = (patch) => packs.validate({ ...v2, ...patch });
  assert.ok(bad({ concepts: { ...v2.concepts, odd: { label: "x", type: "no_such_type" } } }).some((e) => /unknown type/.test(e)));
  assert.ok(bad({ bindings: [...v2.bindings, { platform: "splunk", container: "a", column: "b", concept: "nope" }] }).some((e) => /unknown concept nope/.test(e)));
  assert.ok(bad({ bindings: [...v2.bindings, v2.bindings[0]] }).some((e) => /bound twice/.test(e)));
  assert.ok(bad({ edges: [...v2.edges, { ...v2.edges[0], id: "inline", spl: { lines: ["search x"] } }] }).some((e) => /carries no query/.test(e)));
  assert.ok(bad({ edges: [...v2.edges, { ...v2.edges[0], id: "typed", dst: { type: "no_such_type" } }] }).some((e) => /known concept or a taxonomy type/.test(e)));
  assert.ok(bad({ templates: [...v2.templates, { edge: "ct_principal_activity", container: "aws:cloudtrail", spl: { lines: ["| map search=x"] } }] }).some((e) => /lint|map/.test(e)));
  assert.ok(bad({ templates: [...v2.templates, { edge: "ct_principal_activity", container: "ReachCloudTrail_CL", kql: { lines: ["$table$ | where x == $value$"] } }] }).length === 0, "a KQL template validates on a Splunk build too");
  assert.ok(bad({ templates: [...v2.templates, { edge: "ct_principal_activity", container: "ReachCloudTrail_CL", kql: { lines: ["search *"] } }] }).some((e) => /lint/.test(e)), "and a bad KQL template fails here too");
  assert.ok(packs.validate({ ...v2, version: 1 }).some((e) => /version must be 2/.test(e)), "a version-1 pack is refused, not loaded for one platform");
  for (const id of ["entra-signin", "crowdstrike-falcon", "reach-sentinel-samples"]) assert.equal(packs.validate(packs.pack(id)).length, 0, id);
});

test("catalogue.fieldOn carries the concept and how it lands here", () => {
  const v = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(v.concept.key, ARN);
  assert.equal(v.concept.label, "Principal ARN");
  assert.equal(v.concept.typeLabel, "Principal");
  assert.deepEqual(v.binding, { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn", note: null, alias_of: null, basis: null, packId: "aws-cloudtrail", provenance: null });
  assert.equal(v.taxonomy.type, "principal");
  assert.equal(v.meaning.source, "pack");
  assert.equal(v.meaning.concept, ARN);
  assert.ok(v.concept.bindings.some((b) => b.platform === "sentinel" && b.column === "PrincipalArn"));
  assert.ok(v.concept.hazards.some((h) => /Temporary credentials/.test(h.text)), "the concept's own hazard");
  const ip = catalogue.fieldOn("aws:cloudtrail", "sourceIPAddress");
  assert.ok(ip.concept.hazards.some((h) => h.id === "nat_vpn"), "the type's hazard is inherited");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "no_such_field"), null);
});

test("taxonomy: a signing id is a signer-chosen label, a team id names the certificate, a bitmask is read by mask", () => {
  const sid = taxonomy.type("signing_id");
  assert.equal(sid.label, "Signing identifier");
  assert.equal(sid.role, "identifier");
  assert.deepEqual(sid.hazards.map((h) => h.id), ["signer_chosen"]);
  assert.equal(sid.hazards[0].level, "caution");
  assert.match(sid.hazards[0].text, /certificate chain/);
  const team = taxonomy.type("team_id");
  assert.equal(team.role, "identifier");
  assert.match(team.description, /'-'/);
  assert.deepEqual(team.hazards.map((h) => h.id), ["team_id_is_the_certificate"]);
  const mask = taxonomy.type("bitmask");
  assert.match(mask.description, /by mask, never by equality/);
});

test("Falcon on Splunk: the code-signing columns bind on the sensor sourcetype to typed concepts, observed on the dev pull", () => {
  const sid = catalogue.fieldOn("crowdstrike:events:sensor", "SigningId");
  assert.equal(sid.concept.key, "crowdstrike-falcon/signing_id");
  assert.equal(sid.taxonomy.type, "signing_id");
  assert.equal(sid.binding.basis, "observed");
  assert.ok(sid.concept.hazards.some((h) => h.id === "signer_chosen"), "the pack's own hazard");
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "TeamId").taxonomy.type, "team_id");
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "CodeSigningFlags").taxonomy.type, "bitmask");
  assert.match(catalogue.fieldOn("crowdstrike:events:sensor", "CodeSigningFlags").meaning.description, /CS_PLATFORM_BINARY 0x4000000/);
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "CsValidationCategory").taxonomy.type, "enum");
  // The verdict's other inputs were bound before: the hash and the path.
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "SHA256HashData").taxonomy.type, "file_hash");
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "ImageFileName").taxonomy.type, "file_path");
  // Each new concept binds on exactly one platform: Splunk.
  for (const c of ["signing_id", "team_id", "code_signing_flags", "cs_validation_category"]) {
    const bs = concepts.bindingsOf(`crowdstrike-falcon/${c}`);
    assert.deepEqual(bs.map((b) => [b.platform, b.container]), [["splunk", "crowdstrike:events:sensor"]], c);
  }
});

test("Falcon on Splunk: the feed concept's prose wins, the FDR bundle's record stays attached", () => {
  const v = catalogue.fieldOn("crowdstrike:events:sensor", "aid");
  assert.equal(v.concept.key, "crowdstrike-falcon/aid");
  assert.equal(v.meaning.packId, "crowdstrike-falcon");
  assert.ok(v.pack, "FDR bundle record");
  assert.equal(v.taxonomy.type, "host_id");
  const st = catalogue.sourcetype("crowdstrike:events:sensor");
  assert.deepEqual(st.sources, ["pack"]);
  assert.equal(st.discriminator, "event_simpleName");
});

test("a sourcetype-level note still beats the pack's description, and two packs on one sourcetype list once", async () => {
  await catalogue.annotateSourcetype("aws:cloudtrail", { description: "Our trail.", discriminator: "eventSource" });
  const st = catalogue.sourcetype("aws:cloudtrail");
  assert.equal(st.description, "Our trail.");
  assert.equal(st.discriminator, "eventSource");
  assert.equal(catalogue.discriminators()["aws:cloudtrail"], "eventSource");
  assert.deepEqual(st.sources, ["pack", "user"]);
  await catalogue.annotateSourcetype("aws:cloudtrail", { description: null, discriminator: null });
  assert.match(catalogue.sourcetype("aws:cloudtrail").description, /CloudTrail records/);
  assert.equal(catalogue.sourcetype("aws:cloudtrail").discriminator, "eventName");
});

test("a user note on a bound field is keyed by concept and says where it was written", async () => {
  await catalogue.annotate("aws:cloudtrail", "userIdentity.arn", { description: "Our platform team's role sessions.", tags: ["ours"] });
  const u = catalogue.userLayer();
  assert.ok(u.concepts[ARN]);
  assert.deepEqual(u.concepts[ARN].written_on, { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn" });
  assert.equal(u.sourcetypes["aws:cloudtrail"], undefined, "nothing under the pair itself");
  const v = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(v.meaning.source, "user");
  assert.equal(v.meaning.writtenOn, undefined, "written here: no label");
  assert.deepEqual(catalogue.noteCount(), { notes: 1, sourcetypes: 0, concepts: 1, bindings: 0, setAside: 0 });

  const doc = catalogue.exportUser();
  assert.equal(doc.version, 2);
  assert.ok(doc.concepts[ARN]);
  // Theirs, newer, written on the other platform: it wins and is labelled.
  const theirs = JSON.parse(JSON.stringify(doc));
  theirs.concepts[ARN] = { description: "Written in the portal", updated_at: "2999-01-01T00:00:00Z", written_on: { platform: "sentinel", container: "ReachCloudTrail_CL", column: "PrincipalArn" } };
  const r = await catalogue.importUser(theirs, { mode: "merge" });
  assert.equal(r.updated, 1);
  const after = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(after.meaning.description, "Written in the portal");
  assert.deepEqual(after.meaning.writtenOn, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "PrincipalArn" });
  // The alias spelling sees the same note.
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "src").meaning.source, "pack");
  await catalogue.annotate("aws:cloudtrail", "src_ip", { description: "egress" });
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "sourceIPAddress").meaning.description, "egress");
  // Clearing removes the concept note.
  await catalogue.annotate("aws:cloudtrail", "userIdentity.arn", { description: null, tags: null });
  assert.equal(catalogue.userLayer().concepts[ARN], undefined);
});

test("a version-1 export imports: bound notes land on their concepts, the rest stay by pair", async () => {
  const v1 = {
    format: "reach-catalogue",
    version: 1,
    sourcetypes: {
      "ReachCloudTrail_CL": { fields: { PrincipalArn: { description: "from the portal", updated_at: "2026-01-01T00:00:00Z" } } },
      "acme:widgets": { fields: { unbound_here: { description: "unbound" } } },
    },
  };
  const r = await catalogue.importUser(v1, { mode: "merge" });
  assert.equal(r.concepts, 1);
  assert.equal(r.sourcetypes, 1);
  const v = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(v.meaning.description, "from the portal");
  assert.deepEqual(v.meaning.writtenOn, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "PrincipalArn" });
  assert.equal(catalogue.fieldOn("acme:widgets", "unbound_here").meaning.description, "unbound");
});

test("edges resolve onto the container in hand; a workflow's entries and params follow the bindings", () => {
  const es = catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn");
  assert.ok(es.every((e) => e.spl && e.dst.sourcetype === "aws:cloudtrail"));
  assert.ok(es.map((e) => e.id).includes("ct_principal_failures"));
  assert.equal(es.find((e) => e.id === "ct_principal_failures").dst.field, "errorCode");
  assert.ok(catalogue.edgesFrom("aws:cloudtrail", "src").some((e) => e.id === "ct_source_ip"), "an alias reaches the concept's edges");
  const elsewhere = catalogue.edgesFrom("aws:cloudtrail", "sourceIPAddress").find((e) => e.id === "ct_ip_elsewhere");
  assert.ok(elsewhere && elsewhere.compiled && elsewhere.spl, "the cross-feed pivot compiles here from its scope type intent");
  assert.deepEqual(elsewhere.dst, { sourcetype: "aws:cloudtrail", field: "sourceIPAddress" });
  assert.deepEqual(elsewhere.union, ["aws:cloudtrail", "azure:aad:signin", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"], "the source container leads the union");
  const account = packs.params("aws-cloudtrail", "aws:cloudtrail").account;
  assert.equal(account.from_field, "recipientAccountId");
  assert.match(packs.params("aws-cloudtrail").earliest.hint, /_time/, "Splunk keeps the pack's own words");
  const w = packs.workflow("ct_principal");
  assert.deepEqual(w.entries.map((e) => `${e.sourcetype}/${e.field}`), ["aws:cloudtrail/userIdentity.arn", "aws:cloudtrail/user_arn", "aws:cloudtrail/responseElements.assumedRoleUser.arn"]);
  assert.equal(packs.edge("aws-cloudtrail", "ct_principal_activity").dst.sourcetype, "aws:cloudtrail");
  assert.equal(packs.edge("aws-cloudtrail", "no_such_edge"), null);
});

test("a container with bindings and no template gets the edge's intent compiled into SPL; a hand-written template wins", () => {
  const es = catalogue.edgesFrom("azure:aad:signin", "userPrincipalName");
  const signins = es.find((e) => e.id === "aad_user_signins");
  assert.ok(signins, es.map((e) => e.id).join(","));
  assert.equal(signins.compiled, true);
  assert.ok(signins.spl && Array.isArray(signins.spl.lines));
  assert.equal(signins.kql, undefined);
  assert.deepEqual(signins.dst, { sourcetype: "azure:aad:signin", field: "userPrincipalName" });
  const r = generate(signins, { index: "main", value: "a@b.c", earliest: "-7d" }, { pack: packs.pack("entra-signin") });
  assert.equal(r.lang, "spl");
  assert.ok(r.spl.startsWith("search index=main sourcetype=azure:aad:signin earliest=-7d\n  userPrincipalName=\"a@b.c\""), r.spl);
  assert.match(r.spl, /\| table _time status\.errorCode/);
  assert.deepEqual(r.missing, []);
  // Falcon's FDR sourcetype likewise: no SPL template in the pack, seven compiled pivots.
  const cs = catalogue.edgesFrom("crowdstrike:events:sensor", "aid");
  assert.ok(cs.some((e) => e.id === "cs_host_events" && e.compiled && e.spl));
  const children = packs.edge("crowdstrike-falcon", "cs_process_children");
  assert.equal(children.compiled, true);
  assert.match(generate(children, { index: "main", value: "p", aid: "a", earliest: "-1d" }, { pack: packs.pack("crowdstrike-falcon") }).spl, /event_simpleName="ProcessRollup2" OR event_simpleName="SyntheticProcessRollup2"/);
  // The CloudTrail pack's SPL is compiled too since 0.4.46; a hand-written template, where a pack still writes one, wins for its container.
  const ct = packs.edgesOn("aws:cloudtrail").filter((e) => e.packId === "aws-cloudtrail");
  assert.ok(ct.length >= 16 && ct.every((e) => e.compiled), "every within-feed CloudTrail edge compiled");
  packs.register({
    format: "reach-pack",
    version: 2,
    id: "test-template-wins",
    name: "Template wins",
    feed: { id: "tw" },
    concepts: { who: { label: "Who", type: "principal", description: "Who." }, when: { label: "When", type: "event_time", description: "When." } },
    bindings: [{ platform: "splunk", container: "tw:feed", column: "who", concept: "who" }, { platform: "splunk", container: "tw:feed", column: "_time", concept: "when" }],
    edges: [{ id: "tw_who", kind: "actor", label: "Who did what", src: { concept: "who" }, dst: { concept: "who" }, basis: "confirmed", intent: { filter: [{ concept: "who", op: "eq", value: "$value" }], window: { since: "$earliest" }, shape: { kind: "list", project: ["when"], order: { by: "time", dir: "desc" } } } }],
    templates: [{ edge: "tw_who", container: "tw:feed", spl: { required: ["value", "earliest"], lines: ["search $index$ $sourcetype$ earliest=$earliest:time$ who=$value$", "| table _time who", "| sort - _time"] } }],
  });
  const tw = packs.edgesFrom("tw:feed", "who");
  assert.equal(tw.length, 1);
  assert.equal(tw[0].compiled, undefined, "the hand-written template wins for its container");
  assert.deepEqual(tw[0].spl.lines[1], "| table _time who");
  // A pack whose intent compiles nowhere is rejected at load, with the reason per container.
  const v2 = packs.pack("aws-cloudtrail");
  const orphaned = { ...v2, concepts: { ...v2.concepts, orphan: { label: "Orphan", type: "text", description: "Bound nowhere." } }, edges: v2.edges.map((e) => (e.id === "ct_source_ip" ? { ...e, intent: { ...e.intent, filter: [{ concept: "orphan", op: "eq", value: "$value" }] } } : e)) };
  const errors = packs.validate(orphaned);
  assert.ok(errors.some((e) => /edge ct_source_ip: intent compiles on no container .*aws:cloudtrail: unresolved orphan/.test(e)), errors.join("; "));
  assert.equal(packs.validate(v2).length, 0, "validation leaves the resolver as it found it");
  assert.equal(concepts.resolve("splunk", "aws:cloudtrail", "userIdentity.arn").key, ARN);
});

test("the production tables are known on the other platform without a word of prose repeated", () => {
  const ct = packs.pack("aws-cloudtrail");
  const samples = packs.pack("reach-sentinel-samples");
  assert.equal(Object.keys(samples.concepts).length, 3, "the loader's own three columns");
  assert.ok(samples.bindings.every((b) => b.concept.includes("/") || ["dataset_id", "load_id", "raw_event"].includes(b.concept)));
  assert.ok(ct.bindings.filter((b) => b.container === "AWSCloudTrail").length >= 40);
  assert.ok(packs.pack("entra-signin").bindings.some((b) => b.container === "SigninLogs" && b.column === "IPAddress"));
  assert.ok(packs.pack("entra-signin").bindings.some((b) => b.container === "azure:aad:signin" && b.column === "userPrincipalName"));
  const sig = catalogue.fieldOn("azure:aad:signin", "ipAddress");
  assert.equal(sig.concept.key, "entra-signin/caller_ip");
  assert.equal(sig.taxonomy.type, "source_ip");
});
