// The learned layer: a binding the user confirms on an unbound table is
// projected into the resolver as the "learned" pack, so the column takes
// meaning, notes and compiled pivots like a pack-bound one, and a pack
// binding the same triple still wins.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as store from "../app/lib/store.js";
import * as concepts from "../app/lib/concepts.js";
import * as packs from "../app/lib/packs.js";
import * as learned from "../app/lib/learned.js";
import * as catalogue from "../app/lib/catalogue.js";
import { generate } from "../app/lib/pivot.js";

assert.equal(store.backend(), "memory");
await catalogue.load();

const ST = "acme:cloudtrail"; // bound by no pack
const ARN = "aws-cloudtrail/principal_arn";
const SHARED = "aws-cloudtrail/shared_event_id";
const EVENT_NAME = "aws-cloudtrail/event_name";
const exists = (key) => Boolean(concepts.concept(key));
const EMPTY = { format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }; // no bindings key: the pre-0.4.53 export

beforeEach(async () => {
  await catalogue.importUser(EMPTY, { mode: "replace" });
});

test("a version-2 layer without bindings normalises, and the learned pack is absent", () => {
  assert.equal(catalogue.USER_VERSION, 2);
  assert.deepEqual(catalogue.userLayer().bindings, []);
  assert.deepEqual(catalogue.learnedBindings(), []);
  assert.equal(packs.pack(learned.LEARNED_ID), null);
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn"), null);
});

test("bindField on an unbound pair: the column resolves to the concept with its meaning, through the learned pack", async () => {
  const rec = await catalogue.bindField(ST, "PrincipalArn", ARN, { evidence: { from: "name", score: 0.95, via: "UserIdentityArn on AWSCloudTrail" }, via: "coverage" });
  assert.equal(rec.basis, "confirmed");
  assert.equal(rec.platform, "splunk");
  assert.equal(rec.concept, ARN);
  assert.ok(rec.confirmed_at);
  assert.equal(rec.imported_at, null);
  assert.equal(rec.via, "coverage");

  const v = catalogue.fieldOn(ST, "PrincipalArn");
  assert.ok(v, "the pair is catalogued now");
  assert.equal(v.concept.key, ARN);
  assert.equal(v.concept.label, "Principal ARN");
  assert.equal(v.meaning.source, "pack");
  assert.equal(v.meaning.description, concepts.concept(ARN).description);
  assert.equal(v.binding.column, "PrincipalArn");
  assert.equal(v.binding.basis, "confirmed");
  assert.match(v.binding.note, /Looks like UserIdentityArn on AWSCloudTrail/);
  assert.equal(v.taxonomy.type, "principal");
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn").binding.packId, learned.LEARNED_ID);
  assert.ok(catalogue.fieldsOn(ST).includes("PrincipalArn"));
  assert.deepEqual(catalogue.bindingFor(ST, "PrincipalArn"), rec);
  assert.equal(catalogue.bindingFor(ST, "nope"), null);
  assert.equal(catalogue.learnedBindings().length, 1);
  assert.ok(!packs.list().some((p) => p.id === learned.LEARNED_ID), "the learned pack is not a feed");
  assert.equal(catalogue.exportUser().bindings.length, 1);
});

test("notes on a learned column attach by concept and show on the pack's own column", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  await catalogue.annotate(ST, "PrincipalArn", { description: "Our platform team's role sessions." });
  const u = catalogue.userLayer();
  assert.ok(u.concepts[ARN]);
  assert.deepEqual(u.concepts[ARN].written_on, { platform: "splunk", container: ST, column: "PrincipalArn" });
  assert.equal(u.sourcetypes[ST], undefined, "nothing under the pair itself");
  const v = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(v.meaning.source, "user");
  assert.equal(v.meaning.description, "Our platform team's role sessions.");
  assert.deepEqual(v.meaning.writtenOn, { platform: "splunk", container: ST, column: "PrincipalArn" });
});

test("a note written on the pair before it was bound moves onto the concept when the user binds it", async () => {
  await catalogue.annotate(ST, "PrincipalArn", { description: "written while unbound", tags: ["ours"] });
  assert.ok(catalogue.userLayer().sourcetypes[ST].fields.PrincipalArn);
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  const u = catalogue.userLayer();
  assert.equal(u.sourcetypes[ST], undefined);
  assert.equal(u.concepts[ARN].description, "written while unbound");
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn").meaning.source, "user");
});

test("edgesFrom compiles the pack's pivots onto the new container once the intent resolves, and forgets them on unbind", async () => {
  assert.deepEqual(catalogue.edgesFrom(ST, "SharedEventId"), []);
  await catalogue.bindField(ST, "SharedEventId", SHARED);
  await catalogue.bindField(ST, "EventName", EVENT_NAME);
  const es = catalogue.edgesFrom(ST, "SharedEventId");
  const shared = es.find((e) => e.id === "ct_shared_event");
  assert.ok(shared, es.map((e) => e.id).join(","));
  assert.equal(shared.compiled, true);
  assert.equal(shared.packId, "aws-cloudtrail");
  assert.deepEqual(shared.src, { sourcetype: ST, field: "SharedEventId" });
  assert.equal(shared.dst.sourcetype, ST);
  const r = generate(shared, { index: "main", value: "abc", earliest: "-7d", latest: "now" }, { pack: packs.pack("aws-cloudtrail") });
  assert.equal(r.lang, "spl");
  assert.match(r.spl, /sourcetype=acme:cloudtrail/);
  assert.match(r.spl, /SharedEventId="abc"/);
  assert.match(r.spl, /EventName/);
  assert.deepEqual(r.missing, []);
  // A pivot whose filter needs a concept this container does not carry is not offered.
  assert.ok(!catalogue.edgesFrom(ST, "SharedEventId").some((e) => e.id === "ct_principal_activity"));
  // The resolved-edge memo is rebuilt after a write.
  await catalogue.unbindField(ST, "SharedEventId");
  assert.deepEqual(catalogue.edgesFrom(ST, "SharedEventId"), []);
  assert.equal(catalogue.fieldOn(ST, "SharedEventId"), null);
  assert.ok(catalogue.fieldOn(ST, "EventName"), "the other binding stands");
});

test("a pair a pack binds refuses, naming the pack; an unknown concept refuses; a bad key refuses", async () => {
  await assert.rejects(() => catalogue.bindField("aws:cloudtrail", "eventName", ARN), /eventName is already bound by the AWS CloudTrail pack/);
  await assert.rejects(() => catalogue.bindField(ST, "x", "aws-cloudtrail/no_such_concept"), /Unknown concept/);
  await assert.rejects(() => catalogue.bindField(ST, "x", "not a key"), /Unknown concept/);
  await assert.rejects(() => catalogue.bindField(ST, "__proto__", ARN), /cannot be bound/);
  assert.deepEqual(catalogue.learnedBindings(), []);
  // Re-confirming the user's own binding to another concept is allowed: one record per triple.
  await catalogue.bindField(ST, "Who", ARN);
  await catalogue.bindField(ST, "Who", "aws-cloudtrail/user_name");
  assert.equal(catalogue.learnedBindings().length, 1);
  assert.equal(catalogue.fieldOn(ST, "Who").concept.key, "aws-cloudtrail/user_name");
});

test("a learned binding never overrides a pack binding on the same triple, whichever registered first", async () => {
  await catalogue.bindField(ST, "Actor", ARN);
  assert.equal(concepts.resolve("splunk", ST, "Actor").binding.packId, learned.LEARNED_ID);
  // A pack that owns its concept, registered after the learned pack.
  packs.register({
    format: "reach-pack",
    version: 2,
    id: "test-acme",
    name: "Acme",
    feed: { id: "acme" },
    concepts: { actor: { label: "Actor", type: "principal", description: "Acme's caller." } },
    bindings: [{ platform: "splunk", container: ST, column: "Actor", concept: "actor" }],
  });
  try {
    assert.equal(concepts.resolve("splunk", ST, "Actor").key, "test-acme/actor");
    assert.equal(catalogue.fieldOn(ST, "Actor").concept.key, "test-acme/actor");
    // A pack that only refers to the concept, registered after the learned pack, still precedes it.
    packs.register({
      format: "reach-pack",
      version: 2,
      id: "test-referrer",
      name: "Referrer",
      feed: { id: "referrer" },
      concepts: {},
      bindings: [{ platform: "splunk", container: ST, column: "Referred", concept: ARN, note: "the pack's note" }],
    });
    await catalogue.bindField(ST, "Other", EVENT_NAME); // a resync with both packs present
    assert.equal(concepts.resolve("splunk", ST, "Actor").key, "test-acme/actor");
    await assert.rejects(() => catalogue.bindField(ST, "Referred", ARN), /already bound by the Referrer pack/);
    // The learned record for Actor is still in the layer, inert on this triple, and the owner's binding is the one every read sees.
    assert.equal(catalogue.bindingFor(ST, "Actor").concept, ARN);
    assert.equal(concepts.bindingsOf("test-acme/actor", "splunk")[0].packId, "test-acme");
    assert.equal(concepts.containersWithColumn("splunk", "Actor").find((h) => h.container === ST).key, "test-acme/actor");
    assert.deepEqual(catalogue.inferSourcetype("Actor", [ST]), { sourcetype: ST, concept: "test-acme/actor", basis: "column" });
    // The same triple, a referrer pack (owns nothing, like the learned pack) registered after the confirm:
    // neither owns the concept, so registration order decides, and the learned pack is always re-indexed last.
    packs.remove("test-acme");
    catalogue.syncLearned(); // the shadowed record left the projection with the resync above; the pack gone, the next sync (load or any write) brings it back
    assert.equal(concepts.resolve("splunk", ST, "Actor").binding.packId, learned.LEARNED_ID);
    packs.register({
      format: "reach-pack",
      version: 2,
      id: "test-late-referrer",
      name: "Late referrer",
      feed: { id: "late" },
      concepts: {},
      bindings: [{ platform: "splunk", container: ST, column: "Actor", concept: ARN, note: "the pack's note" }],
    });
    const late = concepts.resolve("splunk", ST, "Actor");
    assert.equal(late.binding.packId, "test-late-referrer", "a referrer pack registered after a confirm still outranks the learned record");
    assert.equal(late.binding.note, "the pack's note");
    packs.remove("test-late-referrer");
  } finally {
    packs.remove("test-acme");
    packs.remove("test-referrer");
    packs.remove("test-late-referrer");
  }
  catalogue.syncLearned();
  assert.equal(concepts.resolve("splunk", ST, "Actor").binding.packId, learned.LEARNED_ID, "the pack gone, the learned binding is back");
});

test("an inert record (its pack is not loaded) loads without throwing, is kept, and is reported inert", async () => {
  const doc = { ...EMPTY, bindings: [
    { platform: "splunk", container: ST, column: "Thing", concept: "no-such-pack/thing", basis: "confirmed", alias_of: null, confirmed_at: "2026-09-18T10:00:00Z", via: null, imported_at: null, evidence: null },
    { platform: "splunk", container: ST, column: "PrincipalArn", concept: ARN, basis: "confirmed", alias_of: null, confirmed_at: "2026-09-18T10:00:00Z", via: null, imported_at: null, evidence: null },
  ] };
  // The store path: a write from another context (the popup) reaches this resolver through the subscribe handler.
  await store.set(catalogue.USER_KEY, doc);
  const recs = catalogue.learnedBindings();
  assert.equal(recs.length, 2);
  const inert = recs.find((b) => b.column === "Thing");
  assert.equal(learned.isInert(inert, exists), true);
  assert.equal(learned.isInert(recs.find((b) => b.column === "PrincipalArn"), exists), false);
  assert.equal(learned.packOf(inert), "no-such-pack");
  assert.equal(concepts.resolve("splunk", ST, "Thing"), null);
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn").concept.key, ARN, "the live one resolves");
  assert.ok(!packs.pack(learned.LEARNED_ID).bindings.some((b) => b.column === "Thing"), "the inert one is not in the pack");
  assert.equal(packs.validate(packs.pack(learned.LEARNED_ID)).length, 0);
  // The import path keeps it too.
  await catalogue.importUser({ ...doc, format: "reach-catalogue" }, { mode: "replace" });
  assert.equal(catalogue.learnedBindings().length, 2);
  assert.equal(catalogue.exportUser().bindings.length, 2);
});

test("malformed records are dropped on the way in", async () => {
  const doc = { ...EMPTY, bindings: [
    { platform: "splunk", container: "__proto__", column: "x", concept: ARN, basis: "confirmed" },
    { platform: "splunk", container: ST, column: "constructor", concept: ARN, basis: "confirmed" },
    { platform: "mainframe", container: ST, column: "x", concept: ARN, basis: "confirmed" },
    { platform: "splunk", container: ST, column: "x", concept: null, basis: "confirmed" },
    { platform: "splunk", container: ST, column: "x", concept: "principal_arn", basis: "confirmed" },
    { platform: "splunk", container: ST, column: "x", concept: ARN, basis: "guessed" },
    "not a record",
    null,
    { platform: "splunk", container: ST, column: "Ok", concept: ARN, basis: "confirmed", evidence: { via: "x", __proto__x: 1 } },
    { platform: "splunk", container: ST, column: "Alone", concept: null, basis: "dismissed" },
  ] };
  await catalogue.importUser(doc, { mode: "replace" });
  const recs = catalogue.learnedBindings();
  assert.deepEqual(recs.map((b) => b.column).sort(), ["Alone", "Ok"]);
  assert.equal(Object.prototype.fields, undefined);
  assert.equal(catalogue.fieldOn(ST, "Ok").concept.key, ARN);
  assert.equal(catalogue.bindingFor(ST, "Alone").basis, "dismissed");
});

test("export then import merges per triple, newer wins; replace takes theirs whole", async () => {
  await catalogue.bindField(ST, "A", ARN);
  await catalogue.bindField(ST, "C", ARN);
  const mine = catalogue.exportUser();
  assert.equal(mine.version, 2);
  assert.equal(mine.bindings.length, 2);
  const theirs = JSON.parse(JSON.stringify(mine));
  const a = theirs.bindings.find((b) => b.column === "A");
  a.concept = EVENT_NAME;
  a.confirmed_at = "2999-01-01T00:00:00Z"; // newer: theirs wins
  const c = theirs.bindings.find((b) => b.column === "C");
  c.basis = "dismissed";
  c.confirmed_at = "2000-01-01T00:00:00Z"; // older: mine stays
  theirs.bindings.push({ platform: "splunk", container: ST, column: "B", concept: SHARED, basis: "confirmed", alias_of: null, confirmed_at: "2026-01-01T00:00:00Z", via: null, imported_at: null, evidence: null });
  theirs.bindings.push({ platform: "sentinel", container: "AcmeTrail_CL", column: "PrincipalArn", concept: ARN, basis: "confirmed", alias_of: null, confirmed_at: "2026-01-01T00:00:00Z", via: null, imported_at: null, evidence: null });

  const r = await catalogue.importUser(theirs, { mode: "merge" });
  assert.equal(r.added, 2);
  assert.equal(r.updated, 1);
  assert.equal(r.kept, 1);
  assert.equal(catalogue.fieldOn(ST, "A").concept.key, EVENT_NAME);
  assert.ok(catalogue.bindingFor(ST, "A").imported_at, "a record taken from theirs says when it came");
  assert.equal(catalogue.bindingFor(ST, "C").basis, "confirmed");
  assert.equal(catalogue.bindingFor(ST, "C").imported_at, null);
  assert.equal(catalogue.fieldOn(ST, "B").concept.key, SHARED);
  assert.equal(catalogue.learnedBindings().length, 4);
  // The other platform's record is registered too: a note on it would show here, labelled.
  assert.equal(concepts.resolve("sentinel", "AcmeTrail_CL", "PrincipalArn").key, ARN);
  assert.equal(catalogue.bindingFor("AcmeTrail_CL", "PrincipalArn"), null, "bindingFor answers for this platform only");
  assert.equal(catalogue.learnedBindings().filter((b) => b.platform === "sentinel").length, 1);
  // A merge of the same document again changes nothing.
  const again = await catalogue.importUser(theirs, { mode: "merge" });
  assert.equal(again.added + again.updated, 0);
  // Replace takes theirs whole.
  await catalogue.importUser({ ...EMPTY, bindings: [theirs.bindings.find((b) => b.column === "B")] }, { mode: "replace" });
  assert.deepEqual(catalogue.learnedBindings().map((b) => b.column), ["B"]);
  assert.equal(catalogue.fieldOn(ST, "A"), null);
  // Importing a version-2 export without a bindings key keeps what is here.
  await catalogue.importUser(EMPTY, { mode: "merge" });
  assert.deepEqual(catalogue.learnedBindings().map((b) => b.column), ["B"]);
});

test("mergeBindings and learnedPack are pure and do what import relies on", () => {
  const mine = [{ platform: "splunk", container: ST, column: "A", concept: ARN, basis: "confirmed", confirmed_at: "2026-01-02T00:00:00Z" }];
  const theirs = [
    { platform: "splunk", container: ST, column: "A", concept: EVENT_NAME, basis: "confirmed", confirmed_at: "2026-01-01T00:00:00Z" },
    { platform: "splunk", container: ST, column: "B", concept: null, basis: "dismissed", confirmed_at: "2026-01-01T00:00:00Z" },
  ];
  const m = learned.mergeBindings(mine, theirs, { now: "2026-09-18T00:00:00Z" });
  assert.deepEqual({ added: m.added, updated: m.updated, kept: m.kept }, { added: 1, updated: 0, kept: 1 });
  assert.equal(m.list.find((b) => b.column === "A").concept, ARN);
  assert.equal(m.list.find((b) => b.column === "B").imported_at, "2026-09-18T00:00:00Z");
  const pack = learned.learnedPack([...m.list, { platform: "sentinel", container: "T_CL", column: "X", concept: "gone-pack/x", basis: "confirmed" }], { conceptExists: exists });
  assert.equal(pack.id, "learned");
  assert.equal(pack.version, 2);
  assert.deepEqual(pack.concepts, {});
  assert.deepEqual(pack.bindings.map((b) => `${b.platform} ${b.container}/${b.column}`), [`splunk ${ST}/A`], "confirmed and live only");
  assert.equal(pack.bindings[0].basis_ref, "confirmed by the user");
  assert.equal(packs.validate(pack).length, 0);
  assert.equal(packs.validate(learned.learnedPack([], { conceptExists: exists })).length, 0, "an empty pack validates too");
  assert.equal(learned.learnedPack(m.list, { platform: "sentinel", conceptExists: exists }).bindings.length, 0, "platform narrows");
});

test("unbind copies a concept note written on the pair back to the pair; the concept keeps its copy", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  await catalogue.annotate(ST, "PrincipalArn", { description: "Our role sessions.", notes: "Assumed roles mostly.", tags: ["ours"], role: "user_id", sensitivity: "internal", owner: "platform team" });
  await catalogue.unbindField(ST, "PrincipalArn");
  assert.equal(catalogue.bindingFor(ST, "PrincipalArn"), null);
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn"), null);
  const v = catalogue.fieldOn(ST, "PrincipalArn");
  assert.equal(v.concept, null);
  assert.equal(v.scope, "user");
  assert.equal(v.meaning.description, "Our role sessions.");
  assert.equal(v.meaning.notes, "Assumed roles mostly.");
  assert.deepEqual(v.taxonomy, { role: "user_id", roleSource: "user", tags: ["ours"], sensitivity: "internal", owner: "platform team", type: null, typeLabel: null });
  assert.equal(catalogue.userLayer().concepts[ARN].description, "Our role sessions.", "the concept note stays for the columns that still carry it");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn").meaning.description, "Our role sessions.");
  // A note written elsewhere is not copied: it was never this pair's.
  await catalogue.bindField(ST, "Other", ARN);
  await catalogue.unbindField(ST, "Other");
  assert.equal(catalogue.fieldOn(ST, "Other"), null);
  await catalogue.unbindField(ST, "never bound"); // a no-op
});

test("a confirmed record on a triple a pack binds is kept in the layer but left out of the projection: no phantom pivot, no phantom column", async () => {
  const AID = "crowdstrike-falcon/aid";
  const before = catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn").map((e) => `${e.packId}:${e.id}`);
  const columnsBefore = concepts.bindingsOf(AID, "splunk").map((b) => `${b.container}/${b.column}`);
  // bindField refuses the pair; an import (or a write from another context) can still carry it.
  await assert.rejects(() => catalogue.bindField("aws:cloudtrail", "userIdentity.arn", AID), /already bound by the AWS CloudTrail pack/);
  const shadowed = { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn", concept: AID, basis: "confirmed", confirmed_at: "2026-01-01T00:00:00Z" };
  await catalogue.importUser({ ...EMPTY, bindings: [shadowed] }, { mode: "merge" });
  assert.equal(catalogue.bindingFor("aws:cloudtrail", "userIdentity.arn").concept, AID, "the record stays in the layer");
  assert.equal(learned.shadowingPack(catalogue.bindingFor("aws:cloudtrail", "userIdentity.arn"), concepts.resolve), "aws-cloudtrail");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn").concept.key, ARN);
  assert.deepEqual(catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn").map((e) => `${e.packId}:${e.id}`), before, "no Falcon pivot on a CloudTrail column");
  assert.deepEqual(concepts.bindingsOf(AID, "splunk").map((b) => `${b.container}/${b.column}`), columnsBefore, "the Falcon concept does not list the CloudTrail column");
  assert.equal(catalogue.fieldOn("crowdstrike:events:sensor", "aid").concept.bindings.some((b) => b.container === "aws:cloudtrail"), false);
  assert.equal(packs.pack(learned.LEARNED_ID), null, "nothing live: no learned pack at all");
  // The same through the store, as another context would write it.
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  const doc = JSON.parse(JSON.stringify(await store.get(catalogue.USER_KEY)));
  doc.bindings.push({ ...shadowed, column: "eventName", concept: ARN });
  await store.set(catalogue.USER_KEY, doc);
  assert.equal(catalogue.learnedBindings().length, 3);
  assert.deepEqual(packs.pack(learned.LEARNED_ID).bindings.map((b) => b.column), ["PrincipalArn"], "the projection holds the live record only");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "eventName").concept.key, EVENT_NAME);
  // The export still carries it: the coverage view says "now bound by the pack".
  assert.equal(catalogue.exportUser().bindings.length, 3);
});

test("binding a column with a note of its own merges key by key with the concept's note: nothing either side wrote is lost", async () => {
  // The pair note is the newer: its keys win, the concept's other keys stay.
  await catalogue.annotate("aws:cloudtrail", "userIdentity.arn", { description: "concept, older", notes: "pack column note", owner: "sec team" });
  await new Promise((r) => setTimeout(r, 3));
  await catalogue.annotate(ST, "PrincipalArn", { description: "pair, newer" });
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  let c = catalogue.userLayer().concepts[ARN];
  assert.equal(c.description, "pair, newer");
  assert.equal(c.notes, "pack column note");
  assert.equal(c.owner, "sec team");
  assert.deepEqual(c.written_on, { platform: "splunk", container: ST, column: "PrincipalArn" });
  assert.equal(catalogue.userLayer().sourcetypes[ST], undefined, "the pair note moved whole");
  assert.equal(catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn").meaning.notes, "pack column note");
  await catalogue.unbindField(ST, "PrincipalArn");
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn").meaning.description, "pair, newer");
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn").taxonomy.owner, "sec team");

  // The pair note is the older: it fills what the concept lacks, and where it loses it stays under the pair for unbind.
  await catalogue.importUser(EMPTY, { mode: "replace" });
  await catalogue.annotate(ST, "PrincipalArn", { description: "pair, older", tags: ["pair"] });
  await new Promise((r) => setTimeout(r, 3));
  await catalogue.annotate("aws:cloudtrail", "userIdentity.arn", { description: "concept, newer", notes: "written on the pack column" });
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  c = catalogue.userLayer().concepts[ARN];
  assert.equal(c.description, "concept, newer");
  assert.deepEqual(c.tags, ["pair"], "a key the concept lacked came across");
  assert.deepEqual(c.written_on, { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn" });
  assert.equal(catalogue.fieldOn(ST, "PrincipalArn").meaning.description, "concept, newer", "bound: the concept's note shows");
  assert.ok(JSON.stringify(catalogue.userLayer()).includes("pair, older"), "the losing text is still in the layer");
  await catalogue.unbindField(ST, "PrincipalArn");
  const v = catalogue.fieldOn(ST, "PrincipalArn");
  assert.equal(v.meaning.description, "pair, older", "unbound: the column reads as the user wrote it");
  assert.deepEqual(v.taxonomy.tags, ["pair"]);
  assert.equal(catalogue.userLayer().concepts[ARN].description, "concept, newer");
  // Under a pack binding the concept is the note's home and the pair record goes (the version-1 migration rule).
  await catalogue.importUser({ ...EMPTY, sourcetypes: { "aws:cloudtrail": { fields: { "userIdentity.arn": { description: "old pair note", updated_at: "2000-01-01T00:00:00Z" } } } } }, { mode: "merge" });
  assert.equal(catalogue.userLayer().sourcetypes["aws:cloudtrail"], undefined);
});

test("a record without confirmed_at never beats a confirmation, whatever its imported_at says", async () => {
  await catalogue.bindField(ST, "A", ARN);
  const mine = catalogue.bindingFor(ST, "A");
  const r = await catalogue.importUser({ ...EMPTY, bindings: [{ ...mine, concept: EVENT_NAME, confirmed_at: null, imported_at: "2999-01-01T00:00:00Z" }] }, { mode: "merge" });
  assert.deepEqual({ added: r.added, updated: r.updated, kept: r.kept }, { added: 0, updated: 0, kept: 1 });
  assert.equal(catalogue.bindingFor(ST, "A").concept, ARN);
  // Pure: two clocks are never compared; imported_at only breaks a tie on confirmed_at.
  const a = { platform: "splunk", container: ST, column: "X", concept: ARN, basis: "confirmed", confirmed_at: "2026-01-02T00:00:00Z", imported_at: null };
  const later = { ...a, concept: EVENT_NAME, confirmed_at: null, imported_at: "2999-01-01T00:00:00Z" };
  assert.equal(learned.mergeBindings([a], [later]).list[0].concept, ARN);
  assert.equal(learned.mergeBindings([later], [a]).list[0].concept, ARN, "and the other way round the confirmation wins too");
  const tie = { ...a, concept: EVENT_NAME, imported_at: "2026-06-01T00:00:00Z" };
  assert.equal(learned.mergeBindings([a], [tie]).list[0].concept, EVENT_NAME, "same confirmed_at: the later import breaks the tie");
  assert.equal(learned.decidedAt(later), "");
});

test("dismissBinding records not-this-one or leave-alone, and replaces a confirmation", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  const d = await catalogue.dismissBinding(ST, "PrincipalArn", ARN);
  assert.equal(d.basis, "dismissed");
  assert.equal(d.concept, ARN);
  assert.equal(catalogue.learnedBindings().length, 1, "one record per triple");
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn"), null);
  assert.equal(packs.pack(learned.LEARNED_ID), null, "no confirmed record left: the learned pack is gone");
  const alone = await catalogue.dismissBinding(ST, "Noise", null);
  assert.equal(alone.concept, null);
  assert.equal(catalogue.bindingFor(ST, "Noise").basis, "dismissed");
  await assert.rejects(() => catalogue.dismissBinding(ST, "Noise", "not a key"), /not a concept key/);
  // Confirming again replaces the dismissal.
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  assert.equal(catalogue.bindingFor(ST, "PrincipalArn").basis, "confirmed");
  assert.equal(catalogue.learnedBindings().length, 2);
});

test("replace twice leaves one record per triple, and a no-op write does not rebuild", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  const pack = packs.pack(learned.LEARNED_ID);
  packs.replace(pack);
  packs.replace(pack);
  const onPair = concepts.bindingsOf(ARN, "splunk").filter((b) => b.container === ST && b.column === "PrincipalArn");
  assert.equal(onPair.length, 1);
  assert.equal(concepts.containers("splunk").filter((c) => c.name === ST).length, 1);
  assert.deepEqual(concepts.container("splunk", ST).packIds, [learned.LEARNED_ID]);
  // The bundled packs are untouched by the rebuild.
  assert.equal(concepts.resolve("splunk", "aws:cloudtrail", "userIdentity.arn").key, ARN);
  assert.ok(catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn").some((e) => e.id === "ct_principal_activity"));
  // The outside replaces moved packs.generation(), so the next sync projects
  // again; after it, a write that changes no confirmed record leaves the
  // pack object as it was.
  catalogue.syncLearned();
  const resynced = packs.pack(learned.LEARNED_ID);
  assert.notEqual(resynced, pack, "a pack change from outside invalidates the memo");
  await catalogue.annotate("acme:widgets", "w", { description: "unrelated" });
  assert.equal(packs.pack(learned.LEARNED_ID), resynced);
  await catalogue.bindField(ST, "EventName", EVENT_NAME);
  assert.notEqual(packs.pack(learned.LEARNED_ID), pack);
  assert.equal(packs.pack(learned.LEARNED_ID).bindings.length, 2);
  assert.equal(packs.validate(packs.pack(learned.LEARNED_ID)).length, 0);
});

test("the learned container is listed and its discriminator follows the feed", async () => {
  await catalogue.bindField(ST, "EventName", EVENT_NAME);
  const st = catalogue.sourcetype(ST);
  assert.ok(st);
  assert.equal(st.discriminator, "EventName");
  assert.equal(packs.sourcetype(ST).packId, "aws-cloudtrail");
  assert.equal(catalogue.discriminators()[ST], "EventName");
  assert.ok(packs.list().find((p) => p.id === "aws-cloudtrail").sourcetypes.includes(ST));
});

test("bindFields: several confirms land in one write, a refused pair is reported and the rest still land, nothing written when all refuse", async () => {
  let saves = 0;
  const off = catalogue.subscribe(() => saves++);
  try {
    await catalogue.bindField("acme:other", "X", ARN);
    const perSave = saves; // what one write notifies (the memory backend notifies twice per save)
    saves = 0;
    const r = await catalogue.bindFields([
      { sourcetype: ST, name: "PrincipalArn", concept: ARN, evidence: { from: "name", score: 0.95, via: "UserIdentityArn" }, via: "coverage" },
      { sourcetype: ST, name: "EventName", concept: EVENT_NAME, via: "coverage" },
      { sourcetype: "aws:cloudtrail", name: "userIdentity.arn", concept: ARN }, // a pack binds it: refused, not fatal
      { sourcetype: ST, name: "Ghost", concept: "no-such/concept" },
      { sourcetype: "acme:cloudtrail-eu", name: "SharedEventId", concept: SHARED }, // another container in the same write
    ]);
    assert.equal(saves, perSave, "one save for the batch");
    assert.equal(r.records.length, 3);
    assert.deepEqual(r.records.map((b) => b.column), ["PrincipalArn", "EventName", "SharedEventId"]);
    assert.ok(r.records.every((b) => b.basis === "confirmed" && b.platform === "splunk"));
    assert.equal(r.errors.length, 2);
    assert.match(r.errors[0], /already bound by the AWS CloudTrail pack/);
    assert.match(r.errors[1], /Unknown concept/);
    assert.equal(catalogue.learnedBindings().length, 4);
    assert.equal(concepts.resolve("splunk", ST, "PrincipalArn").key, ARN);
    assert.equal(concepts.resolve("splunk", ST, "EventName").key, EVENT_NAME);
    assert.equal(concepts.resolve("splunk", "acme:cloudtrail-eu", "SharedEventId").key, SHARED);
    assert.equal(packs.pack(learned.LEARNED_ID).bindings.length, 4, "one projection holds all three and the earlier one");
    assert.match(catalogue.fieldOn(ST, "PrincipalArn").binding.note, /Looks like UserIdentityArn/);
    // Every pair refused: no write at all.
    const none = await catalogue.bindFields([{ sourcetype: "aws:cloudtrail", name: "eventName", concept: EVENT_NAME }]);
    assert.deepEqual(none.records, []);
    assert.equal(none.errors.length, 1);
    assert.equal(saves, perSave);
    assert.deepEqual(await catalogue.bindFields([]), { records: [], errors: [] });
  } finally {
    off();
  }
});

test("a pack registered, replaced or removed from outside invalidates the learned memo: the next sync puts the projection right", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  const before = packs.generation();
  // Dropped by another caller: nothing in the layer changed, so the memo
  // alone would say there is nothing to do; the generation says otherwise.
  packs.remove(learned.LEARNED_ID);
  assert.ok(packs.generation() > before);
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn"), null);
  await catalogue.annotate("acme:widgets", "w", { description: "unrelated" }); // a write that changes no confirmed record
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn").binding.packId, learned.LEARNED_ID, "the learned pack is back after a no-op write");
  // A pack registered at runtime that binds the triple: the record leaves
  // the projection on the next sync, so bindingsOf lists the pack alone.
  packs.register({
    format: "reach-pack",
    version: 2,
    id: "test-runtime",
    name: "Runtime",
    feed: { id: "runtime" },
    concepts: {},
    bindings: [{ platform: "splunk", container: ST, column: "PrincipalArn", concept: ARN, note: "the pack's note" }],
  });
  try {
    await catalogue.annotate("acme:widgets", "w", { description: "still unrelated" });
    const onPair = concepts.bindingsOf(ARN, "splunk").filter((b) => b.container === ST && b.column === "PrincipalArn");
    assert.deepEqual(onPair.map((b) => b.packId), ["test-runtime"], "the shadowed learned triple is out of the projection");
    assert.equal(packs.pack(learned.LEARNED_ID), null);
    assert.equal(catalogue.bindingFor(ST, "PrincipalArn").concept, ARN, "still in the layer");
  } finally {
    packs.remove("test-runtime");
  }
  catalogue.syncLearned();
  assert.equal(concepts.resolve("splunk", ST, "PrincipalArn").binding.packId, learned.LEARNED_ID);
});

test("the triple and edge keys join on an escaped NUL, not a raw byte in the source: they still separate", async () => {
  const fs = await import("node:fs");
  for (const f of ["app/lib/packs.js", "app/lib/propose.js", "app/lib/learned.js"]) assert.ok(!fs.readFileSync(new URL(`../${f}`, import.meta.url), "utf8").includes("\u0000"), `${f} holds no raw NUL byte`);
  const base = { format: "reach-pack", version: 2, id: "test-sep", name: "Sep", feed: { id: "sep" }, concepts: { c: { label: "C", type: "principal", description: "x" } } };
  // Two bindings whose fields would collide under an empty join ("ab" + "c" versus "a" + "bc") are two triples.
  assert.deepEqual(packs.validate({ ...base, bindings: [{ platform: "splunk", container: "ab", column: "c", concept: "c" }, { platform: "splunk", container: "a", column: "bc", concept: "c" }] }), []);
  assert.ok(packs.validate({ ...base, bindings: [{ platform: "splunk", container: "a", column: "b", concept: "c" }, { platform: "splunk", container: "a", column: "b", concept: "c" }] }).some((e) => /bound twice/.test(e)));
});

test('"not this" accumulates: a second refusal keeps the first, so two candidates cannot take turns', async () => {
  await catalogue.importUser({ ...EMPTY, format: "reach-catalogue" }, { mode: "replace" });
  await catalogue.dismissBinding(ST, "Who", ARN);
  await catalogue.dismissBinding(ST, "Who", "aws-cloudtrail/cim_user");
  const rec = catalogue.bindingFor(ST, "Who");
  assert.equal(rec.basis, "dismissed");
  assert.deepEqual(rec.dismissed.sort(), [ARN, "aws-cloudtrail/cim_user"].sort());
  assert.equal(rec.concept, "aws-cloudtrail/cim_user", "the latest refusal is the record's concept");
  // Setting the pair aside outright keeps the list; the pair stays one record.
  await catalogue.dismissBinding(ST, "Who", null);
  const aside = catalogue.bindingFor(ST, "Who");
  assert.equal(aside.concept, null);
  assert.equal(aside.dismissed.length, 2);
  assert.equal(catalogue.learnedBindings().filter((b) => b.column === "Who").length, 1);
  // Export carries the list; a merge of two dismissals of one pair unions them.
  const merged = learned.normaliseBindings([
    { platform: "splunk", container: ST, column: "W", concept: "a/b", basis: "dismissed", confirmed_at: "2026-01-01T00:00:00Z", dismissed: ["a/b"] },
    { platform: "splunk", container: ST, column: "W", concept: "a/c", basis: "dismissed", confirmed_at: "2026-01-02T00:00:00Z", dismissed: ["a/c"] },
  ]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].dismissed.sort(), ["a/b", "a/c"]);
});

test("a note alone (Notes filled, no Description) shows on the column, rides under the pack's description, and reaches the pack's own column", async () => {
  await catalogue.bindField(ST, "PrincipalArn", ARN);
  await catalogue.annotate(ST, "PrincipalArn", { notes: "Platform team sessions land here; assumed-role ARNs mostly." });
  const u = catalogue.userLayer();
  assert.equal(u.concepts[ARN].notes, "Platform team sessions land here; assumed-role ARNs mostly.");
  assert.equal(u.concepts[ARN].description, undefined, "nothing described, only noted");
  // On the column it was written on: the concept's description stands, the note is yours.
  const here = catalogue.fieldOn(ST, "PrincipalArn");
  assert.equal(here.meaning.source, "pack", "the description is still the pack's");
  assert.match(here.meaning.description, /ARN of the caller/);
  assert.equal(here.meaning.notes, "Platform team sessions land here; assumed-role ARNs mostly.");
  assert.equal(here.meaning.notesSource, "user");
  assert.equal(here.meaning.writtenOn, undefined, "written right here");
  // On the pack's own column: the same note, marked as written elsewhere.
  const there = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(there.meaning.source, "pack");
  assert.equal(there.meaning.notes, "Platform team sessions land here; assumed-role ARNs mostly.");
  assert.equal(there.meaning.notesSource, "user");
  assert.deepEqual(there.meaning.writtenOn, { platform: "splunk", container: ST, column: "PrincipalArn" });
  // A description of yours takes over the whole meaning, as before.
  await catalogue.annotate(ST, "PrincipalArn", { description: "Our role sessions.", notes: "kept" });
  const both = catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn");
  assert.equal(both.meaning.source, "user");
  assert.equal(both.meaning.notes, "kept");
  assert.equal(both.meaning.notesSource, undefined);
  // A note alone on an unbound pair keeps its old slot and still shows.
  await catalogue.annotate(ST, "zz_free", { notes: "free-form" });
  const free = catalogue.fieldOn(ST, "zz_free");
  assert.equal(free.meaning.description, null);
  assert.equal(free.meaning.notes, "free-form");
  assert.equal(free.meaning.notesSource, "user");
});
