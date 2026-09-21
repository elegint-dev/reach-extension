// The learned layer on the other platform: a binding confirmed on a custom
// table resolves, refuses where the connector table is bound, and compiles
// the feed's pivots into KQL for the new table.
import "./_sentinel.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as concepts from "../app/lib/concepts.js";
import * as packs from "../app/lib/packs.js";
import * as learned from "../app/lib/learned.js";
import * as catalogue from "../app/lib/catalogue.js";
import { generate } from "../app/lib/pivot.js";
import { PLATFORM } from "../app/lib/platform.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

const TABLE = "AcmeTrail_CL";
const ARN = "aws-cloudtrail/principal_arn";
const SHARED = "aws-cloudtrail/shared_event_id";
const EVENT_NAME = "aws-cloudtrail/event_name";

beforeEach(async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
});

test("a confirmed column on a custom table resolves on Sentinel and the record says sentinel", async () => {
  const rec = await catalogue.bindField(TABLE, "PrincipalArn", ARN);
  assert.equal(rec.platform, "sentinel");
  const v = catalogue.fieldOn(TABLE, "PrincipalArn");
  assert.equal(v.concept.key, ARN);
  assert.equal(v.meaning.description, concepts.concept(ARN).description);
  assert.equal(concepts.resolve("sentinel", TABLE, "PrincipalArn").binding.packId, learned.LEARNED_ID);
  assert.equal(concepts.resolve("splunk", TABLE, "PrincipalArn"), null, "this platform's record only");
  await assert.rejects(() => catalogue.bindField("AWSCloudTrail", "UserIdentityArn", ARN), /already bound by the AWS CloudTrail pack/);
  await assert.rejects(() => catalogue.bindField("ReachCloudTrail_CL", "PrincipalArn", ARN), /already bound by the/);
});

test("the feed's pivot compiles into KQL for the new table once its filter concept is bound", async () => {
  await catalogue.bindField(TABLE, "SharedEventId", SHARED);
  await catalogue.bindField(TABLE, "EventName", EVENT_NAME);
  const shared = catalogue.edgesFrom(TABLE, "SharedEventId").find((e) => e.id === "ct_shared_event");
  assert.ok(shared);
  assert.equal(shared.compiled, true);
  assert.ok(shared.kql && !shared.spl);
  const r = generate(shared, { value: "abc", earliest: "-7d", latest: "now" }, { pack: packs.pack("aws-cloudtrail") });
  assert.equal(r.lang, "kql");
  assert.match(r.spl, /^AcmeTrail_CL/); // pivot.generate keeps the text under .spl whichever language it is
  assert.match(r.spl, /SharedEventId == "abc"/);
  await catalogue.unbindField(TABLE, "SharedEventId");
  assert.deepEqual(catalogue.edgesFrom(TABLE, "SharedEventId"), []);
});

test("bindFields on Sentinel: one write binds several columns of a custom table, a connector-table pair is refused without stopping the rest", async () => {
  const r = await catalogue.bindFields([
    { sourcetype: TABLE, name: "SharedEventId", concept: SHARED, via: "coverage" },
    { sourcetype: TABLE, name: "EventName", concept: EVENT_NAME, via: "coverage" },
    { sourcetype: "AWSCloudTrail", name: "UserIdentityArn", concept: ARN },
  ]);
  assert.equal(r.records.length, 2);
  assert.ok(r.records.every((b) => b.platform === "sentinel" && b.basis === "confirmed"));
  assert.equal(r.errors.length, 1);
  assert.match(r.errors[0], /already bound by the AWS CloudTrail pack/);
  const shared = catalogue.edgesFrom(TABLE, "SharedEventId").find((e) => e.id === "ct_shared_event");
  assert.ok(shared && shared.compiled && shared.kql, "the pivot compiles into KQL from the one write");
});

test("on Sentinel too: a note alone reaches the connector table's column, refusals walk only the sure candidates, and the chip on a learned binding is yours", async () => {
  const { setAsideRows, asideWords, rowsFor, environmentsFor, proposalsFor, vocabularyConcepts } = await import("../app/views/coverage.js");
  const propose = await import("../app/lib/propose.js");
  const { boundChipText } = await import("../app/views/field.js");
  await catalogue.bindField(TABLE, "PrincipalArn", ARN);
  await catalogue.annotate(TABLE, "PrincipalArn", { notes: "written on the custom table" });
  const there = catalogue.fieldOn("AWSCloudTrail", "UserIdentityArn");
  assert.equal(there.meaning.source, "pack");
  assert.equal(there.meaning.notes, "written on the custom table");
  assert.equal(there.meaning.notesSource, "user");
  assert.deepEqual(there.meaning.writtenOn, { platform: "sentinel", container: TABLE, column: "PrincipalArn" });
  assert.equal(catalogue.fieldOn(TABLE, "PrincipalArn").binding.packId, learned.LEARNED_ID);
  assert.equal(boundChipText(catalogue.fieldOn(TABLE, "PrincipalArn"), null), "yours");
  assert.equal(catalogue.noteCount().bindings, 1);

  // A second custom table with a user-ARN column named after the CIM alias:
  // the walk is the alias, then the two acting-principal concepts, then set
  // aside, with nothing ever sure by elimination.
  const prof = (top) => ({ count: 100, distinct: top.length, fill: 0.9, numeric: false, top: top.map((value, i) => ({ value, count: 10 - i })), sample: 100 });
  const WS = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws1";
  const layer = {
    [WS]: {
      resourceId: WS,
      sourcetypes: {
        Copy_CL: {
          fields: {
            EventName: { profile: prof(["ConsoleLogin", "AssumeRole", "GetObject"]) },
            EventSource: { profile: prof(["signin.amazonaws.com", "sts.amazonaws.com", "s3.amazonaws.com"]) },
            UserIdentityArn: { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/bob", "arn:aws:iam::123456789012:user/carol"]) },
            SourceIpAddress: { profile: prof(["10.0.0.1", "10.0.0.2", "203.0.113.9"]) },
            UserAgent: { profile: prof(["aws-cli/2.0", "console.amazonaws.com", "Boto3/1.0"]) },
            RecipientAccountId: { profile: prof(["123456789012", "210987654321", "111111111111"]) },
            user_arn: { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/carol", "arn:aws:iam::123456789012:user/dave"]) },
          },
        },
      },
    },
  };
  const packIds = packs.list().filter((p) => !p.legacy && p.version === 2).map((p) => p.id);
  const vocabulary = propose.vocabulary({ concepts: vocabularyConcepts({ packIds, conceptsOf: concepts.conceptsOf, bindingsOf: concepts.bindingsOf }), learned: [] });
  const labelOf = (k) => concepts.concept(k).label;
  const walk = [];
  for (let i = 0; i < 6; i++) {
    const learnedRecords = catalogue.learnedBindings();
    const env = environmentsFor(layer, { resolve: concepts.resolve, learnedRecords })[0];
    assert.equal(env.platform, "sentinel");
    const container = env.containers.find((c) => c.name === "Copy_CL");
    const { feed, proposals } = proposalsFor(env, container, { vocabulary, learnedRecords });
    assert.equal(feed.packId, "aws-cloudtrail");
    const row = rowsFor(env, container, { proposals, learnedRecords, labelOf }).find((r) => r.column === "user_arn");
    if (!row.proposal) {
      assert.equal(row.state, "dismissed");
      const aside = setAsideRows(learnedRecords, "sentinel", "Copy_CL", proposals);
      assert.equal(aside.length, 1);
      assert.equal(asideWords(aside[0], labelOf), "not CIM user ARN, not CIM user, not Principal ARN");
      break;
    }
    if (i) assert.notEqual(row.proposal.tier, "high");
    walk.push(labelOf(row.proposal.concept));
    const rec = await catalogue.dismissBinding("Copy_CL", "user_arn", row.proposal.concept);
    assert.equal(rec.platform, "sentinel");
  }
  assert.deepEqual(walk, ["CIM user ARN", "CIM user", "Principal ARN"]);
});
