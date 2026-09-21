// The Coverage view's pure helpers (app/views/coverage.js), with no DOM:
// the adapters that turn the stored discovered layer into what
// learned.coverage() and propose.js take, the row state machine, the
// words a row shows, and one pass through the whole render path's
// module chain (environmentsFor -> proposalsFor -> learned.coverage with
// intent.plan -> intentGaps) against the bundled packs and the real
// catalogue, so a wrong module call in the view cannot hide behind the
// helper tests. The last test confirms a binding through catalogue and
// checks the words and states the page would show after it.
import "./_splunk.js";
import "./_bundle.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as store from "../app/lib/store.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as concepts from "../app/lib/concepts.js";
import * as packs from "../app/lib/packs.js";
import * as learned from "../app/lib/learned.js";
import * as propose from "../app/lib/propose.js";
import { plan as intentPlan } from "../app/lib/intent.js";
import * as view from "../app/views/coverage.js";

assert.equal(store.backend(), "memory");
await catalogue.load();

const EMPTY = { format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} };
const WS = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws1";
const ORIGIN = "https://splunk.acme";
const ST = "acme:cloudtrail";
const ST2 = "acme:cloudtrail-eu";

function prof(top, extra = {}) {
  const t = top.map((value, i) => ({ value, count: 10 - i }));
  return { count: 100, distinct: t.length, fill: 0.9, numeric: false, top: t, sample: 100, measured_at: "2026-09-17T09:00:00Z", window: "-7d", ...extra };
}

// A custom CloudTrail sourcetype with Microsoft's documented column names:
// enough distinctive names to elect the feed by votes, an ARN column, an
// address column and one column nothing matches.
function layerFor() {
  return {
    [ORIGIN]: {
      sourcetypes: {
        [ST]: {
          indexes: ["aws"],
          count: 1000,
          profiled_at: "2026-09-17T09:00:00Z",
          fields: {
            EventName: { profile: prof(["ConsoleLogin", "AssumeRole", "GetObject"]) },
            EventSource: { profile: prof(["signin.amazonaws.com", "sts.amazonaws.com", "s3.amazonaws.com"]) },
            UserIdentityArn: { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:sts::123456789012:assumed-role/Admin/bob", "arn:aws:iam::123456789012:user/carol"]) },
            SourceIpAddress: { profile: prof(["10.0.0.1", "10.0.0.2", "203.0.113.9"]) },
            UserAgent: { profile: prof(["aws-cli/2.0", "console.amazonaws.com", "Boto3/1.0"]) },
            RecipientAccountId: { profile: prof(["123456789012", "210987654321", "111111111111"]) },
            SharedEventId: { profile: prof(["7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a01", "7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a02", "7f1c2a2e-1111-4c1b-9b2f-0a0a0a0a0a03"]) },
            zz_custom_note: { profile: prof(["alpha", "beta", "gamma"]) },
          },
          decodes: { EventName: { lookup: "ct_events", values: { ConsoleLogin: "A console sign-in" } } },
        },
        [ST2]: {
          indexes: ["aws-eu"],
          count: 10,
          profiled_at: "2026-09-17T09:00:00Z",
          // Enough CloudTrail names to elect by votes (five, one an anchor:
          // UserIdentityArn is a principal); SourceIpAddress unprofiled.
          fields: {
            EventName: { profile: prof(["ConsoleLogin", "AssumeRole", "PutObject"]) },
            EventSource: { profile: prof(["signin.amazonaws.com", "sts.amazonaws.com", "s3.amazonaws.com"]) },
            UserIdentityArn: { profile: prof(["arn:aws:iam::123456789012:user/dave", "arn:aws:iam::123456789012:user/erin", "arn:aws:iam::123456789012:user/frank"]) },
            SourceIpAddress: { profile: null },
            UserAgent: { profile: prof(["aws-cli/2.0", "console.amazonaws.com", "Boto3/1.0"]) },
            RecipientAccountId: { profile: prof(["123456789012", "210987654321", "111111111111"]) },
          },
        },
      },
      discovered_at: "2026-09-17T09:00:00Z",
    },
    [WS]: {
      resourceId: WS,
      label: "ws1",
      sourcetypes: { CloudTrailCopy_CL: { fields: { EventName: { profile: prof(["ConsoleLogin", "AssumeRole", "GetObject"]) } } } },
    },
  };
}

function build({ layer = layerFor(), forcedFeed = null } = {}) {
  const learnedRecords = catalogue.learnedBindings();
  const environments = view.environmentsFor(layer, { resolve: concepts.resolve, learnedRecords });
  const packIds = packs.list().filter((p) => !p.legacy && p.version === 2).map((p) => p.id);
  const vocabulary = propose.vocabulary({ concepts: view.vocabularyConcepts({ packIds, conceptsOf: concepts.conceptsOf, bindingsOf: concepts.bindingsOf }), learned: learnedRecords.filter((b) => b.basis === "confirmed") });
  const feeds = new Map();
  const proposals = [];
  for (const env of environments) {
    if (env.platform !== "splunk") continue;
    for (const c of env.containers) {
      const r = view.proposalsFor(env, c, { vocabulary, learnedRecords, forcedFeed: c.name === ST ? forcedFeed : null });
      feeds.set(c.name, r.feed);
      proposals.push(...r.proposals);
    }
  }
  const rawPacks = packIds.map((id) => packs.pack(id));
  const cov = learned.coverage({ environments, platform: "splunk", packs: rawPacks, learned: learnedRecords, proposals, plan: intentPlan });
  return { learnedRecords, environments, vocabulary, feeds, proposals, cov };
}

const labelOf = (key) => concepts.concept(key).label;

beforeEach(async () => {
  await catalogue.importUser(EMPTY, { mode: "replace" });
});

// ---------------------------------------------------------------------------
// Adapters

test("envPlatform and envLabel: an ARM resource id is a Sentinel workspace, an origin is a Splunk instance", () => {
  assert.equal(view.envPlatform(ORIGIN, {}), "splunk");
  assert.equal(view.envPlatform(WS, {}), "sentinel");
  assert.equal(view.envPlatform("something", { resourceId: WS }), "sentinel");
  assert.equal(view.envLabel(ORIGIN, {}), ORIGIN);
  assert.equal(view.envLabel(WS, {}), "ws1", "the workspace name, read off the id");
  assert.equal(view.envLabel(WS, { label: "Prod" }), "Prod");
});

test("columnsOf: fields plus decode keys plus extra names, sorted, profile and provenance carried", () => {
  const rec = { fields: { b: { profile: { fill: 1 }, provenance: [{ kind: "alias", from: "a" }] }, a: {} }, decodes: { c: { values: {} } } };
  const cols = view.columnsOf(rec, ["d", null]);
  assert.deepEqual(cols.map((c) => c.column), ["a", "b", "c", "d"]);
  assert.equal(cols[1].profile.fill, 1);
  assert.equal(cols[1].provenance[0].kind, "alias");
  assert.equal(cols[2].profile, null);
  assert.deepEqual(view.columnsOf(null), []);
});

test("environmentsFor: both platforms, concept through the injected resolve, a learned column listed even when unprofiled", () => {
  const resolve = (platform, container, column) => (column === "EventName" ? { key: "aws-cloudtrail/event_name" } : null);
  const learnedRecords = [{ platform: "splunk", container: ST, column: "GhostColumn", concept: "aws-cloudtrail/user_agent", basis: "confirmed" }];
  const envs = view.environmentsFor(layerFor(), { resolve, learnedRecords });
  assert.deepEqual(envs.map((e) => e.platform).sort(), ["sentinel", "splunk"]);
  const splunk = envs.find((e) => e.key === ORIGIN);
  assert.deepEqual(splunk.containers.map((c) => c.name), [ST, ST2]);
  const acme = splunk.containers[0];
  assert.equal(acme.columns.find((c) => c.column === "EventName").concept, "aws-cloudtrail/event_name");
  assert.equal(acme.columns.find((c) => c.column === "UserAgent").concept, null);
  assert.ok(acme.columns.some((c) => c.column === "GhostColumn"), "the learned record's column is a row, so it can be unbound");
  assert.equal(acme.rec.count, 1000, "the raw record rides along for decodes and record types");
  assert.deepEqual(view.environmentsFor({}), []);
});

test("a sourcetype the latest inventory did not return is vanished: out of the default counts, listed only when asked", () => {
  const layer = layerFor();
  layer[ORIGIN].sourcetypes["zzdiag_eval_st"] = { indexes: ["main"], count: 0, missing_since: "2026-09-18T10:00:00Z", fields: { EventName: { profile: prof(["a", "b", "c"]) } } };
  const envs = view.environmentsFor(layer, { resolve: concepts.resolve, learnedRecords: [] });
  const splunk = envs.find((e) => e.key === ORIGIN);
  assert.deepEqual(splunk.containers.map((c) => [c.name, c.vanished]), [[ST, false], [ST2, false], ["zzdiag_eval_st", true]]);
  assert.equal(splunk.containers[2].missingSince, "2026-09-18T10:00:00Z");
  const { live, vanished } = view.partitionVanished(splunk.containers);
  assert.deepEqual(live.map((c) => c.name), [ST, ST2]);
  assert.deepEqual(vanished.map((c) => c.name), ["zzdiag_eval_st"]);
  const shown = view.withoutVanished(envs);
  assert.deepEqual(shown.find((e) => e.key === ORIGIN).containers.map((c) => c.name), [ST, ST2]);
  assert.equal(shown.find((e) => e.key === WS).containers.length, 1, "the other environment is untouched");
  const cov = learned.coverage({ environments: shown, platform: "splunk", packs: packs.list().filter((p) => !p.legacy && p.version === 2).map((p) => packs.pack(p.id)), learned: [], proposals: [], plan: intentPlan });
  assert.equal(view.envStats(cov.environments.find((e) => e.key === ORIGIN)).tables, 2, "the vanished one is not counted");
  assert.deepEqual(view.partitionVanished([]), { live: [], vanished: [] });
});

test("vocabularyConcepts: every concept of the packs with its pack bindings, the learned pack's own left out", async () => {
  await catalogue.bindField(ST, "PrincipalArn", "aws-cloudtrail/principal_arn");
  const list = view.vocabularyConcepts({ packIds: ["aws-cloudtrail"], conceptsOf: concepts.conceptsOf, bindingsOf: concepts.bindingsOf });
  const arn = list.find((c) => c.key === "aws-cloudtrail/principal_arn");
  assert.ok(arn);
  assert.equal(arn.type, "principal");
  assert.ok(arn.bindings.some((b) => b.container === "AWSCloudTrail" && b.column === "UserIdentityArn"));
  assert.ok(arn.bindings.some((b) => b.container === "aws:cloudtrail" && b.column === "userIdentity.arn"));
  assert.ok(!arn.bindings.some((b) => b.container === ST), "the learned binding goes in as `learned`, not as a pack spelling");
  assert.ok(list.length > 50);
});

test("dismissedOn: this platform and container only, concept kept (not this) or null (leave alone)", () => {
  const recs = [
    { platform: "splunk", container: ST, column: "a", concept: "x/y", basis: "dismissed" },
    { platform: "splunk", container: ST, column: "b", concept: null, basis: "dismissed" },
    { platform: "splunk", container: ST, column: "c", concept: "x/y", basis: "confirmed" },
    { platform: "sentinel", container: ST, column: "d", concept: null, basis: "dismissed" },
  ];
  assert.deepEqual(view.dismissedOn(recs, "splunk", ST), [{ column: "a", concept: "x/y" }, { column: "b", concept: null }]);
});

// ---------------------------------------------------------------------------
// The whole chain: election, proposals, coverage, blockers, rows, words

test("proposalsFor elects CloudTrail from names on the custom sourcetype and proposes its columns; nothing on the unmatched one", () => {
  const { feeds, proposals } = build();
  const feed = feeds.get(ST);
  assert.equal(feed.packId, "aws-cloudtrail");
  assert.equal(feed.basis, "names");
  assert.ok(feed.votes["aws-cloudtrail"] >= 3);
  const mine = proposals.filter((p) => p.container === ST);
  assert.ok(mine.every((p) => p.platform === "splunk" && p.container === ST), "tagged for coverage()");
  const arn = mine.find((p) => p.column === "UserIdentityArn");
  assert.ok(arn, "the ARN column is proposed");
  assert.equal(arn.concept, "aws-cloudtrail/principal_arn");
  assert.equal(arn.tier, "high");
  assert.equal(arn.evidence.shape, "arn");
  assert.ok(!mine.some((p) => p.column === "zz_custom_note"), "a name nothing matches is left alone");
  assert.ok(!mine.some((p) => p.column === "EventName" && p.tier !== "high"), "EventName is a sure match when proposed");
});

test("proposalsFor: ?feed= forces a feed on a container the vote did not recognise; a dismissal hides that pair", async () => {
  const layer = layerFor();
  layer[ORIGIN].sourcetypes.mystery = { fields: { UserIdentityArn: { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/bob", "arn:aws:iam::123456789012:user/carol"]) }, note: { profile: prof(["a", "b", "c"]) } } };
  let r = build({ layer });
  assert.equal(r.feeds.get("mystery").packId, null, "one matching name is not a feed");
  assert.equal(r.proposals.filter((p) => p.container === "mystery").length, 0);

  const envs = view.environmentsFor(layer, { resolve: concepts.resolve, learnedRecords: [] });
  const env = envs.find((e) => e.key === ORIGIN);
  const mystery = env.containers.find((c) => c.name === "mystery");
  const forced = view.proposalsFor(env, mystery, { vocabulary: r.vocabulary, learnedRecords: [], forcedFeed: "aws-cloudtrail" });
  assert.equal(forced.feed.packId, "aws-cloudtrail");
  assert.equal(forced.feed.basis, "forced");
  assert.ok(forced.proposals.some((p) => p.column === "UserIdentityArn" && p.concept === "aws-cloudtrail/principal_arn"));

  await catalogue.dismissBinding("mystery", "UserIdentityArn", "aws-cloudtrail/principal_arn");
  const after = view.proposalsFor(env, mystery, { vocabulary: r.vocabulary, learnedRecords: catalogue.learnedBindings(), forcedFeed: "aws-cloudtrail" });
  assert.ok(!after.proposals.some((p) => p.column === "UserIdentityArn" && p.concept === "aws-cloudtrail/principal_arn"), "not this one: the pair is skipped");
});

test("coverage through the real plan: the custom sourcetype's blockers name the concepts its pivots wait on, and intentGaps reads them out", () => {
  const { cov } = build();
  const env = cov.environments.find((e) => e.key === ORIGIN);
  assert.equal(env.thisPlatform, true);
  const acme = env.containers.find((c) => c.name === ST);
  assert.equal(acme.feedPackId, "aws-cloudtrail", "elected through its proposals, nothing bound yet");
  assert.equal(acme.counts.bound, 0);
  assert.ok(acme.counts.proposed >= 3);
  assert.ok(acme.blockers.length > 0, "nothing is bound, so every CloudTrail pivot here is blocked");
  const sentence = learned.intentGaps(acme);
  assert.match(sentence, /^AWS CloudTrail pivots here still need /);
  assert.match(sentence, /Principal ARN \(proposal: UserIdentityArn, sure\)/);
  const feed = env.feeds.find((f) => f.packId === "aws-cloudtrail");
  assert.ok(feed.proposed >= 3);
  assert.ok(feed.gaps > 0);
  const stats = view.envStats(env);
  assert.equal(stats.tables, 2);
  assert.equal(stats.proposed, feed.proposed);
  assert.equal(stats.carried + stats.proposed + stats.gaps, stats.concepts);
  const other = cov.environments.find((e) => e.key === WS);
  assert.equal(other.thisPlatform, false, "the workspace is listed, read only");
});

test("rowsFor: states, fill, looks like, why and unblocks for the table screen", () => {
  const { environments, proposals, learnedRecords, cov } = build();
  const env = environments.find((e) => e.key === ORIGIN);
  const container = env.containers.find((c) => c.name === ST);
  const acme = cov.environments.find((e) => e.key === ORIGIN).containers.find((c) => c.name === ST);
  const rows = view.rowsFor(env, container, { proposals: proposals.filter((p) => p.container === ST), learnedRecords, labelOf, blockers: acme.blockers });
  const byCol = Object.fromEntries(rows.map((r) => [r.column, r]));
  assert.equal(byCol.UserIdentityArn.state, "proposed");
  assert.equal(byCol.UserIdentityArn.label, "Principal ARN");
  assert.equal(byCol.UserIdentityArn.looksLike, "ARN");
  assert.equal(byCol.UserIdentityArn.fill, 0.9);
  assert.ok(byCol.UserIdentityArn.unblocks.length > 0, "confirming the ARN unblocks a pivot");
  assert.equal(byCol.SourceIpAddress.looksLike, "IP");
  assert.equal(byCol.zz_custom_note.state, "unbound");
  assert.equal(byCol.zz_custom_note.concept, null);
  assert.equal(byCol.zz_custom_note.looksLike, null);
  const why = view.whyLine(byCol.UserIdentityArn.proposal, { unblocks: byCol.UserIdentityArn.unblocks });
  assert.match(why, /^name matches (UserIdentityArn|userIdentity\.arn|UserIdentity\.arn)/, "one of the pack's spellings for the concept");
  assert.match(why, /3 of 3 top values look like ARNs/, "distinct top values, the list a reader can check, not the count-weighted sum");
  assert.match(why, /unblocks \d+ pivots?$/);
  assert.equal(rows.every((r) => r.id === r.column), true, "the row id is the column, what ?sel= carries");
});

test("confirmAllDisabled: off on a feed recognised from names alone, on once bindings elect it and a sure match remains", async () => {
  let r = build();
  assert.equal(view.confirmAllDisabled(r.feeds.get(ST), r.proposals.filter((p) => p.container === ST)), true, "elected by names: one by one");
  assert.equal(view.confirmAllDisabled({ packId: null, basis: null }, []), true);
  assert.equal(view.confirmAllDisabled({ packId: "x", basis: "bindings" }, [{ tier: "several" }]), true, "no sure match to confirm");
  assert.equal(view.confirmAllDisabled({ packId: "x", basis: "bindings" }, [{ tier: "high" }]), false);
  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  r = build();
  assert.equal(r.feeds.get(ST).basis, "bindings");
  assert.equal(view.confirmAllDisabled(r.feeds.get(ST), r.proposals.filter((p) => p.container === ST)), false);
});

test("after a confirm: the row is yours, the result and blocker lines read as the page shows them, the sibling offer finds the same column elsewhere", async () => {
  let r = build();
  const before = learned.intentGaps(r.cov.environments.find((e) => e.key === ORIGIN).containers.find((c) => c.name === ST));
  assert.match(before, /Principal ARN \(proposal: UserIdentityArn, sure\)/);

  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn", { evidence: { from: "name", score: 0.95, via: "UserIdentityArn" }, via: "coverage" });
  r = build();
  const env = r.environments.find((e) => e.key === ORIGIN);
  const container = env.containers.find((c) => c.name === ST);
  const acme = r.cov.environments.find((e) => e.key === ORIGIN).containers.find((c) => c.name === ST);
  assert.equal(acme.counts.yours, 1);
  assert.equal(acme.counts.bound, 1);
  const rows = view.rowsFor(env, container, { proposals: r.proposals.filter((p) => p.container === ST), learnedRecords: r.learnedRecords, labelOf, blockers: acme.blockers });
  const row = rows.find((x) => x.column === "UserIdentityArn");
  assert.equal(row.state, "yours");
  assert.equal(row.packId, "aws-cloudtrail");
  assert.equal(row.record.basis, "confirmed");
  assert.ok(!r.proposals.some((p) => p.container === ST && p.column === "UserIdentityArn"), "nothing is proposed over a binding");

  assert.equal(view.resultLine("UserIdentityArn", "Principal ARN"), "Bound UserIdentityArn to Principal ARN.");
  const line = view.blockerLine(acme);
  assert.match(line, /^No pivot yet: AWS CloudTrail pivots here still need /);
  assert.ok(!line.includes("Principal ARN"), "the concept just bound is no longer missing");
  assert.equal(view.blockerLine({ blockers: [] }), "Notes on this column now show on every SIEM.");

  const feedOf = (name) => (r.feeds.get(name) || {}).packId || null;
  assert.equal(feedOf(ST2), "aws-cloudtrail", "the fixture's second sourcetype elects CloudTrail by names");
  const offers = view.siblingOffers(env, ST, "UserIdentityArn", "aws-cloudtrail/principal_arn", { learnedRecords: r.learnedRecords, conceptType: "principal", feedOf });
  assert.deepEqual(offers, [{ container: ST2, column: "UserIdentityArn", profiled: true, agrees: true, checked: true }]);
  const ipOffers = view.siblingOffers(env, ST, "SourceIpAddress", "aws-cloudtrail/source_ip", { learnedRecords: r.learnedRecords, conceptType: "source_ip", feedOf });
  assert.deepEqual(ipOffers, [{ container: ST2, column: "SourceIpAddress", profiled: false, agrees: null, checked: false }], "an unprofiled sibling is offered unchecked");

  await catalogue.unbindField(ST, "UserIdentityArn");
  r = build();
  const undone = r.cov.environments.find((e) => e.key === ORIGIN).containers.find((c) => c.name === ST);
  assert.equal(undone.counts.yours, 0, "undo drops the record");
});

test("siblingOffers: a sibling whose values disagree is offered unchecked, a dismissed one is not offered, a bound one is not offered", () => {
  const env = {
    key: ORIGIN,
    platform: "splunk",
    containers: [
      { name: "a", columns: [{ column: "UserIdentityArn", concept: null, profile: prof(["arn:aws:iam::1:user/x", "arn:aws:iam::1:user/y", "arn:aws:iam::1:user/z"]) }] },
      { name: "b", columns: [{ column: "user_identity_arn", concept: null, profile: prof(["10.0.0.1", "10.0.0.2", "10.0.0.3"]) }] },
      { name: "c", columns: [{ column: "UserIdentityArn", concept: "aws-cloudtrail/principal_arn", profile: null }] },
      { name: "d", columns: [{ column: "UserIdentityArn", concept: null, profile: null }] },
      { name: "e", columns: [{ column: "Other", concept: null, profile: null }] },
    ],
  };
  const learnedRecords = [{ platform: "splunk", container: "d", column: "UserIdentityArn", concept: null, basis: "dismissed" }];
  const feedOf = () => "aws-cloudtrail";
  const offers = view.siblingOffers(env, "a", "UserIdentityArn", "aws-cloudtrail/principal_arn", { learnedRecords, conceptType: "principal", feedOf });
  assert.deepEqual(offers, [{ container: "b", column: "user_identity_arn", profiled: true, agrees: false, checked: false }]);
});

test("siblingOffers passes the feed gate: a table the election did not recognise, or elected to another feed, is never offered; no feedOf, no offers", () => {
  const arns = prof(["arn:aws:iam::1:user/x", "arn:aws:iam::1:user/y", "arn:aws:iam::1:user/z"]);
  const env = {
    key: ORIGIN,
    platform: "splunk",
    containers: [
      { name: "a", columns: [{ column: "UserIdentityArn", concept: null, profile: arns }] },
      { name: "recognised", columns: [{ column: "UserIdentityArn", concept: null, profile: arns }] },
      { name: "mystery", columns: [{ column: "UserIdentityArn", concept: null, profile: arns }] },
      { name: "entra", columns: [{ column: "UserIdentityArn", concept: null, profile: arns }] },
    ],
  };
  const elected = { recognised: "aws-cloudtrail", mystery: null, entra: "entra-signin" };
  const offers = view.siblingOffers(env, "a", "UserIdentityArn", "aws-cloudtrail/principal_arn", { conceptType: "principal", feedOf: (name) => elected[name] });
  assert.deepEqual(offers.map((o) => o.container), ["recognised"], "only the table elected to the concept's own pack");
  assert.deepEqual(view.siblingOffers(env, "a", "UserIdentityArn", "aws-cloudtrail/principal_arn", { conceptType: "principal" }), [], "no election in hand: nothing is offered");
  // Through the real fixture: a sourcetype one matching name cannot elect is
  // not offered the confirm made on acme:cloudtrail, so "Bind these" cannot
  // write onto it.
  const layer = layerFor();
  layer[ORIGIN].sourcetypes.mystery = { fields: { UserIdentityArn: { profile: arns }, note: { profile: prof(["a", "b", "c"]) } } };
  const r = build({ layer });
  const envReal = r.environments.find((e) => e.key === ORIGIN);
  const feedOf = (name) => (r.feeds.get(name) || {}).packId || null;
  assert.equal(feedOf("mystery"), null);
  const real = view.siblingOffers(envReal, ST, "UserIdentityArn", "aws-cloudtrail/principal_arn", { learnedRecords: r.learnedRecords, conceptType: "principal", feedOf });
  assert.deepEqual(real.map((o) => o.container), [ST2]);
});

test("dismissed rows: leave-alone reads as set aside; not-this-one falls back to the next proposal or to unbound", async () => {
  await catalogue.dismissBinding(ST, "zz_custom_note", null);
  await catalogue.dismissBinding(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  const r = build();
  const env = r.environments.find((e) => e.key === ORIGIN);
  const container = env.containers.find((c) => c.name === ST);
  const rows = view.rowsFor(env, container, { proposals: r.proposals.filter((p) => p.container === ST), learnedRecords: r.learnedRecords, labelOf });
  const byCol = Object.fromEntries(rows.map((x) => [x.column, x]));
  assert.equal(byCol.zz_custom_note.state, "dismissed");
  assert.notEqual(byCol.UserIdentityArn.concept, "aws-cloudtrail/principal_arn", "not this one: never that concept again");
  assert.ok(["proposed", "several", "medium", "unbound"].includes(byCol.UserIdentityArn.state));
  assert.equal(view.STATE_CHIP.dismissed.text, "set aside");
  assert.equal(view.STATE_CHIP.proposed.value, "suggested");
  assert.equal(view.STATE_CHIP.yours.text, "yours");
});

// ---------------------------------------------------------------------------
// Words

test("feedSentence: the feed and how it was recognised, in plain words", () => {
  const label = (id) => (id === "aws-cloudtrail" ? "AWS CloudTrail" : id);
  assert.equal(view.feedSentence({ packId: null, basis: null }, label), "not recognised");
  assert.equal(view.feedSentence({ packId: "aws-cloudtrail", basis: "names", votes: { "aws-cloudtrail": 31 } }, label), "AWS CloudTrail, from 31 matching names");
  assert.equal(view.feedSentence({ packId: "aws-cloudtrail", basis: "names", votes: { "aws-cloudtrail": 1 } }, label), "AWS CloudTrail, from 1 matching name");
  assert.equal(view.feedSentence({ packId: "aws-cloudtrail", basis: "bindings" }, label), "AWS CloudTrail, from its bindings");
  assert.equal(view.feedSentence({ packId: "aws-cloudtrail", basis: "literals" }, label), "AWS CloudTrail, from its values");
  assert.equal(view.feedSentence({ packId: "aws-cloudtrail", basis: "forced" }, label), "AWS CloudTrail, your pick");
});

test("whyLine: alias, calculated, shape-only and bare name routes", () => {
  assert.equal(view.whyLine({ evidence: { from: "alias", via: "alias of sourceIPAddress" } }), "alias of sourceIPAddress");
  assert.equal(view.whyLine({ evidence: { from: "calculated", via: "calculated from src" } }), "calculated from src");
  assert.equal(view.whyLine({ evidence: { from: "shape", via: "shape:arn", shape: "arn", matched: 10, total: 10, hits: 3, values: 3 } }), "the values decide it; 3 of 3 top values look like ARNs");
  assert.equal(view.whyLine({ evidence: { from: "shape", via: "shape:arn", shape: "arn", matched: 10, total: 10 } }), "the values decide it; the top values look like ARNs", "an older evidence record without the distinct counts never shows the weighted sum");
  assert.equal(view.whyLine({ evidence: { from: "name", via: "EventName", shape: null } }, { unblocks: ["e1"] }), "name matches EventName; unblocks 1 pivot");
  assert.equal(view.whyLine(null), "");
});

test("looksLike: the dominant shape of the top values in a word, or nothing", () => {
  assert.equal(view.looksLike(prof(["arn:aws:iam::1:user/a", "arn:aws:iam::1:user/b"])), "ARN");
  assert.equal(view.looksLike(prof(["10.0.0.1", "10.0.0.2"])), "IP");
  assert.equal(view.looksLike(prof(["S-1-5-21-1-2-3-500", "S-1-5-18"])), "SID");
  assert.equal(view.looksLike(prof(["hello", "world"])), null);
  assert.equal(view.looksLike(null), null);
  assert.equal(view.looksLike({ top: [] }), null);
});

test("chooseGroups: the feed first with the proposal's alternatives on top, then the other feeds by name", () => {
  const feeds = [
    { id: "x", label: "X", concepts: [{ key: "x/b", label: "Bee" }, { key: "x/a", label: "Ay" }] },
    { id: "y", label: "Y", concepts: [{ key: "y/c", label: "Cee" }, { key: "y/d", label: "Dee" }, { key: "y/e", label: "Eee" }] },
  ];
  const proposal = { concept: "y/d", score: 0.91, alternatives: [{ concept: "y/e", score: 0.8 }] };
  const groups = view.chooseGroups({ feedPackId: "y", proposal, feeds });
  assert.deepEqual(groups.map((g) => g.label), ["Y", "X"]);
  assert.deepEqual(groups[0].options.map((o) => o.key), ["y/d", "y/e", "y/c"]);
  assert.equal(groups[0].options[0].score, 0.91);
  assert.equal(groups[0].options[2].score, null);
  assert.deepEqual(groups[1].options.map((o) => o.label), ["Ay", "Bee"]);
  assert.deepEqual(view.chooseGroups({ feeds: [] }), []);
});

test("evidenceFor: the proposal's own evidence, an alternative's score with the same story, or manual", async () => {
  const proposal = { concept: "y/d", score: 0.91, alias_of: null, evidence: { from: "name", score: 0.91, via: "Dee", shape: "arn", matched: 3, total: 3 }, alternatives: [{ concept: "y/e", score: 0.8 }] };
  assert.deepEqual(view.evidenceFor(proposal, "y/d"), { from: "name", score: 0.91, via: "Dee", shape: "arn", matched: 3, total: 3 });
  assert.deepEqual(view.evidenceFor(proposal, "y/e"), { from: "name", score: 0.8, via: "Dee", shape: null, matched: null, total: null }, "the runner-up keeps the story and its own score");
  assert.deepEqual(view.evidenceFor(proposal, "y/zzz"), { from: "manual", score: null, via: null, shape: null, matched: null, total: null });
  assert.equal(view.evidenceFor(null, "y/d").from, "manual");
  // Through catalogue: a pick from the alternatives lands with a score, so the stored record says why.
  const r = build();
  const p = r.proposals.find((x) => x.container === ST && x.alternatives.length);
  assert.ok(p, "some proposal on the custom sourcetype has an alternative");
  const alt = p.alternatives[0].concept;
  await catalogue.bindField(ST, p.column, alt, { evidence: view.evidenceFor(p, alt), via: "coverage" });
  const rec = catalogue.bindingFor(ST, p.column);
  assert.equal(rec.concept, alt);
  assert.equal(rec.evidence.score, p.alternatives[0].score);
  assert.ok(rec.evidence.via);
});

test("envStats: totals over every feed of the environment", () => {
  const stats = view.envStats({ feeds: [{ concepts: [1, 2, 3], carried: 1, proposed: 1, gaps: 1 }, { concepts: [1, 2], carried: 2, proposed: 0, gaps: 0 }], containers: [{}, {}, {}] });
  assert.deepEqual(stats, { concepts: 5, carried: 3, proposed: 1, gaps: 1, tables: 3 });
  assert.deepEqual(view.envStats(null), { concepts: 0, carried: 0, proposed: 0, gaps: 0, tables: 0 });
});

test("the view never runs a query: no discovery.run/rest, no recipe.queryFor reachable from it", async () => {
  const { readFile } = await import("node:fs/promises");
  const src = await readFile(new URL("../app/views/coverage.js", import.meta.url), "utf8");
  assert.ok(!/recipe\.js/.test(src), "recipe.js is not imported at all");
  assert.ok(!/discovery\.(run|rest|profile|inventory|recordTypes|provenance|decodes)\b/.test(src));
  assert.match(src, /import \{ readAll as discovered \} from "\.\.\/lib\/layer\.js"/, "only the layer read");
  assert.ok(!/lib\/discovery\.js/.test(src), "discovery.js is not imported at all");
  assert.ok(!src.includes(String.fromCharCode(0x2014)), "no em dashes");
});

test("dismissedOn expands an accumulated not-this list; blockerLine never says no pivot while some compile; an inert record is yours", () => {
  const recs = [{ platform: "splunk", container: ST, column: "a", concept: "x/z", basis: "dismissed", dismissed: ["x/y", "x/z"] }];
  assert.deepEqual(view.dismissedOn(recs, "splunk", ST).map((d) => d.concept).sort(), ["x/y", "x/z"]);
  const gaps = { feedLabel: "CloudTrail", blockers: [{ edgeId: "e", label: "E", missing: [{ concept: "aws-cloudtrail/event_name", label: "Event name", proposal: null }] }] };
  assert.match(view.blockerLine({ ...gaps, pivots: { ready: 0, blocked: 1 } }), /^No pivot yet: CloudTrail pivots here still need Event name \(pick a column\)\./);
  assert.match(view.blockerLine({ ...gaps, pivots: { ready: 3, blocked: 1 } }), /^3 pivots compile here now\. CloudTrail pivots here still need Event name/);
  assert.match(view.blockerLine({ blockers: [], pivots: { ready: 4, blocked: 0 } }), /^4 pivots compile here now\. Notes on this column/);
  const env = { platform: "splunk" };
  const container = { name: ST, columns: [{ column: "Thing", concept: null, profile: null }] };
  const rows = view.rowsFor(env, container, {
    proposals: [{ container: ST, column: "Thing", concept: "aws-cloudtrail/event_name", tier: "high", evidence: {}, alternatives: [] }],
    learnedRecords: [{ platform: "splunk", container: ST, column: "Thing", concept: "no-such-pack/thing", basis: "confirmed" }],
  });
  assert.equal(rows[0].state, "inert");
  assert.equal(rows[0].concept, "no-such-pack/thing");
  assert.equal(rows[0].proposal, null, "never proposed over the analyst's own record");
  assert.equal(rows[0].packId, "no-such-pack");
});

test("Confirm all writes the live sure list in one write: a row confirmed in place since the draw is skipped, and the count is the count written", async () => {
  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn"); // bindings now elect the feed
  const drawn = build();
  const drawTime = drawn.proposals.filter((p) => p.container === ST && p.tier === "high");
  assert.ok(drawTime.length >= 2, `the fixture proposes at least two sure columns (${drawTime.map((p) => p.column)})`);
  // The user confirms one of them in place after the page was drawn.
  const first = drawTime[0];
  await catalogue.bindField(ST, first.column, first.concept);
  // The handler recomputes at click time: the confirmed column is out.
  const live = build();
  const args = { platform: "splunk", container: ST, resolve: concepts.resolve, learnedRecords: live.learnedRecords };
  const list = view.sureProposals(live.proposals, args);
  assert.ok(!list.some((p) => p.column === first.column), "bound by now: not bound twice");
  assert.equal(list.length, drawTime.length - 1);
  // Even the draw-time list, filtered the same way, drops it.
  assert.ok(!view.sureProposals(drawTime, args).some((p) => p.column === first.column));
  const before = catalogue.learnedBindings().length;
  const r = await catalogue.bindFields(list.map((p) => ({ sourcetype: ST, name: p.column, concept: p.concept, alias_of: p.alias_of || null, evidence: p.evidence || null, via: "coverage" })));
  assert.equal(r.records.length, list.length, "the count reported is the count written");
  assert.deepEqual(r.errors, []);
  assert.equal(catalogue.learnedBindings().length, before + list.length);
  for (const p of list) assert.equal(concepts.resolve("splunk", ST, p.column).key, p.concept);
  assert.deepEqual(view.sureProposals(build().proposals, args), [], "nothing sure is left");
});

test("rule 8 reaches the page: a match with one bound side is a proposal row for the other, feed-gated, live against the resolver", async () => {
  // The second sourcetype keeps its CloudTrail names (so it elects) but its
  // ARN column carries acme:cloudtrail's own values; a third, unrecognised
  // table carries them too.
  const layer = layerFor();
  const arns = layer[ORIGIN].sourcetypes[ST].fields.UserIdentityArn.profile;
  layer[ORIGIN].sourcetypes[ST2].fields.UserIdentityArn = { profile: arns };
  layer[ORIGIN].sourcetypes.mystery = { fields: { UserIdentityArn: { profile: arns }, note: { profile: prof(["a", "b", "c"]) } } };
  const environmentsWith = () => view.environmentsFor(layer, { resolve: concepts.resolve, learnedRecords: catalogue.learnedBindings() });
  const feedOfIn = (r) => (key, name) => (key === ORIGIN && r.feeds.get(name) ? r.feeds.get(name).packId : null);
  const matchRows = (leads, r) => view.matchProposals(leads, { platform: "splunk", feedOf: feedOfIn(r), resolve: concepts.resolve, learnedRecords: r.learnedRecords });

  // Nothing bound: every pair is a join lead and no row.
  const leads = propose.matches({ environments: environmentsWith() });
  assert.ok(leads.some((x) => x.a.column === "UserIdentityArn" && x.b.column === "UserIdentityArn"), "the ARN columns pair on their values");
  assert.ok(leads.every((x) => x.proposal === null));
  let r = build({ layer });
  assert.deepEqual(matchRows(leads, r), []);

  // Bound on acme:cloudtrail: with the resolver, matches() carries the
  // proposal, and so does matchProposals() over the leads computed earlier.
  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  const fresh = propose.matches({ environments: environmentsWith() });
  assert.ok(fresh.some((x) => x.proposal && x.proposal.concept === "aws-cloudtrail/principal_arn"), "matches() proposes once a side resolves");
  r = build({ layer });
  assert.equal(feedOfIn(r)(ORIGIN, "mystery"), null);
  const rows = matchRows(leads, r);
  const eu = rows.find((p) => p.container === ST2 && p.column === "UserIdentityArn");
  assert.ok(eu, "the recognised sibling gets the row");
  assert.equal(eu.concept, "aws-cloudtrail/principal_arn");
  assert.equal(eu.tier, "high");
  assert.equal(eu.evidence.from, "match");
  assert.equal(eu.evidence.via, `${ST}.UserIdentityArn`);
  assert.match(view.whyLine(eu), /^3 values shared with acme:cloudtrail\.UserIdentityArn/);
  assert.ok(!rows.some((p) => p.container === "mystery"), "a table the election did not recognise gets none (the feed rule)");
  assert.ok(!rows.some((p) => p.container === ST), "the bound side is never the target");
  assert.ok(rows.every((p) => p.platform === "splunk"), "the other platform's tables are read only here");
  // Composed as model() composes it: the name route proposes the same
  // concept on that column (the pack's own spelling), so its row stands and
  // the match adds no second row; a column the name route has nothing for
  // takes the match row, and it renders through rowsFor like any proposal.
  const named = r.proposals.find((p) => p.container === ST2 && p.column === "UserIdentityArn");
  assert.ok(named && named.concept === eu.concept, "the fixture's name route proposes the same concept");
  let merged = view.mergeProposals(r.proposals, rows);
  assert.equal(merged.filter((p) => p.container === ST2 && p.column === "UserIdentityArn").length, 1);
  assert.equal(merged.find((p) => p.container === ST2 && p.column === "UserIdentityArn").evidence.from, named.evidence.from, "the name row keeps the column");
  const withoutName = r.proposals.filter((p) => !(p.container === ST2 && p.column === "UserIdentityArn"));
  merged = view.mergeProposals(withoutName, rows);
  const env = r.environments.find((e) => e.key === ORIGIN);
  const container = env.containers.find((c) => c.name === ST2);
  const row = view.rowsFor(env, container, { proposals: merged, learnedRecords: r.learnedRecords, labelOf }).find((x) => x.column === "UserIdentityArn");
  assert.equal(row.state, "proposed");
  assert.equal(row.label, "Principal ARN");
  assert.equal(row.proposal.evidence.from, "match");
  assert.match(view.whyLine(row.proposal), /shared with acme:cloudtrail\.UserIdentityArn/);
  // A name row that is only a close call on another concept loses to a sure
  // match; a sure name row on another concept does not.
  const several = { ...named, concept: "aws-cloudtrail/session_issuer_arn", tier: "several" };
  assert.equal(view.mergeProposals([...withoutName, several], rows).find((p) => p.container === ST2 && p.column === "UserIdentityArn").concept, eu.concept);
  const sure = { ...several, tier: "high" };
  assert.equal(view.mergeProposals([...withoutName, sure], rows).find((p) => p.container === ST2 && p.column === "UserIdentityArn").concept, sure.concept);
  assert.equal(view.mergeProposals([], []).length, 0);
  // Not this: the match no longer proposes that concept there; a confirm
  // there takes the target out altogether.
  await catalogue.dismissBinding(ST2, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  r = build({ layer });
  assert.deepEqual(matchRows(leads, r), []);
  await catalogue.bindField(ST2, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  r = build({ layer });
  assert.deepEqual(matchRows(leads, r), [], "both sides bound: a join lead at most, never a row");
});

// ---------------------------------------------------------------------------
// Coverage acceptance pass, findings 1 and 3 to 6 (0.4.76)

test('"Not this" walks only the sure candidates, never promotes by elimination, and sets the column aside once they are gone (finding 1)', async () => {
  // user_arn: a CIM alias spelling with user ARNs. Three candidates are sure
  // on their own (the alias, CIM user, Principal ARN, all favoured by the
  // ARN's resource kind); Bucket name and Image id are the ARN shape's
  // leftovers and never were.
  const layer = layerFor();
  layer[ORIGIN].sourcetypes[ST].fields.user_arn = { profile: prof(["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/carol", "arn:aws:iam::123456789012:user/dave"]) };
  const walk = [];
  for (let i = 0; i < 6; i++) {
    const r = build({ layer });
    const env = r.environments.find((e) => e.key === ORIGIN);
    const container = env.containers.find((c) => c.name === ST);
    const rows = view.rowsFor(env, container, { proposals: r.proposals.filter((p) => p.container === ST), learnedRecords: r.learnedRecords, labelOf });
    const row = rows.find((x) => x.column === "user_arn");
    const aside = view.setAsideRows(r.learnedRecords, "splunk", ST, r.proposals);
    if (!row.proposal) {
      assert.equal(row.state, "dismissed", "no sure survivor: the row reads set aside");
      assert.equal(aside.length, 1, "listed once under Set aside");
      assert.equal(aside[0].column, "user_arn");
      assert.deepEqual(aside[0].refused.map(labelOf).sort(), ["CIM user", "CIM user ARN", "Principal ARN"], "every refused concept named");
      assert.equal(aside[0].leftAlone, false);
      assert.equal(view.asideWords(aside[0], labelOf), "not CIM user ARN, not CIM user, not Principal ARN");
      break;
    }
    if (i) assert.notEqual(row.proposal.tier, "high", `${labelOf(row.proposal.concept)} after a refusal: the runner-up is never sure by elimination`);
    if (i) assert.equal(aside.length, 0, "a column still proposed is not listed under Set aside as well");
    if (i) assert.deepEqual(row.proposal.refused.length, i, "the refusals ride on the proposal");
    assert.ok(!/bucket|image|instance|policy/.test(row.proposal.concept), `${row.proposal.concept}: a resource concept is never walked for a user ARN`);
    walk.push(labelOf(row.proposal.concept));
    await catalogue.dismissBinding(ST, "user_arn", row.proposal.concept);
  }
  assert.deepEqual(walk, ["CIM user ARN", "CIM user", "Principal ARN"]);
  // The record keeps the walk; Choose on the set-aside row still binds.
  assert.deepEqual(catalogue.bindingFor(ST, "user_arn").dismissed.length, 3);
  await catalogue.bindField(ST, "user_arn", "aws-cloudtrail/principal_arn");
  assert.equal(concepts.resolve("splunk", ST, "user_arn").key, "aws-cloudtrail/principal_arn");
});

test("a refused candidate stays in the field the tier is read against: refusing the best turns the runner-up into a close call, not a sure match", async () => {
  // EventName: Event name 1.0 sure, Event type 0.93 a gap behind. Refuse
  // the first and the second is offered as several (against the refused
  // 1.0), then refused too and the column is set aside naming both.
  let r = build();
  const evn = (rr) => rr.proposals.find((p) => p.container === ST && p.column === "EventName") || null;
  assert.equal(evn(r).tier, "high");
  await catalogue.dismissBinding(ST, "EventName", evn(r).concept);
  r = build();
  const second = evn(r);
  assert.ok(second, "a sure-on-its-own runner-up is still offered");
  assert.equal(second.concept, "aws-cloudtrail/event_type");
  assert.equal(second.tier, "several", "never high by elimination");
  assert.deepEqual(second.refused, ["aws-cloudtrail/event_name"]);
  assert.ok(!second.alternatives.some((a) => a.concept === "aws-cloudtrail/event_name"), "a refused concept is not an alternative either");
  await catalogue.dismissBinding(ST, "EventName", second.concept);
  r = build();
  assert.equal(evn(r), null);
  const aside = view.setAsideRows(r.learnedRecords, "splunk", ST, r.proposals);
  assert.deepEqual(aside.map((a) => a.column), ["EventName"]);
  assert.equal(view.asideWords(aside[0], labelOf), "not Event name, not Event type");
  // A column dismissed outright with no refusals reads "left alone"; with
  // refusals before it, both.
  await catalogue.dismissBinding(ST, "zz_custom_note", null);
  await catalogue.dismissBinding(ST, "EventName", null);
  r = build();
  const words = Object.fromEntries(view.setAsideRows(r.learnedRecords, "splunk", ST, r.proposals).map((a) => [a.column, view.asideWords(a, labelOf)]));
  assert.equal(words.zz_custom_note, "left alone");
  assert.equal(words.EventName, "left alone; not Event name, not Event type");
});

test("the roll-up names each carried-on entry's own status when it differs from the concept's best (finding 3)", async () => {
  assert.equal(view.onWord({ status: "proposed" }, "pack"), "proposed");
  assert.equal(view.onWord({ status: "several" }, "yours"), "several fit");
  assert.equal(view.onWord({ status: "pack" }, "pack"), "");
  assert.equal(view.onWord(null, "pack"), "");
  // Bind EventSource on one custom table only: the concept's row is "yours"
  // (its best), the other table's entry still says proposed.
  await catalogue.bindField(ST, "EventSource", "aws-cloudtrail/event_source");
  const { cov } = build();
  const feed = cov.environments.find((e) => e.key === ORIGIN).feeds.find((f) => f.packId === "aws-cloudtrail");
  const row = feed.concepts.find((c) => c.key === "aws-cloudtrail/event_source");
  assert.equal(row.status, "yours");
  const on = Object.fromEntries(row.on.map((o) => [o.container, o.status]));
  assert.equal(on[ST], "yours");
  assert.equal(on[ST2], "proposed");
  assert.equal(view.onWord(row.on.find((o) => o.container === ST2), row.status), "proposed");
  assert.equal(view.onWord(row.on.find((o) => o.container === ST), row.status), "");
});

test("intentGaps keeps the blocker sentence short: sure proposals first, then three named and N more (finding 4)", () => {
  const missing = [
    { concept: "p/a", label: "A", proposal: null },
    { concept: "p/b", label: "B", proposal: { column: "b_col", tier: "medium" } },
    { concept: "p/c", label: "C", proposal: { column: "c_col", tier: "high" } },
    { concept: "p/d", label: "D", proposal: null },
    { concept: "p/e", label: "E", proposal: { column: "e_col", tier: "high" } },
  ];
  const c = { feedLabel: "P", blockers: [{ edgeId: "e1", label: "E1", missing: missing.slice(0, 3) }, { edgeId: "e2", label: "E2", missing }] };
  assert.equal(learned.intentGaps(c), "P pivots here still need C (proposal: c_col, sure), E (proposal: e_col, sure), B (maybe b_col) and 2 more.");
  assert.equal(learned.intentGaps(c, { limit: 0 }), "P pivots here still need C (proposal: c_col, sure), E (proposal: e_col, sure), B (maybe b_col), A (pick a column) and D (pick a column).");
  assert.equal(learned.intentGaps({ feedLabel: "P", blockers: [{ edgeId: "e", label: "E", missing: missing.slice(0, 3) }] }), "P pivots here still need C (proposal: c_col, sure), B (maybe b_col) and A (pick a column).", "three or fewer: no more");
  const { cov } = build();
  const acme = cov.environments.find((e) => e.key === ORIGIN).containers.find((c2) => c2.name === ST);
  const sentence = learned.intentGaps(acme);
  assert.match(sentence, /^AWS CloudTrail pivots here still need .* and \d+ more\.$/);
  assert.equal(sentence.split(" (").length - 1, 3, "three named");
  assert.equal(view.blockerLine(acme).split(" (").length - 1, 3);
});

test("confirmAllReason says why Confirm all is off, and the why-line names a concept by its id whichever spelling matched (finding 6)", async () => {
  let r = build();
  const mine = r.proposals.filter((p) => p.container === ST);
  assert.equal(view.confirmAllReason(r.feeds.get(ST), mine), "This feed was recognised from names alone; confirm its columns one by one.");
  assert.equal(view.confirmAllReason({ packId: null, basis: null }, mine), "Not recognised as one feed, so nothing is sure.");
  assert.equal(view.confirmAllReason({ packId: "aws-cloudtrail", basis: "bindings" }, mine.filter((p) => p.tier !== "high")), "No sure match left to confirm.");
  assert.equal(view.confirmAllReason({ packId: "aws-cloudtrail", basis: "bindings" }, mine), null);
  assert.equal(view.confirmAllDisabled({ packId: "aws-cloudtrail", basis: "bindings" }, mine), false, "confirmAllDisabled reads the reason");
  // SourceIpAddress matches the concept's label; the why-line says source_ip, as a column match says the column.
  const ip = mine.find((p) => p.column === "SourceIpAddress");
  assert.equal(ip.evidence.via, "source_ip");
  assert.match(view.whyLine(ip), /^name matches source_ip; 3 of 3 top values look like IPs/);
  const evn = mine.find((p) => p.column === "EventName");
  assert.equal(evn.evidence.via, "event_name");
  assert.ok(mine.every((p) => !/\s/.test(p.evidence.via || "")), "no label prose in a via");
});

test("the Share page: import words per kind, bindings in the header count, a no-op merge writes nothing (finding 5)", async () => {
  const share = await import("../app/views/share.js");
  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  await catalogue.annotate(ST, "UserIdentityArn", { notes: "ours" });
  await catalogue.dismissBinding(ST, "zz_custom_note", null);
  const counts = catalogue.noteCount();
  assert.equal(counts.bindings, 1, "confirmed bindings");
  assert.equal(counts.setAside, 1);
  assert.equal(counts.notes, 1);
  const doc = catalogue.exportUser();
  const before = catalogue.userLayer().updated_at;
  const r = await catalogue.importUser(doc, { mode: "merge" });
  assert.deepEqual(r.bindings, { added: 0, updated: 0, kept: 2 });
  assert.deepEqual(r.notes, { added: 0, updated: 0, kept: 1 });
  assert.equal(catalogue.userLayer().updated_at, before, "nothing merged in: last change stays put");
  assert.equal(share.importWords(r), "Imported: bindings 0 added, 0 updated, 2 skipped; notes 0 added, 0 updated, 1 skipped (skipped: yours were newer or the same). Nothing changed.");
  await catalogue.unbindField(ST, "UserIdentityArn");
  const r2 = await catalogue.importUser(doc, { mode: "merge" });
  assert.deepEqual(r2.bindings, { added: 1, updated: 0, kept: 1 });
  assert.equal(share.importWords(r2), "Imported: bindings 1 added, 0 updated, 1 skipped; notes 0 added, 0 updated, 1 skipped (skipped: yours were newer or the same).");
  assert.equal(catalogue.bindingFor(ST, "UserIdentityArn").basis, "confirmed", "the binding came back through the merge");
  assert.equal(share.importWords({ sourcetypes: 1, concepts: 2, bindings: { added: 3, updated: 0, kept: 0 }, notes: { added: 2, updated: 0, kept: 0 } }, "replace"), "Replaced: 3 bindings and 2 notes now in your catalogue, across 1 sourcetype and 2 concepts.");
});

test("a column you bound carries the learned pack on its binding: the field page chip says yours and the CIM sentence stops naming a TA (finding 6)", async () => {
  const field = await import("../app/views/field.js");
  const ann = await import("../app/components/annotation.js");
  await catalogue.bindField(ST, "UserIdentityArn", "aws-cloudtrail/principal_arn");
  const v = catalogue.fieldOn(ST, "UserIdentityArn");
  assert.equal(v.binding.packId, learned.LEARNED_ID);
  assert.equal(field.boundChipText(v, null), "yours");
  assert.equal(field.boundChipText(catalogue.fieldOn("aws:cloudtrail", "userIdentity.arn"), null), "pack · aws-cloudtrail");
  assert.equal(ann.writtenOnWords({ platform: "splunk", container: ST, column: "UserIdentityArn" }), ST, "this platform: name the table");
  assert.equal(ann.writtenOnWords({ platform: "sentinel", container: "CloudTrail_CL", column: "X" }), "Sentinel CloudTrail_CL", "the other: name it too");
});
