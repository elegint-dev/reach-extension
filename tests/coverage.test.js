// learned.coverage() and learned.intentGaps(): the per-environment
// checklist, built from data passed in - including `plan`, intent.js's
// own plan() function, injected rather than imported (see the header
// comment on learned.js for why: only the live resolver can say whether a
// filter concept is bound, and a hand-rolled stand-in for that check would
// silently disagree with it on a partial column list). The synthetic
// tests below pass a small fake that mimics plan()'s unresolved list from
// the same container data the test already built; the real-resolver tests
// at the bottom pass intent.js's actual plan(), against the bundled
// aws-cloudtrail pack, to prove the two agree and that a column list
// coverage() was not given never invents or hides a blocker. A short
// propose.matches() parity check rides along too (the very bottom): the
// same-environment case recipe.proposeEdges covers, through the
// cross-platform matcher instead.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as learned from "../app/lib/learned.js";
import * as propose from "../app/lib/propose.js";

// One small feed, in the same shape packs.pack(id) returns: a concept
// roster and two edges with an intent, one filtering on a concept, the
// other on record_types (which resolves through the feed's discriminator).
const PACK = {
  id: "p",
  name: "P Feed",
  feed: { id: "p", label: "P", discriminator: "event_type" },
  concepts: {
    who: { label: "Who", type: "principal" },
    when: { label: "When", type: "event_time" },
    what: { label: "What", type: "text" },
    event_type: { label: "Event type", type: "text" },
  },
  edges: [
    {
      id: "p_activity",
      label: "Everything this principal did",
      intent: {
        filter: [{ concept: "who", op: "eq", value: "$value" }],
        window: { since: "$earliest", until: "$latest" },
        shape: { kind: "list", project: ["who", "when", "what"] },
      },
    },
    {
      id: "p_recent",
      label: "Recent events",
      intent: {
        record_types: ["login"],
        shape: { kind: "list", project: ["when"] },
      },
    },
  ],
};

// acme:p1 (Splunk): "who" is pack-bound (callerArn), "event_type" is
// unbound but has a "several" proposal, "eventTimestamp" has a high
// proposal for "when". The p_activity edge is not blocked (who resolves);
// p_recent is, on event_type only.
const CONTAINER_A = {
  name: "acme:p1",
  columns: [
    { column: "callerArn", concept: "p/who" },
    { column: "eventTimestamp", concept: null },
    { column: "eventTypeCode", concept: null },
    { column: "freeText", concept: null },
  ],
};

// acme:p2 (Splunk): nothing resolved and nothing proposed anywhere on it -
// "not recognised": no elected feed, so no blockers are even attempted.
const CONTAINER_B = { name: "acme:p2", columns: [{ column: "z1", concept: null }, { column: "z2", concept: null }] };

// acme:p3 (Splunk): "who" is bound by the user (learned), not a pack;
// event_type is unbound with no proposal at all, so p_recent is blocked
// with no proposal to point at.
const CONTAINER_C = { name: "acme:p3", columns: [{ column: "caller", concept: "p/who" }, { column: "kind", concept: null }] };

const ENV_SPLUNK = { key: "https://splunk.acme", platform: "splunk", containers: [CONTAINER_A, CONTAINER_B, CONTAINER_C] };
const ENV_SENTINEL = { key: "/subscriptions/1/ws", platform: "sentinel", containers: [{ name: "PTable_CL", columns: [{ column: "Who", concept: null }] }] };

const LEARNED = [{ platform: "splunk", container: "acme:p3", column: "caller", concept: "p/who", basis: "confirmed", confirmed_at: "2026-09-18T00:00:00Z" }];

const PROPOSALS = [
  { platform: "splunk", container: "acme:p1", column: "eventTimestamp", concept: "p/when", tier: "high", score: 0.95 },
  { platform: "splunk", container: "acme:p1", column: "eventTypeCode", concept: "p/event_type", tier: "several", score: 0.8 },
];

const CONTAINERS_BY_NAME = new Map([CONTAINER_A, CONTAINER_B, CONTAINER_C].map((c) => [c.name, c]));

// A stand-in for intent.js's plan(): "unresolved" is every concept ref a
// clause names (filter, record_types via the feed's discriminator, or a
// shape concept) whose key is not already a bound column of the given
// container, read from the same fixtures the test built above. This is
// deliberately not a copy of intent.js's real resolution logic (it does
// not know about aliases, alternatives or dynamic paths) - it only needs
// to report unresolved concepts faithfully enough to drive coverage()'s
// own filtering, which is what these tests check: that a shape-only
// unresolved concept (when, what) never blocks, and a filter or
// record-type one (who, event_type) does.
function fakePlan(intent, { pack, container }) {
  const cols = (CONTAINERS_BY_NAME.get(container) || {}).columns || [];
  const bound = new Set(cols.filter((c) => c.concept).map((c) => c.concept));
  const unresolved = [];
  const check = (ref) => {
    const key = ref.includes("/") ? ref : `${pack.id}/${ref}`;
    if (!bound.has(key)) unresolved.push(ref);
  };
  for (const f of intent.filter || []) {
    if (!f) continue;
    if (Array.isArray(f.any)) f.any.forEach((c) => c && c.concept && check(c.concept));
    else if (f.concept) check(f.concept);
  }
  if (intent.record_types && intent.record_types.length) {
    const disc = pack.feed && pack.feed.discriminator;
    if (disc) check(disc);
  }
  for (const ref of (intent.shape && intent.shape.project) || []) check(ref);
  return { unresolved: Array.from(new Set(unresolved)) };
}

function run() {
  return learned.coverage({ environments: [ENV_SPLUNK, ENV_SENTINEL], platform: "splunk", packs: [PACK], learned: LEARNED, proposals: PROPOSALS, plan: fakePlan });
}

test("coverage(): per-container counts, feed election, and thisPlatform", () => {
  const cov = run();
  assert.equal(cov.environments.length, 2);
  const splunk = cov.environments.find((e) => e.key === ENV_SPLUNK.key);
  assert.equal(splunk.thisPlatform, true);
  const sentinel = cov.environments.find((e) => e.key === ENV_SENTINEL.key);
  assert.equal(sentinel.thisPlatform, false);

  const [a, b, c] = splunk.containers;
  assert.equal(a.name, "acme:p1");
  assert.equal(a.feedPackId, "p");
  assert.equal(a.feedLabel, "P");
  assert.deepEqual(a.counts, { bound: 1, yours: 0, proposed: 2, unbound: 1 });

  assert.equal(b.name, "acme:p2");
  assert.equal(b.feedPackId, null, "nothing resolved or proposed: not recognised");
  assert.deepEqual(b.counts, { bound: 0, yours: 0, proposed: 0, unbound: 2 });
  assert.deepEqual(b.blockers, [], "no elected feed means no blocker can be computed");

  assert.equal(c.name, "acme:p3");
  assert.equal(c.feedPackId, "p", "a learned binding still elects the feed");
  assert.deepEqual(c.counts, { bound: 1, yours: 1, proposed: 0, unbound: 1 });
});

test("coverage(): without a `plan`, nothing is ever reported as a blocker (no guessing)", () => {
  const cov = learned.coverage({ environments: [ENV_SPLUNK], platform: "splunk", packs: [PACK], learned: LEARNED, proposals: PROPOSALS });
  for (const c of cov.environments[0].containers) assert.deepEqual(c.blockers, []);
});

test("coverage(): blockers name the concept a filter or record_types clause needs, with the best proposal here; a shape-only concept never blocks", () => {
  const cov = run();
  const splunk = cov.environments.find((e) => e.key === ENV_SPLUNK.key);
  const [a, , c] = splunk.containers;

  assert.equal(a.blockers.length, 1, "who resolves, so only p_recent (record_types) blocks - not p_activity's unresolved shape concepts (when, what)");
  assert.equal(a.blockers[0].edgeId, "p_recent");
  assert.deepEqual(a.blockers[0].missing, [{ concept: "p/event_type", label: "Event type", proposal: { column: "eventTypeCode", tier: "several" } }]);

  assert.equal(c.blockers.length, 1);
  assert.deepEqual(c.blockers[0].missing, [{ concept: "p/event_type", label: "Event type", proposal: null }]);
});

test("intentGaps(): the blocker sentence a table row shows, with and without a proposal to point at", () => {
  const cov = run();
  const splunk = cov.environments.find((e) => e.key === ENV_SPLUNK.key);
  const [a, b, c] = splunk.containers;

  assert.equal(learned.intentGaps(a), "P pivots here still need Event type (maybe eventTypeCode).");
  assert.equal(learned.intentGaps(c), "P pivots here still need Event type (pick a column).");
  assert.equal(learned.intentGaps(b), null, "no blockers at all");
  assert.equal(learned.intentGaps(null), null);
});

test("intentGaps(): several missing concepts join with a plain 'and', a sure proposal reads differently from an unsure one", () => {
  const container = {
    feedLabel: "CloudTrail",
    blockers: [
      { edgeId: "e1", label: "e1", missing: [{ concept: "x/a", label: "Event name", proposal: { column: "EventName", tier: "high" } }] },
      { edgeId: "e2", label: "e2", missing: [{ concept: "x/b", label: "Event time", proposal: null }] },
    ],
  };
  assert.equal(learned.intentGaps(container), "CloudTrail pivots here still need Event name (proposal: EventName, sure) and Event time (pick a column).");
});

test("coverage(): per-feed concept rollup - status is the best landing anywhere in the environment, roster gaps still show", () => {
  const cov = run();
  const splunk = cov.environments.find((e) => e.key === ENV_SPLUNK.key);
  assert.equal(splunk.feeds.length, 1);
  const feed = splunk.feeds[0];
  assert.equal(feed.packId, "p");
  assert.equal(feed.label, "P");

  const byKey = Object.fromEntries(feed.concepts.map((c) => [c.key, c]));
  assert.equal(Object.keys(byKey).length, 4, "the whole roster shows, touched or not");
  assert.equal(byKey["p/who"].status, "pack", "bound on acme:p1 (pack) and acme:p3 (yours): pack wins");
  assert.deepEqual(
    byKey["p/who"].on.map((o) => o.container).sort(),
    ["acme:p1", "acme:p3"],
  );
  assert.equal(byKey["p/when"].status, "proposed");
  assert.equal(byKey["p/event_type"].status, "several");
  assert.equal(byKey["p/what"].status, "gap");
  assert.equal(byKey["p/what"].on.length, 0);

  assert.equal(feed.carried, 1);
  assert.equal(feed.proposed, 2);
  assert.equal(feed.gaps, 1);
});

test("coverage(): a concept named by a proposal whose pack is not in `packs` still shows, marked unknown", () => {
  const container = { name: "t", columns: [{ column: "c1", concept: null }] };
  const env = { key: "e", platform: "splunk", containers: [container] };
  const cov = learned.coverage({ environments: [env], platform: "splunk", packs: [], learned: [], proposals: [{ platform: "splunk", container: "t", column: "c1", concept: "unloaded/thing", tier: "high" }] });
  const feed = cov.environments[0].feeds.find((f) => f.packId === "unloaded");
  assert.ok(feed, "a feed row is still made for the unloaded pack");
  const row = feed.concepts.find((c) => c.key === "unloaded/thing");
  assert.ok(row);
  assert.equal(row.known, false);
  assert.equal(row.status, "proposed");
});

test("coverage(): defaults handle missing optional inputs without throwing", () => {
  assert.deepEqual(learned.coverage({}), { environments: [] });
  assert.deepEqual(learned.coverage({ environments: [{ key: "e", platform: "splunk", containers: [] }] }).environments[0].containers, []);
});

// ---------------------------------------------------------------------------
// Blockers against the real resolver: the bundled aws-cloudtrail pack,
// intent.js's actual plan(), and catalogue.js's own bindField/edgesFrom as
// the independent check. This is the case a hand-rolled "is this concept
// in the column list I was given" check cannot get right: a container's
// real bindings are never fully described by whatever columns
// `environments` happens to enumerate (discovery may not have profiled
// every one), so a blocker must come from the live registry, not the list.
import "./_splunk.js";
import "./_bundle.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as concepts from "../app/lib/concepts.js";
import { plan as intentPlan } from "../app/lib/intent.js";

await catalogue.load();

test("coverage(): a partial column list never invents a false blocker - the real container's other bindings still count", () => {
  const pack = packs.pack("aws-cloudtrail");
  assert.ok(pack, "the bundled pack is loaded");
  // ct_principal_activity filters on principal_arn AND recipient_account_id.
  // Only principal_arn's column is listed here; recipientAccountId (real,
  // bound by the pack on this very container) is left off on purpose.
  const container = { name: "aws:cloudtrail", columns: [{ column: "userIdentity.arn", concept: "aws-cloudtrail/principal_arn" }] };
  const env = { key: "https://splunk.acme", platform: "splunk", containers: [container] };
  const cov = learned.coverage({ environments: [env], platform: "splunk", packs: [pack], learned: [], proposals: [], plan: intentPlan });
  const row = cov.environments[0].containers[0];
  const blocked = row.blockers.map((b) => b.edgeId);
  assert.ok(!blocked.includes("ct_principal_activity"), `recipient_account_id is bound on the real container; a partial column list must not report it missing: ${JSON.stringify(row.blockers)}`);
  assert.ok(catalogue.edgesFrom("aws:cloudtrail", "userIdentity.arn").some((e) => e.id === "ct_principal_activity"), "sanity: the edge really does compile here");
});

test("coverage(): blockers shrink to nothing as catalogue.bindField() resolves them, matching catalogue.edgesFrom() - even when the column list omits the newly-bound column", async () => {
  const ST = "acme:cloudtrail-coverage"; // bound by no pack
  const pack = packs.pack("aws-cloudtrail");
  await catalogue.bindField(ST, "PrincipalArn", "aws-cloudtrail/principal_arn"); // elects the feed

  const build = (columns) => {
    const resolved = columns.map((column) => {
      const r = concepts.resolve("splunk", ST, column);
      return { column, concept: r ? r.key : null };
    });
    const env = { key: "https://splunk.acme", platform: "splunk", containers: [{ name: ST, columns: resolved }] };
    return learned.coverage({ environments: [env], platform: "splunk", packs: [pack], learned: catalogue.learnedBindings(), proposals: [], plan: intentPlan }).environments[0].containers[0];
  };

  let row = build(["PrincipalArn", "SharedEventId"]);
  assert.equal(row.feedPackId, "aws-cloudtrail");
  assert.ok(row.blockers.some((b) => b.edgeId === "ct_shared_event"), "SharedEventId still unbound: the pivot is blocked");
  assert.deepEqual(catalogue.edgesFrom(ST, "SharedEventId").filter((e) => e.id === "ct_shared_event"), []);

  await catalogue.bindField(ST, "SharedEventId", "aws-cloudtrail/shared_event_id");
  row = build(["PrincipalArn"]); // SharedEventId is left off this column list entirely
  assert.ok(!row.blockers.some((b) => b.edgeId === "ct_shared_event"), "the real resolver already has it bound, even though this column list never mentions it");
  assert.ok(catalogue.edgesFrom(ST, "SharedEventId").some((e) => e.id === "ct_shared_event"), "and the pivot really does compile now");
});

// ---------------------------------------------------------------------------
// propose.matches(): the same-environment case recipe.proposeEdges covers
// (two tables of one origin, same column name, shared values), run through
// the cross-platform matcher instead. Covers "matches() across environments
// and platforms" for a same-env pair, alongside the cross-platform case
// already in tests/propose.test.js.

test("matches(): recipe.proposeEdges parity - two containers of one environment, same name and shared values, still match", () => {
  const top = [{ value: "10.0.0.1", count: 5 }, { value: "10.0.0.2", count: 3 }];
  const environments = [
    {
      key: "https://splunk.acme",
      platform: "splunk",
      containers: [
        { name: "t1", columns: [{ column: "src_ip", profile: { top, distinct: 2 }, concept: "p/where" }] },
        { name: "t2", columns: [{ column: "src_ip", profile: { top, distinct: 2 }, concept: null }] },
      ],
    },
  ];
  const out = propose.matches({ environments });
  const m = out.find((x) => x.a.container !== x.b.container);
  assert.ok(m, "same-environment, different-container pair still matches");
  assert.equal(m.a.env, m.b.env, "one environment on both sides, unlike the cross-platform case");
  assert.ok(m.overlap >= 2);
  assert.equal(m.proposal.concept, "p/where");
});
