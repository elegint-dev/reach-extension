// propose.js: the name-first proposer. These tests run against synthetic
// vocabularies (tiers, tokens, dismissals) and against the four bundled
// packs' own JSON (feed election, the leave-one-container-out precision
// reference, the renamed-columns run). No _bundle.js/_splunk.js needed:
// propose.js is pure and reads no store, so the pack JSON is read straight
// off disk, the same way tools/dev/check-bindings.mjs does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as propose from "../app/lib/propose.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
function loadPack(id) {
  return JSON.parse(readFileSync(path.join(root, "app/packs", `${id}.json`), "utf8"));
}
const PACK_IDS = ["aws-cloudtrail", "entra-signin", "crowdstrike-falcon", "reach-sentinel-samples"];
const PACKS = PACK_IDS.map(loadPack);

// Builds propose.js's `concepts` input from raw pack JSON (see
// tools/dev/check-bindings.mjs for the same helper, used the same way).
function conceptsFrom(packs, { excludeContainer } = {}) {
  const byKey = new Map();
  for (const pack of packs) {
    for (const [id, rec] of Object.entries(pack.concepts || {})) {
      const key = `${pack.id}/${id}`;
      byKey.set(key, { key, id, label: rec.label, type: rec.type, decode: rec.decode || null, cim: rec.cim || null, bindings: [] });
    }
  }
  for (const pack of packs) {
    for (const b of pack.bindings || []) {
      if (excludeContainer && b.container === excludeContainer) continue;
      const key = b.concept.includes("/") ? b.concept : `${pack.id}/${b.concept}`;
      const entry = byKey.get(key);
      if (!entry) continue;
      entry.bindings.push({ platform: b.platform, container: b.container, column: b.column, alias_of: b.alias_of || null, cim: b.cim || null });
    }
  }
  return Array.from(byKey.values());
}

const REAL_VOCAB = propose.vocabulary({ concepts: conceptsFrom(PACKS), learned: [] });

// ---------------------------------------------------------------------------
// tokens()

test("tokens: camel, Pascal, snake, dot and brace splits fold to a common superset", () => {
  const forms = ["userIdentity.arn", "UserIdentityArn", "PrincipalArn", "principal_arn"];
  for (const f of forms) assert.ok(propose.tokens(f).includes("arn"), f);
  assert.deepEqual(propose.tokens("resources{}.type"), ["resource", "type"]);
  assert.deepEqual(propose.tokens("SHA256HashData"), ["sha256", "hash", "data"]);
});

test("tokens: the Sentinel custom-log suffix is stripped, not tokenised", () => {
  const t = propose.tokens("ReachCloudTrail_CL");
  assert.deepEqual(t, ["reach", "cloud", "trail"]);
  assert.ok(!t.includes("cl"));
  assert.deepEqual(propose.tokens("bytes_received_d"), ["byte", "received"]);
});

test("tokens: synonyms fold and low-info tokens survive as ordinary tokens", () => {
  assert.deepEqual(propose.tokens("src_ip"), ["source", "ip"]);
  assert.deepEqual(propose.tokens("CorrelationId"), ["correlation", "id"]);
  assert.ok(propose.LOW_INFO.has("id"));
});

// ---------------------------------------------------------------------------
// nameScore()

test("nameScore: equal tokens score 1, disjoint tokens score 0", () => {
  assert.equal(propose.nameScore(propose.tokens("userIdentity.arn"), propose.tokens("UserIdentity.arn")), 1);
  assert.equal(propose.nameScore(propose.tokens("PrincipalArn"), propose.tokens("principal_arn")), 1);
  assert.equal(propose.nameScore(propose.tokens("CorrelationId"), propose.tokens("bucketName")), 0);
});

test("nameScore: containment, specificity and the order rule", () => {
  // IPAddress inside SourceIpAddress: the extra token (source) is not
  // low-info, so the spelling is a different, more specific name and the
  // score falls short of the floor, in both directions.
  const ipVsSource = propose.nameScore(propose.tokens("IPAddress"), propose.tokens("SourceIpAddress"));
  assert.ok(ipVsSource < 0.75, String(ipVsSource));
  assert.equal(propose.nameScore(propose.tokens("SourceIpAddress"), propose.tokens("IPAddress")), ipVsSource, "containment is symmetric");
  // UserIdentityPrincipalid is more specific than UserIdentity: the extra
  // token is not low-info, so this falls well short of a match.
  assert.ok(propose.nameScore(propose.tokens("UserIdentityPrincipalid"), propose.tokens("UserIdentity")) < 0.75);
  // Low-info filler on either side is the same name: 0.8 plus share.
  assert.ok(propose.nameScore(propose.tokens("UserIdentity"), propose.tokens("UserIdentityId")) >= 0.9);
  assert.ok(propose.nameScore(propose.tokens("user"), propose.tokens("UserId")) >= 0.9);
  // SourceEventTime vs EventSource: the same two tokens, reversed order.
  const reordered = propose.nameScore(propose.tokens("SourceEventTime"), propose.tokens("EventSource"));
  assert.ok(reordered < 0.9, String(reordered));
  // status.errorCode is not just "status": below the match floor.
  assert.ok(propose.nameScore(propose.tokens("status.errorCode"), propose.tokens("status")) < 0.75);
});

test("nameScore: a one-token column never reaches 0.9 against a distinctive two-token spelling", () => {
  const pairs = [["user", "UserIdentity"], ["ip", "CidrIp"], ["arn", "PrincipalArn"], ["method", "authentication_method"], ["category", "eventCategory"], ["version", "apiVersion"], ["detail", "insightDetails"], ["title", "WindowTitle"], ["mfa", "session_mfa_authenticated"], ["host", "tls_client_host_header"]];
  for (const [col, sp] of pairs) {
    const score = propose.nameScore(propose.tokens(col), propose.tokens(sp));
    assert.ok(score < 0.75, `${col} vs ${sp}: ${score}`);
  }
});

// ---------------------------------------------------------------------------
// vocabulary(): alias_of and cim spellings never vote

test("vocabulary: a spelling bound to several concepts of one feed weighs 1/n; one bound in several feeds is not distinct", () => {
  const vocab = REAL_VOCAB;
  const sp = (key, column) => vocab.get(key).spellings.find((x) => x.kind === "column" && x.column === column);
  // Location: country on SigninLogs, location_details on azure:aad:signin, both entra.
  assert.equal(sp("entra-signin/country", "Location").weight, 0.5);
  assert.equal(sp("entra-signin/location_details", "location").weight, 0.5);
  // userAgent means user_agent in aws and in entra: full weight inside each feed, never a vote.
  assert.equal(sp("aws-cloudtrail/user_agent", "userAgent").weight, 1);
  assert.equal(sp("aws-cloudtrail/user_agent", "userAgent").distinct, false);
  assert.equal(sp("entra-signin/user_agent", "UserAgent").distinct, false);
  // eventName is CloudTrail's and nobody else's.
  assert.equal(sp("aws-cloudtrail/event_name", "eventName").weight, 1);
  assert.equal(sp("aws-cloudtrail/event_name", "eventName").distinct, true);
  // Category: event_category in aws, category in entra.
  assert.equal(sp("aws-cloudtrail/event_category", "Category").distinct, false);
  // The concept's own id and label carry weight 1.
  assert.ok(vocab.get("entra-signin/country").spellings.filter((x) => x.kind === "id" || x.kind === "label").every((x) => x.weight === 1));
});

test("vocabulary excludes alias_of and cim spellings from feed-election votes", () => {
  const vocab = REAL_VOCAB;
  const cimUser = vocab.get("aws-cloudtrail/cim_user");
  assert.ok(cimUser, "aws-cloudtrail/cim_user exists");
  assert.ok(cimUser.spellings.every((sp) => sp.capped), "every spelling of a cim concept is capped, including its own id/label");
  const alias = vocab.get("aws-cloudtrail/source_ip");
  assert.ok(alias.spellings.some((sp) => sp.column === "src_ip" && sp.capped), "the src_ip alias spelling is capped");
  assert.ok(alias.spellings.some((sp) => sp.column === "sourceIPAddress" && !sp.capped), "the raw field's own spelling is not capped");
});

// ---------------------------------------------------------------------------
// electFeed()

test("electFeed: majority owner of existing bindings", () => {
  const columns = ["a", "b", "c"];
  const existingBindings = [{ column: "a", concept: "entra-signin/user_principal_name" }, { column: "b", concept: "entra-signin/caller_ip" }];
  const r = propose.electFeed("t", columns, { vocabulary: REAL_VOCAB, existingBindings });
  assert.equal(r.feedPackId, "entra-signin");
  assert.equal(r.basis, "bindings");
});

test("electFeed: literal hits on Entra's own result-type decode (0, 50126, 53003)", () => {
  const columns = ["c1", "c2"];
  const decodes = { c1: { values: { "0": "Success", "50126": "Invalid username or password", "53003": "Blocked by Conditional Access" } } };
  const r = propose.electFeed("t", columns, { vocabulary: REAL_VOCAB, decodes });
  assert.equal(r.feedPackId, "entra-signin");
  assert.equal(r.basis, "literals");
});

test("electFeed: 30 CloudTrail-named columns elect by name vote; 2 matching columns do not", () => {
  const ct = PACKS[0].bindings.filter((b) => b.container === "AWSCloudTrail").slice(0, 30).map((b) => b.column);
  const many = propose.electFeed("t", ct, { vocabulary: REAL_VOCAB });
  assert.equal(many.basis, "names");
  assert.equal(many.feedPackId, "aws-cloudtrail");

  const two = propose.electFeed("t", ct.slice(0, 2), { vocabulary: REAL_VOCAB });
  assert.equal(two.feedPackId, null, "two matching columns is not enough to elect a feed");
});

const FOREIGN = JSON.parse(readFileSync(path.join(root, "tests/fixtures/foreign-tables.json"), "utf8"));

test("electFeed: not recognised on any of the eight foreign fixtures, at their real width, with profiles", () => {
  assert.equal(FOREIGN.tables.length, 8);
  for (const t of FOREIGN.tables) {
    assert.ok(t.columns.length >= 30, `${t.container} has ${t.columns.length} columns; a fixture narrower than the real table cannot reach the vote floor and tests nothing`);
    const columns = t.columns.map((c) => ({ column: c.column, profile: c.profile || null }));
    const r = propose.electFeed(t.container, columns, { vocabulary: REAL_VOCAB, decodes: {}, recordTypes: null, existingBindings: [] });
    assert.equal(r.feedPackId, null, `${t.container} should not elect a feed by name: votes ${JSON.stringify(r.votes)}`);
    assert.equal(r.basis, null);
    for (const [pack, n] of Object.entries(r.votes)) assert.ok(n < 3, `${t.container}: ${pack} got ${n} votes`);
  }
  const splunk = FOREIGN.tables.filter((t) => t.platform === "splunk");
  for (const t of splunk) for (const d of ["host", "source", "sourcetype", "index"]) assert.ok(t.columns.some((c) => c.column === d), `${t.container} carries the Splunk default field ${d}`);
});

test("electFeed: a name vote needs distinct vendor spellings, not generic words", () => {
  // Three exact matches on names every platform has (user, level, ip) are
  // not a feed; three exact CloudTrail names are.
  const generic = propose.electFeed("t", ["user", "level", "ip", "category", "status", "region"], { vocabulary: REAL_VOCAB });
  assert.equal(generic.feedPackId, null);
  // Five vendor names with an anchor (eventName is the record type) elect the feed.
  const vendor = propose.electFeed("t", ["eventName", "eventSource", "awsRegion", "requestParameters", "userAgent", "errorCode"], { vocabulary: REAL_VOCAB });
  assert.equal(vendor.feedPackId, "aws-cloudtrail");
  assert.equal(vendor.basis, "names");
  assert.ok(vendor.anchors >= 1);
  // Four generic-but-CloudTrail names and no anchor do not (what S3 access logs share with CloudTrail: error_code, request_id, tls_version, cipher_suite).
  const s3 = propose.electFeed("t", ["error_code", "request_id", "tls_version", "cipher_suite", "bucket_name", "user_agent"], { vocabulary: REAL_VOCAB });
  assert.equal(s3.feedPackId, null, JSON.stringify(s3.votes));
  // Columns present in almost no rows do not vote (o365:management:activity carried Graph sign-in columns in 0.3% of events).
  const sparse = ["userPrincipalName", "appDisplayName", "clientAppUsed", "conditionalAccessStatus", "createdDateTime", "isInteractive"].map((c) => ({ column: c, profile: { fill: 0.003 } }));
  assert.equal(propose.electFeed("t", [...sparse, { column: "Operation", profile: { fill: 1 } }], { vocabulary: REAL_VOCAB }).feedPackId, null);
  const dense = sparse.map((c) => ({ ...c, profile: { fill: 0.9 } }));
  assert.equal(propose.electFeed("t", dense, { vocabulary: REAL_VOCAB }).feedPackId, "entra-signin");
  // The Azure Monitor common schema on its own is not an Entra sign-in table.
  const azure = propose.electFeed("t", ["TimeGenerated", "OperationName", "CorrelationId", "CallerIpAddress", "Level", "Category", "Properties", "ResultType"], { vocabulary: REAL_VOCAB });
  assert.equal(azure.feedPackId, null);
  // A column literally named after a CIM alias never votes for the feed that aliases it.
  const cim = propose.electFeed("t", ["src_ip", "user", "action", "src", "dest"], { vocabulary: REAL_VOCAB });
  assert.equal(cim.feedPackId, null);
});

// ---------------------------------------------------------------------------
// proposeBindings(): tiers on a synthetic vocabulary

function syntheticVocab() {
  return propose.vocabulary({
    concepts: [
      { key: "p/who", id: "who", label: "Who", type: "principal", decode: null, bindings: [{ platform: "splunk", container: "v1", column: "callerArn" }] },
      { key: "p/where", id: "where", label: "Where", type: "source_ip", decode: null, bindings: [{ platform: "splunk", container: "v1", column: "callerIp" }] },
      { key: "p/when", id: "when", label: "When", type: "event_time", decode: null, bindings: [{ platform: "splunk", container: "v1", column: "eventTimestamp" }] },
    ],
    learned: [],
  });
}

test("proposeBindings: tiers - high, several (a close runner-up), medium, and nothing below the floor", () => {
  const vocab = syntheticVocab();
  // "callerArn" is an exact match: high.
  const high = propose.proposeBindings({ container: "v1", columns: [{ column: "callerArn" }], vocabulary: vocab, feed: "p" });
  assert.equal(high.length, 1);
  assert.equal(high[0].tier, "high");
  assert.equal(high[0].concept, "p/who");

  // "caller" alone is ambiguous between "who" and (weakly) nothing else here,
  // so build a genuine tie: two concepts sharing enough of the same tokens.
  const tieVocab = propose.vocabulary({
    concepts: [
      { key: "p/a", id: "a", label: "A", type: "text", bindings: [{ platform: "splunk", container: "v1", column: "requestAccountId" }] },
      { key: "p/b", id: "b", label: "B", type: "text", bindings: [{ platform: "splunk", container: "v1", column: "requestAccount" }] },
    ],
    learned: [],
  });
  const several = propose.proposeBindings({ container: "v1", columns: [{ column: "requestAccountId" }], vocabulary: tieVocab, feed: "p" });
  assert.equal(several.length, 1);
  assert.ok(several[0].tier === "high" || several[0].tier === "several", several[0].tier);

  // Nothing below the 0.75 floor.
  const none = propose.proposeBindings({ container: "v1", columns: [{ column: "zzz" }], vocabulary: vocab, feed: "p" });
  assert.equal(none.length, 0);
});

test("a confirming shape breaks a tie but never lifts a middling name to high", () => {
  // "flag" inside "flag_value_data_id": 0.8 + 0.2 * 1/4 = 0.85 on the name;
  // three true/false values confirm a flag (+0.1) and the total is 0.95,
  // but the tier is decided on the name: medium, not high.
  const vocab = propose.vocabulary({ concepts: [{ key: "p/f", id: "f", label: "F", type: "flag", bindings: [{ platform: "splunk", container: "v1", column: "flag_value_data_id" }] }], learned: [] });
  const out = propose.proposeBindings({ container: "v1", columns: [{ column: "flag", profile: { top: [{ value: "true", count: 5 }, { value: "false", count: 4 }, { value: "TRUE", count: 1 }] } }], vocabulary: vocab, feed: "p" });
  assert.equal(out.length, 1);
  assert.equal(out[0].tier, "medium", `${out[0].tier} ${out[0].score}`);
  assert.equal(out[0].evidence.shape, "bool");

  // Two exact names: an event_time concept spelled eventWhen and a text
  // concept spelled event_when (the same tokens); ISO values confirm the
  // time and separate the tie.
  const tie = propose.vocabulary({
    concepts: [
      { key: "p/t", id: "t", label: "T", type: "event_time", bindings: [{ platform: "splunk", container: "v1", column: "eventWhen" }] },
      { key: "p/x", id: "x", label: "X", type: "text", bindings: [{ platform: "sentinel", container: "v2", column: "event_when" }] },
    ],
    learned: [],
  });
  const noShape = propose.proposeBindings({ container: "v3", columns: [{ column: "event.when" }], vocabulary: tie, feed: "p" });
  assert.equal(noShape[0].tier, "several");
  const withShape = propose.proposeBindings({ container: "v3", columns: [{ column: "event.when", profile: { top: [{ value: "2026-09-18T10:00:00Z", count: 3 }, { value: "2026-09-18T10:00:01Z", count: 2 }, { value: "2026-09-18T10:00:02Z", count: 1 }] } }], vocabulary: tie, feed: "p" });
  assert.equal(withShape[0].concept, "p/t");
  assert.equal(withShape[0].tier, "high");
  assert.equal(withShape[0].score, 1, "reported scores stay clamped at 1");
});

test("a veto-only shape (ip, guid, hash) adds nothing: it cannot turn a tie into a confident proposal", () => {
  const vocab = propose.vocabulary({
    concepts: [
      { key: "p/a", id: "a", label: "A", type: "source_ip", bindings: [{ platform: "splunk", container: "v1", column: "ipAddr" }] },
      { key: "p/b", id: "b", label: "B", type: "text", bindings: [{ platform: "sentinel", container: "v2", column: "ip_addr" }] },
    ],
    learned: [],
  });
  const ips = { top: [{ value: "10.0.0.1", count: 3 }, { value: "10.0.0.2", count: 2 }, { value: "10.0.0.3", count: 1 }] };
  const out = propose.proposeBindings({ container: "v3", columns: [{ column: "IpAddr", profile: ips }], vocabulary: vocab, feed: "p" });
  assert.equal(out[0].tier, "several", "the ip shape must not separate the tie");
  assert.equal(out[0].score, 1);
  // And on the real packs: "ip" with IP values on a CloudTrail feed is not source_ip.
  const real = propose.proposeBindings({ container: "t", columns: [{ column: "ip", profile: ips }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" });
  assert.equal(real.length, 0, JSON.stringify(real));
});

test("a column named after an alias or CIM spelling never reaches high, even through the concept id", () => {
  const ips = { top: [{ value: "10.0.0.1", count: 3 }, { value: "10.0.0.2", count: 2 }, { value: "10.0.0.3", count: 1 }] };
  for (const column of ["src_ip", "SourceIp"]) {
    const out = propose.proposeBindings({ container: "t", columns: [{ column, profile: ips }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" });
    assert.equal(out.length, 1, column);
    assert.equal(out[0].concept, "aws-cloudtrail/source_ip");
    assert.equal(out[0].tier, "several", `${column}: ${out[0].tier}`);
  }
  // The canonical vendor spelling still reaches high.
  const raw = propose.proposeBindings({ container: "t", columns: [{ column: "sourceIPAddress", profile: ips }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" });
  assert.equal(raw[0].tier, "high");
});

test("Splunk default fields never propose, on any feed", () => {
  const columns = [
    { column: "host", profile: { top: [{ value: "web-1.acme.internal", count: 3 }, { value: "web-2.acme.internal", count: 2 }, { value: "web-3.acme.internal", count: 1 }] } },
    { column: "source", profile: { top: [{ value: "/var/log/a.log", count: 3 }, { value: "/var/log/b.log", count: 2 }, { value: "/var/log/c.log", count: 1 }] } },
    { column: "sourcetype", profile: { top: [{ value: "x", count: 3 }] } },
    { column: "index", profile: { top: [{ value: "main", count: 3 }] } },
  ];
  for (const feed of ["aws-cloudtrail", "entra-signin", "crowdstrike-falcon"]) {
    const out = propose.proposeBindings({ container: "t", columns, vocabulary: REAL_VOCAB, feed });
    assert.deepEqual(out, [], `${feed}: ${JSON.stringify(out.map((p) => p.column + ">" + p.concept))}`);
  }
  for (const d of ["host", "source", "sourcetype", "index"]) assert.ok(propose.PLATFORM_DEFAULT_COLUMNS.has(d));
});

test("value vetoes on the real packs: numeric ids, GUID tenant ids and braced GUIDs keep their concept", () => {
  const guids = { top: [{ value: "550e8400-e29b-41d4-a716-446655440000", count: 3 }, { value: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", count: 2 }, { value: "6ba7b811-9dad-11d1-80b4-00c04fd430c8", count: 1 }] };
  const braced = { top: guids.top.map((t) => ({ value: `{${t.value}}`, count: t.count })) };
  const numbers = { top: [{ value: "1234", count: 3 }, { value: "5678", count: 2 }, { value: "91011", count: 1 }], numeric: true };
  const tenant = propose.proposeBindings({ container: "t", columns: [{ column: "AADTenantId", profile: guids }], vocabulary: REAL_VOCAB, feed: "entra-signin" });
  assert.equal(tenant.length, 1);
  assert.equal(tenant[0].concept, "entra-signin/tenant_id");
  assert.equal(tenant[0].tier, "high");

  const falconVocab = propose.vocabulary({ concepts: conceptsFrom(PACKS, { excludeContainer: "crowdstrike:events:sensor" }), learned: [] });
  for (const [column, concept] of [["RawProcessId", "crowdstrike-falcon/raw_process_id"], ["TargetProcessId", "crowdstrike-falcon/target_process_id"], ["ContextThreadId", "crowdstrike-falcon/context_thread_id"]]) {
    const out = propose.proposeBindings({ container: "t", columns: [{ column, profile: numbers }], vocabulary: falconVocab, feed: "crowdstrike-falcon" });
    assert.equal(out.length, 1, `${column} (numeric) still proposes`);
    assert.equal(out[0].concept, concept);
    assert.equal(out[0].tier, "high");
  }
  const entraVocab = propose.vocabulary({ concepts: conceptsFrom(PACKS, { excludeContainer: "SigninLogs" }), learned: [] });
  const resultType = propose.proposeBindings({ container: "t", columns: [{ column: "ResultType", profile: { top: [{ value: "0", count: 3 }, { value: "50126", count: 2 }, { value: "53003", count: 1 }], numeric: true } }], vocabulary: entraVocab, feed: "entra-signin" });
  assert.equal(resultType.length, 1);
  assert.equal(resultType[0].concept, "entra-signin/result_type");

  const eventId = propose.proposeBindings({ container: "t", columns: [{ column: "eventID", profile: braced }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" });
  assert.equal(eventId.length, 1);
  assert.equal(eventId[0].concept, "aws-cloudtrail/event_id");
  assert.equal(eventId[0].tier, "high", "a braced GUID is a guid, not json");

  const flag = propose.proposeBindings({ container: "t", columns: [{ column: "readOnly", profile: { top: [{ value: "0", count: 3 }, { value: "1", count: 2 }, { value: "0", count: 1 }], numeric: true } }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" });
  assert.equal(flag.length, 1);
  assert.equal(flag[0].concept, "aws-cloudtrail/read_only");
});

test("a UPN or email column proposes nothing on values alone; a SID or ARN column does", () => {
  const upns = { top: [{ value: "alice@contoso.com", count: 3 }, { value: "bob@contoso.com", count: 2 }, { value: "carol@contoso.com", count: 1 }] };
  const emails = { top: [{ value: "a@yahoo.co.uk", count: 3 }, { value: "b@proton.me", count: 2 }, { value: "c@googlemail.com", count: 1 }] };
  for (const [column, profile] of [["TargetMailbox", upns], ["CcRecipients", emails], ["CcRecipients", upns]]) {
    const out = propose.proposeBindings({ container: "t", columns: [{ column, profile }], vocabulary: REAL_VOCAB, feed: "entra-signin" });
    assert.deepEqual(out, [], `${column}: ${JSON.stringify(out.map((p) => p.concept))}`);
  }
  const sids = { top: [{ value: "S-1-5-18", count: 3 }, { value: "S-1-5-21-1-2-3-1001", count: 2 }, { value: "S-1-5-21-1-2-3-1002", count: 1 }] };
  const sid = propose.proposeBindings({ container: "t", columns: [{ column: "c9", profile: sids }], vocabulary: REAL_VOCAB, feed: "crowdstrike-falcon" });
  assert.ok(sid.length === 1 && sid[0].evidence.via === "shape:sid", JSON.stringify(sid));
});

test("ARN detail breaks the principal versus session-issuer tie", () => {
  const users = { top: [{ value: "arn:aws:iam::123456789012:user/jdoe", count: 6 }, { value: "arn:aws:sts::123456789012:assumed-role/Admin/s1", count: 2 }, { value: "arn:aws:iam::123456789012:user/bsmith", count: 2 }] };
  const roles = { top: [{ value: "arn:aws:iam::123456789012:role/Admin", count: 6 }, { value: "arn:aws:iam::123456789012:role/ReadOnly", count: 2 }, { value: "arn:aws:iam::123456789012:role/Ops", count: 2 }] };
  const u = propose.proposeBindings({ container: "t", columns: [{ column: "c7", profile: users }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" })[0];
  assert.ok(u, "user ARNs propose on shape alone");
  assert.ok(!/issuer|role/.test(u.concept), `${u.concept} is the acting principal, not an issuer`);
  assert.ok(u.alternatives.every((a) => !/issuer|requested_role/.test(a.concept) || a.score < u.score), "issuer concepts sit a gap behind");
  const r = propose.proposeBindings({ container: "t", columns: [{ column: "c8", profile: roles }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" })[0];
  assert.ok(r && /issuer|role/.test(r.concept), `${r && r.concept}: role ARNs land on an issuer or requested-role concept`);
  const named = propose.proposeBindings({ container: "t", columns: [{ column: "userIdentity.arn", profile: users }], vocabulary: REAL_VOCAB, feed: "aws-cloudtrail" })[0];
  assert.equal(named.concept, "aws-cloudtrail/principal_arn");
  assert.equal(named.tier, "high", "an exact name plus a positive shape is high, not demoted by the clamp");
});

// ---------------------------------------------------------------------------
// The renamed-columns CloudTrail run: real bindings, anonymised names.

test("renamed CloudTrail (c1..cN): the feed still elects by literal hits, and only specific-shape columns propose", () => {
  const ct = PACKS[0];
  const bindings = ct.bindings.filter((b) => b.container === "aws:cloudtrail");
  const renamed = new Map(bindings.map((b, i) => [b.column, `c${i + 1}`]));
  const VALUES = {
    "userIdentity.arn": [{ value: "arn:aws:iam::123456789012:user/jdoe", count: 6 }, { value: "arn:aws:sts::123456789012:assumed-role/Admin/sess1", count: 2 }, { value: "arn:aws:iam::123456789012:user/bsmith", count: 2 }],
    "userIdentity.accessKeyId": [{ value: "AKIAIOSFODNN7EXAMPLE", count: 4 }, { value: "ASIAIOSFODNN7EXAMPLE", count: 4 }, { value: "AKIAIOSFODNN7EXAMPL2", count: 2 }],
    "userIdentity.principalId": [{ value: "AIDAJQABLZS4A3QDU576Q", count: 4 }, { value: "AROAJQABLZS4A3QDU576Q", count: 4 }, { value: "AIDAJQABLZS4A3QDU5772", count: 2 }],
    "sourceIPAddress": [{ value: "10.0.0.1", count: 4 }, { value: "203.0.113.5", count: 4 }, { value: "203.0.113.6", count: 2 }],
    "eventName": [{ value: "ConsoleLogin", count: 4 }, { value: "AssumeRole", count: 4 }, { value: "GetObject", count: 2 }],
  };
  const columns = bindings.map((b) => {
    const c = renamed.get(b.column);
    const top = VALUES[b.column];
    return { column: c, profile: top ? { top, distinct: top.length, fill: 1 } : null };
  });
  const eventTypeCol = renamed.get("eventType");
  const decodes = { [eventTypeCol]: { values: ct.concepts.event_type.decode.values } };

  const elect = propose.electFeed("renamed", columns, { vocabulary: REAL_VOCAB, decodes });
  assert.equal(elect.feedPackId, "aws-cloudtrail");
  assert.equal(elect.basis, "literals", "with every name anonymised, only the eventType decode set can elect the feed");

  const proposals = propose.proposeBindings({ container: "renamed", columns, vocabulary: REAL_VOCAB, feed: elect.feedPackId });
  const proposedColumns = new Set(proposals.map((p) => p.column));
  for (const shapeCol of ["userIdentity.arn", "userIdentity.accessKeyId", "userIdentity.principalId"]) {
    assert.ok(proposedColumns.has(renamed.get(shapeCol)), `${shapeCol} (a specific shape) should propose even anonymised`);
  }
  // A veto-only shape (ip) and plain text never propose on name alone.
  assert.ok(!proposedColumns.has(renamed.get("sourceIPAddress")), "an IP address alone is not enough evidence");
  assert.ok(!proposedColumns.has(renamed.get("eventName")), "free text with no shape and no name is not enough evidence");

  // With the real names kept, the same values confirm and the feed elects by name.
  const named = bindings.map((b) => ({ column: b.column, profile: VALUES[b.column] ? { top: VALUES[b.column], distinct: 3, fill: 1 } : null }));
  const byName = propose.electFeed("acme:cloudtrail", named, { vocabulary: REAL_VOCAB });
  assert.equal(byName.basis, "names");
  assert.equal(byName.feedPackId, "aws-cloudtrail");
});

// ---------------------------------------------------------------------------
// Dismissals and pack-bound columns

test("dismissed pairs never return; a dismissal with no concept sets the column aside entirely", () => {
  const vocab = syntheticVocab();
  const columns = [{ column: "callerArn" }];
  const dismissedPair = propose.proposeBindings({ container: "v1", columns, vocabulary: vocab, feed: "p", dismissed: [{ column: "callerArn", concept: "p/who" }] });
  assert.equal(dismissedPair.length, 0);

  const dismissedColumn = propose.proposeBindings({ container: "v1", columns, vocabulary: vocab, feed: "p", dismissed: [{ column: "callerArn", concept: null }] });
  assert.equal(dismissedColumn.length, 0);

  const stillProposes = propose.proposeBindings({ container: "v1", columns, vocabulary: vocab, feed: "p", dismissed: [{ column: "somethingElse", concept: "p/who" }] });
  assert.equal(stillProposes.length, 1);
});

test("provenance route: an alias of a bound column proposes at high with alias_of set; a calculated field with one ref at medium; two refs propose nothing", () => {
  const vocab = syntheticVocab();
  const packBound = [{ column: "callerArn", concept: "p/who" }];

  const alias = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "src_ip", provenance: [{ kind: "alias", from: "callerArn" }] }],
    vocabulary: vocab,
    feed: "p",
    packBound,
  });
  assert.equal(alias.length, 1);
  assert.equal(alias[0].tier, "high");
  assert.equal(alias[0].concept, "p/who");
  assert.equal(alias[0].evidence.from, "alias");
  assert.equal(alias[0].alias_of, "callerArn");

  const calculated = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "computedWho", provenance: [{ kind: "calculated", refs: ["callerArn"] }] }],
    vocabulary: vocab,
    feed: "p",
    packBound,
  });
  assert.equal(calculated.length, 1);
  assert.equal(calculated[0].tier, "medium");
  assert.equal(calculated[0].evidence.from, "calculated");
  assert.equal(calculated[0].alias_of, "callerArn");

  const twoRefs = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "computedBoth", provenance: [{ kind: "calculated", refs: ["callerArn", "callerIp"] }] }],
    vocabulary: vocab,
    feed: "p",
    packBound,
  });
  assert.equal(twoRefs.length, 0, "a calculated field with two refs is ambiguous and proposes nothing");
});

test("shape vetoes: an all-numeric column never carries a textual concept, and a dynamic Sentinel column never carries anything but raw_object", () => {
  const vocab = syntheticVocab(); // p/who is type "principal"
  const numeric = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "who", profile: { top: [{ value: "1", count: 10 }, { value: "2", count: 10 }, { value: "3", count: 10 }], numeric: true } }],
    vocabulary: vocab,
    feed: "p",
  });
  assert.equal(numeric.length, 0, "an all-numeric column cannot be the principal, however well the name matches");

  const dynamic = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "who", profile: { top: [{ value: '{"a":1}', count: 10 }], type: "dynamic" } }],
    vocabulary: vocab,
    feed: "p",
  });
  assert.equal(dynamic.length, 0, "a dynamic column cannot be a principal");
});

test("a single repeated value never trips the 3-values-minimum veto guard", () => {
  const vocab = syntheticVocab(); // p/where is type "source_ip"
  // One IP value, seen 1000 times: a real column, not a thin sample. An IP
  // shape is veto-only, so this must not veto a principal candidate on the
  // strength of a single distinct value.
  const out = propose.proposeBindings({
    container: "v1",
    columns: [{ column: "callerArn", profile: { top: [{ value: "10.0.0.1", count: 1000 }] } }],
    vocabulary: vocab,
    feed: "p",
  });
  assert.ok(out.length === 1 && out[0].concept === "p/who", "the name match on callerArn still wins; one value cannot veto");
});

test("a pack-bound column never proposes", () => {
  const vocab = syntheticVocab();
  const columns = [{ column: "callerArn" }, { column: "callerIp" }];
  const out = propose.proposeBindings({ container: "v1", columns, vocabulary: vocab, feed: "p", packBound: ["callerArn"] });
  assert.equal(out.length, 1);
  assert.equal(out[0].column, "callerIp");
});

// ---------------------------------------------------------------------------
// matches(): the same column on two containers of two environments

test("matches: exact names with shared values match across platforms; a bound side proposes for the unbound side", () => {
  const arns = (n) => ({ top: [{ value: "arn:aws:iam::1:user/a", count: 5 }, { value: "arn:aws:iam::1:user/b", count: 3 }, { value: `arn:aws:iam::1:user/${n}`, count: 1 }], distinct: 3 });
  const ips = { top: [{ value: "10.0.0.1", count: 3 }, { value: "10.0.0.2", count: 2 }], distinct: 2 };
  const environments = [
    { key: "https://splunk.acme", platform: "splunk", containers: [{ name: "aws:cloudtrail", columns: [
      { column: "userIdentity.arn", profile: arns("c"), concept: "aws-cloudtrail/principal_arn" },
      { column: "sourceIPAddress", profile: ips, concept: "aws-cloudtrail/source_ip" },
      { column: "CallerIp", profile: ips, concept: null },
    ] }] },
    { key: "/subscriptions/1/ws", platform: "sentinel", containers: [{ name: "AcmeCloudTrail_CL", columns: [
      { column: "UserIdentityArn", profile: arns("d"), concept: null },
      { column: "SourceIpAddress", profile: ips, concept: null },
      { column: "CallerIpAddress", profile: ips, concept: null },
      { column: "OtherIp", profile: ips, concept: null },
    ] }] },
  ];
  const out = propose.matches({ environments });
  const find = (x, y) => out.find((m) => (m.a.column === x && m.b.column === y) || (m.a.column === y && m.b.column === x));
  const arn = find("userIdentity.arn", "UserIdentityArn");
  assert.ok(arn, "same token set, two shared values");
  assert.equal(arn.overlap, 2);
  assert.deepEqual(arn.proposal, { for: "b", concept: "aws-cloudtrail/principal_arn", tier: "high" });
  const ip = find("sourceIPAddress", "SourceIpAddress");
  assert.ok(ip && ip.proposal.tier === "high");
  // Containment with low-info filler still matches; a different name with the same values does not.
  const caller = find("CallerIp", "CallerIpAddress");
  assert.ok(caller, "CallerIp inside CallerIpAddress (address is low-info)");
  assert.equal(caller.proposal, null, "neither side is bound: a join lead, not a proposal");
  assert.equal(find("sourceIPAddress", "OtherIp"), undefined, "shared values alone never match a different name");
  assert.equal(find("sourceIPAddress", "CallerIpAddress"), undefined, "a real extra token (caller) is a different name");
});

// ---------------------------------------------------------------------------
// The leave-one-container-out golden reference: every one of the 8 bound
// containers keeps high-tier precision at or above the check-bindings.mjs
// gate when its own bindings are hidden and its feed is elected by name
// alone (no profiles, no existing bindings).

test("leave-one-container-out: every pack container holds 0.9+ high-tier precision", () => {
  const containers = new Map();
  for (const pack of PACKS) {
    for (const b of pack.bindings || []) {
      const key = b.concept.includes("/") ? b.concept : `${pack.id}/${b.concept}`;
      const rec = containers.get(b.container) || new Map();
      rec.set(b.column, key);
      containers.set(b.container, rec);
    }
  }
  assert.ok(containers.size >= 8, "the four packs bind at least 8 containers");
  for (const [container, truth] of containers) {
    const concepts = conceptsFrom(PACKS, { excludeContainer: container });
    const vocabulary = propose.vocabulary({ concepts, learned: [] });
    const columns = [...truth.keys()].map((column) => ({ column, profile: null }));
    const elect = propose.electFeed(container, columns, { vocabulary, decodes: {}, recordTypes: null, existingBindings: [] });
    const tally = new Map();
    for (const key of truth.values()) tally.set(key.split("/")[0], (tally.get(key.split("/")[0]) || 0) + 1);
    const owner = [...tally.entries()].sort((a, b) => b[1] - a[1])[0][0];
    assert.equal(elect.feedPackId, owner, `${container} elects its own feed by name: ${JSON.stringify(elect.votes)}`);
    const proposals = propose.proposeBindings({ container, columns, vocabulary, feed: elect.feedPackId });
    const high = proposals.filter((p) => p.tier === "high");
    assert.ok(high.length > 0, `${container}: proposes something`);
    const correct = high.filter((p) => truth.get(p.column) === p.concept).length;
    assert.ok(correct / high.length >= 0.9, `${container}: ${correct}/${high.length}`);
    assert.ok(correct / truth.size >= 0.6, `${container}: recall ${correct}/${truth.size}`);
  }
});
