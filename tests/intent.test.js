// The platform-neutral half of query synthesis: an edge's intent names
// concepts; plan() turns them into the destination container's columns on
// either platform. The emitters (one per language) are step 2.
import "./_splunk.js";
import "./_bundle.js";
import "./_core-packs.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as intent from "../app/lib/intent.js";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";

await catalogue.load();
const ct = packs.pack("aws-cloudtrail");
const activity = ct.edges.find((e) => e.id === "ct_principal_activity");
const logins = ct.edges.find((e) => e.id === "ct_console_logins");

test("validate: structure, ops, measures and concept refs", () => {
  assert.deepEqual(intent.validate(activity.intent, (r) => Boolean(ct.concepts[r])), []);
  const bad = (patch) => intent.validate({ ...activity.intent, ...patch }, (r) => Boolean(ct.concepts[r]));
  assert.ok(bad({ filter: [{ concept: "nope", op: "eq", value: "$value" }] }).some((e) => /unknown concept nope/.test(e)));
  assert.ok(bad({ filter: [{ concept: "principal_arn", op: "like", value: "x" }] }).some((e) => /op must be/.test(e)));
  assert.ok(bad({ filter: [{ concept: "principal_arn", op: "eq" }] }).some((e) => /needs a value/.test(e)));
  assert.ok(bad({ filter: [{ concept: "principal_arn", op: "eq", value: ["a"] }] }).some((e) => /only in takes a list/.test(e)));
  assert.ok(bad({ window: { since: "-24h" } }).some((e) => /since must be a \$param/.test(e)));
  assert.ok(bad({ shape: { kind: "table" } }).some((e) => /kind must be/.test(e)));
  assert.ok(bad({ shape: { kind: "summary", by: ["event_name"], measures: [{ fn: "median", as: "m" }] } }).some((e) => /fn must be/.test(e)));
  assert.ok(bad({ shape: { kind: "summary", by: ["event_name"], measures: [{ fn: "values", concept: "source_ip", as: "Bad As" }] } }).some((e) => /as must be/.test(e)));
  assert.ok(bad({ scope: "everywhere" }).some((e) => /scope must be/.test(e)));
  // The pack loader runs the same check on every edge that carries an intent.
  assert.ok(packs.validate({ ...ct, edges: ct.edges.map((e) => (e.id === "ct_console_logins" ? { ...e, intent: { ...e.intent, shape: { kind: "list", project: ["no_such"] } } } : e)) }).some((e) => /intent shape.project: unknown concept no_such/.test(e)));
});

test("plan on Splunk: the pack's own dotted fields, _time, and the bound params", () => {
  const p = intent.plan(activity.intent, { pack: ct, platform: "splunk", container: "aws:cloudtrail" });
  assert.equal(p.lang, "spl");
  assert.equal(p.time, "_time");
  assert.deepEqual(p.unresolved, []);
  assert.deepEqual(p.filters.map((f) => [f.column, f.op, f.param, f.needs]), [["userIdentity.arn", "eq", "value", []], ["recipientAccountId", "eq", "account", ["account"]]]);
  assert.deepEqual(p.window, { since: "earliest", until: "latest" });
  assert.deepEqual(p.shape.by.map((b) => b.column), ["eventSource", "eventName"]);
  assert.deepEqual(p.shape.measures.map((m) => [m.fn, m.column, m.as]), [["count", null, "calls"], ["count_where_exists", "errorCode", "failures"], ["min_time", null, "first_seen"], ["max_time", null, "last_seen"], ["values", "sourceIPAddress", "addresses"]]);
  assert.deepEqual(p.shape.order, { by: "calls", dir: "desc" });
  assert.deepEqual(p.params.sort(), ["account", "earliest", "latest", "value"]);
  assert.ok(p.filters.every((f) => !f.dynamic));
  // A direct binding beats the TA alias: sourceIPAddress, not src.
  assert.equal(p.shape.measures.find((m) => m.as === "addresses").column, "sourceIPAddress");
});

test("plan on Sentinel: the same intent lands on the sample table, Microsoft's table, and flags dynamic paths", () => {
  const sample = intent.plan(activity.intent, { pack: ct, platform: "sentinel", container: "ReachCloudTrail_CL" });
  assert.equal(sample.lang, "kql");
  assert.equal(sample.time, "TimeGenerated");
  assert.deepEqual(sample.unresolved, []);
  assert.equal(sample.filters[0].column, "PrincipalArn");
  assert.equal(sample.filters[0].dynamic, false, "the flattened column, not the UserIdentity.arn path");
  assert.deepEqual(sample.shape.by.map((b) => b.column), ["EventSource", "EventName"]);

  const ms = intent.plan(activity.intent, { pack: ct, platform: "sentinel", container: "AWSCloudTrail" });
  assert.deepEqual(ms.unresolved, []);
  assert.equal(ms.filters[0].column, "UserIdentityArn");
  assert.equal(ms.shape.measures.find((m) => m.as === "addresses").column, "SourceIpAddress");

  // Console sign-ins: the record type is the feed's discriminator; two projected concepts
  // exist only inside dynamic columns on the sample table, and one is not bound on Microsoft's.
  const li = intent.plan(logins.intent, { pack: ct, platform: "sentinel", container: "ReachCloudTrail_CL" });
  assert.deepEqual(li.recordTypes, { column: "EventName", dynamic: false, values: ["ConsoleLogin"] });
  const res = li.shape.project.find((c) => c.concept === "console_login_result");
  assert.equal(res.column, "ResponseElements.ConsoleLogin");
  assert.equal(res.dynamic, true);
  assert.deepEqual(li.unresolved, ["console_mfa_used"], "additionalEventData is not a column on the sample table");
  const liMs = intent.plan(logins.intent, { pack: ct, platform: "sentinel", container: "AWSCloudTrail" });
  assert.deepEqual(liMs.unresolved, [], "the JSON-string columns bind as head.path with an encoding");
  const msRes = liMs.shape.project.find((c) => c.concept === "console_login_result");
  assert.deepEqual([msRes.column, msRes.encoding, msRes.head, msRes.path, msRes.dynamic], ["ResponseElements.ConsoleLogin", "json_string", "ResponseElements", "ConsoleLogin", false]);
  const msMfa = liMs.shape.project.find((c) => c.concept === "console_mfa_used");
  assert.deepEqual([msMfa.head, msMfa.path], ["AdditionalEventData", "MFAUsed"]);
  assert.equal(sample.filters[0].encoding, null);
});

test("every intent in the bundled packs plans cleanly onto the pack's own vendor containers on both platforms", () => {
  const vendor = {
    "aws-cloudtrail": [["splunk", "aws:cloudtrail"], ["sentinel", "AWSCloudTrail"]],
    "entra-signin": [["splunk", "azure:aad:signin"], ["sentinel", "SigninLogs"]],
    "crowdstrike-falcon": [["splunk", "crowdstrike:events:sensor"]],
  };
  for (const [id, containers] of Object.entries(vendor)) {
    const p = packs.pack(id);
    assert.ok(p.edges.some((e) => e.intent), id);
    for (const e of p.edges) {
      if (!e.intent) continue;
      for (const [platform, container] of containers) {
        const plan = intent.plan(e.intent, { pack: p, platform, container });
        assert.deepEqual(plan.unresolved, [], `${e.id} on ${container}`);
      }
    }
  }
  // The dev sample table lacks two columns the connector table has; those are projections, so the pivot still compiles there.
  const li = intent.plan(logins.intent, { pack: ct, platform: "sentinel", container: "ReachCloudTrail_CL" });
  assert.deepEqual(li.unresolved, ["console_mfa_used"]);
});

test("the two cross-feed edges carry scope type intents that union every source_ip container, the vendor container first, and drop none", () => {
  const cases = [
    ["aws-cloudtrail", "ct_ip_elsewhere", "source_ip", "splunk", "aws:cloudtrail", ["aws:cloudtrail", "azure:aad:signin", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"]],
    ["aws-cloudtrail", "ct_ip_elsewhere", "source_ip", "sentinel", "AWSCloudTrail", ["AWSCloudTrail", "GWorkspace_ReportsAPI_admin_CL", "GWorkspace_ReportsAPI_drive_CL", "GWorkspace_ReportsAPI_login_CL", "Okta_CL", "ReachAzureAD_CL", "ReachCloudTrail_CL", "ReachCrowdStrike_CL", "SigninLogs"]],
    ["entra-signin", "aad_ip_elsewhere", "caller_ip", "splunk", "azure:aad:signin", ["azure:aad:signin", "aws:cloudtrail", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"]],
    ["entra-signin", "aad_ip_elsewhere", "caller_ip", "sentinel", "SigninLogs", ["SigninLogs", "AWSCloudTrail", "GWorkspace_ReportsAPI_admin_CL", "GWorkspace_ReportsAPI_drive_CL", "GWorkspace_ReportsAPI_login_CL", "Okta_CL", "ReachAzureAD_CL", "ReachCloudTrail_CL", "ReachCrowdStrike_CL"]],
  ];
  for (const [packId, edgeId, filterConcept, platform, container, union] of cases) {
    const p = packs.pack(packId);
    const e = p.edges.find((x) => x.id === edgeId);
    assert.ok(e && e.intent && e.intent.scope === "type", `${packId}/${edgeId} has a scope type intent`);
    assert.deepEqual(e.dst, { type: "source_ip" });
    assert.deepEqual(e.intent.filter, [{ concept: filterConcept, op: "eq", value: "$value" }]);
    assert.equal(e.intent.shape.kind, "list");
    assert.deepEqual(intent.validate(e.intent, (r) => Boolean(p.concepts[r])), []);
    const plan = intent.plan(e.intent, { pack: p, platform, container });
    assert.deepEqual(plan.union.map((u) => u.container), union, `${edgeId} on ${platform}`);
    assert.deepEqual(plan.dropped, []);
    assert.deepEqual(plan.params.sort(), ["earliest", "latest", "value"]);
  }
});

test("an any-of filter and a concept bound twice on one table both plan", () => {
  const either = { filter: [{ any: [{ concept: "target_process_id", op: "eq", value: "$value" }, { concept: "context_process_id", op: "eq", value: "$value" }] }, { concept: "aid", op: "eq", value: "$aid", needs: ["aid"] }], window: { since: "$earliest" }, shape: { kind: "list", project: ["event_time", "event_simple_name"], order: { by: "time", dir: "asc" } } };
  const falcon = packs.pack("crowdstrike-falcon");
  assert.deepEqual(intent.validate(either, (r) => Boolean(falcon.concepts[r])), []);
  assert.ok(intent.validate({ ...either, filter: [{ any: [{ concept: "aid", op: "eq", value: "x" }] }] }, () => true).some((e) => /at least two/.test(e)));
  const p = intent.plan(either, { pack: falcon, platform: "sentinel", container: "ReachCrowdStrike_CL" });
  assert.deepEqual(p.filters[0].any.map((c) => c.column), ["TargetProcessId", "ContextProcessId"]);
  assert.deepEqual(p.filters[1].needs, ["aid"]);
  assert.deepEqual(p.params.sort(), ["aid", "earliest", "value"]);
  // access_key_id sits in AccessKeyId and in the UserIdentity.accessKeyId path on the sample table.
  const key = intent.plan({ filter: [{ concept: "access_key_id", op: "eq", value: "$value" }], shape: { kind: "list", project: ["event_name"] } }, { pack: ct, platform: "sentinel", container: "ReachCloudTrail_CL" });
  assert.equal(key.filters[0].column, "AccessKeyId");
  assert.deepEqual(key.filters[0].alternatives.map((a) => [a.column, a.dynamic]), [["UserIdentity.accessKeyId", true]]);
});

// ---------------------------------------------------------------------------
// Scope "type": this address in every feed I have

import * as concepts from "../app/lib/concepts.js";

const aad = packs.pack("entra-signin");
// The cross-feed intent the two hand-written KQL templates stand in for
// (ct_ip_elsewhere from CloudTrail, aad_ip_elsewhere from Entra): the
// address everywhere, listed newest first, one shared shape.
const ELSEWHERE_CT = {
  scope: "type",
  filter: [{ concept: "source_ip", op: "eq", value: "$value" }],
  window: { since: "$earliest", until: "$latest" },
  shape: { kind: "list", project: ["event_name", "principal_arn", "error_code", "user_agent"], order: { by: "time", dir: "desc" }, take: 200 },
};
const ELSEWHERE_AAD = {
  scope: "type",
  filter: [{ concept: "caller_ip", op: "eq", value: "$value" }],
  window: { since: "$earliest", until: "$latest" },
  shape: { kind: "summary", by: ["result_type"], measures: [{ fn: "count", as: "attempts" }, { fn: "dcount", concept: "user_principal_name", as: "users" }], order: { by: "attempts", dir: "desc" } },
};

test("containersOfType: every container a concept of the type binds on directly, per platform", () => {
  assert.deepEqual(concepts.containersOfType("splunk", "source_ip"), ["aws:cloudtrail", "azure:aad:signin", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"]);
  assert.deepEqual(concepts.containersOfType("sentinel", "source_ip"), ["AWSCloudTrail", "GWorkspace_ReportsAPI_admin_CL", "GWorkspace_ReportsAPI_drive_CL", "GWorkspace_ReportsAPI_login_CL", "Okta_CL", "ReachAzureAD_CL", "ReachCloudTrail_CL", "ReachCrowdStrike_CL", "SigninLogs"]);
  assert.deepEqual(concepts.containersOfType("splunk", "hostname"), ["crowdstrike:events:sensor"]);
  assert.deepEqual(concepts.containersOfType("splunk", "no_such_type"), []);
});

test("validate: scope type refuses record_types and needs-gated filters, and needs a filter", () => {
  assert.deepEqual(intent.validate(ELSEWHERE_CT, (r) => Boolean(ct.concepts[r])), []);
  assert.deepEqual(intent.validate(ELSEWHERE_AAD, (r) => Boolean(aad.concepts[r])), []);
  const bad = (patch) => intent.validate({ ...ELSEWHERE_CT, ...patch }, (r) => Boolean(ct.concepts[r]));
  assert.ok(bad({ record_types: ["ConsoleLogin"] }).some((e) => /scope type cannot filter record_types/.test(e)));
  assert.ok(bad({ filter: [{ concept: "source_ip", op: "eq", value: "$value" }, { concept: "recipient_account_id", op: "eq", value: "$account", needs: ["account"] }] }).some((e) => /filter\[1\]: a scope type filter cannot be needs-gated/.test(e)));
  assert.ok(bad({ filter: [] }).some((e) => /scope type needs at least one filter/.test(e)));
});

test("plan scope type: a union over every container the type lands on, the one in hand first, shared aliases by type id", () => {
  const p = intent.plan(ELSEWHERE_CT, { pack: ct, platform: "splunk", container: "aws:cloudtrail" });
  assert.equal(p.scope, "type");
  assert.equal(p.type, "source_ip");
  assert.deepEqual(p.filters, []);
  assert.deepEqual(p.union.map((u) => u.container), ["aws:cloudtrail", "azure:aad:signin", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"]);
  assert.deepEqual(p.union.map((u) => u.filters[0].column), ["sourceIPAddress", "ipAddress", "aip", "ipAddress", "ip_address", "ipAddress", "src_ip"]);
  assert.deepEqual(p.union.map((u) => u.filters[0].via), ["aws-cloudtrail/source_ip", "entra-signin/caller_ip", "crowdstrike-falcon/aip", "gws/source_ip", "gws/source_ip", "gws/source_ip", "okta/source_ip"]);
  assert.deepEqual(p.shape.project.map((x) => [x.concept, x.alias]), [["event_name", "record_type"], ["principal_arn", "principal"], ["error_code", "outcome"], ["user_agent", "user_agent"]]);
  const cols = (u) => Object.fromEntries(Object.entries(u.columns).map(([k, v]) => [k, v && v.column]));
  assert.deepEqual(cols(p.union[0]), { event_name: "eventName", principal_arn: "userIdentity.arn", error_code: "errorCode", user_agent: "userAgent" });
  // Entra has no record_type column on Splunk; its principal and outcome are the concepts of the same type.
  assert.deepEqual(cols(p.union[1]), { event_name: null, principal_arn: "userPrincipalName", error_code: "status.errorCode", user_agent: "userAgent" });
  assert.deepEqual(p.union[1].columns.principal_arn.via, "entra-signin/user_principal_name");
  assert.deepEqual(cols(p.union[2]), { event_name: "event_simpleName", principal_arn: null, error_code: null, user_agent: null });
  // gws binds no concept of type "principal" beyond actor_email and no outcome or user_agent concept at all.
  assert.deepEqual(cols(p.union[3]), { event_name: "event.type", principal_arn: "actor.email", error_code: null, user_agent: null });
  assert.deepEqual(cols(p.union[4]), { event_name: "type", principal_arn: "email", error_code: null, user_agent: null });
  assert.deepEqual(cols(p.union[5]), { event_name: "event.type", principal_arn: "actor.email", error_code: null, user_agent: null });
  // okta's widest-bound principal and outcome concepts each have a top-level alias column, preferred over the dotted extracted one.
  assert.deepEqual(cols(p.union[6]), { event_name: "eventType", principal_arn: "user", error_code: "result", user_agent: "client.userAgent.rawUserAgent" });
  assert.deepEqual(p.dropped, []);
  assert.deepEqual(p.unresolved, []);
  assert.deepEqual(p.params.sort(), ["earliest", "latest", "value"]);
  // From another container of the union, that one leads.
  const fromEntra = intent.plan(ELSEWHERE_CT, { pack: ct, platform: "splunk", container: "azure:aad:signin" });
  assert.deepEqual(fromEntra.union.map((u) => u.container), ["azure:aad:signin", "aws:cloudtrail", "crowdstrike:events:sensor", "gws:reports:admin", "gws:reports:drive", "gws:reports:login", "OktaIM2:log"]);
  // On Sentinel: the connector tables and the dev sample tables alike; a dynamic path is flagged.
  const s = intent.plan(ELSEWHERE_CT, { pack: ct, platform: "sentinel", container: "AWSCloudTrail" });
  assert.deepEqual(s.union.map((u) => [u.container, u.filters[0].column]), [["AWSCloudTrail", "SourceIpAddress"], ["GWorkspace_ReportsAPI_admin_CL", "IPAddress"], ["GWorkspace_ReportsAPI_drive_CL", "IPAddress"], ["GWorkspace_ReportsAPI_login_CL", "IPAddress"], ["Okta_CL", "client_ipAddress_s"], ["ReachAzureAD_CL", "CallerIpAddress"], ["ReachCloudTrail_CL", "SourceIpAddress"], ["ReachCrowdStrike_CL", "Aip"], ["SigninLogs", "IPAddress"]]);
  assert.equal(s.time, "TimeGenerated");
  const sAad = s.union.find((u) => u.container === "ReachAzureAD_CL");
  assert.equal(sAad.columns.event_name.column, "Category");
  assert.equal(sAad.columns.error_code.column, "ResultType");
});

test("plan scope type: the stand-in for a type is the concept bound most widely, then a top-level column, then declaration order; both SIEMs pick alike", () => {
  // The Entra edge lands its principal (user_principal_name) and outcome (result_type) on CloudTrail's
  // six principal and five outcome concepts: principal_arn and error_code, on both platforms.
  const spl = intent.plan(ELSEWHERE_AAD, { pack: aad, platform: "splunk", container: "azure:aad:signin" });
  const ctSpl = spl.union.find((u) => u.container === "aws:cloudtrail");
  assert.deepEqual([ctSpl.columns.result_type.column, ctSpl.columns.result_type.via], ["errorCode", "aws-cloudtrail/error_code"]);
  assert.deepEqual([ctSpl.columns.user_principal_name.column, ctSpl.columns.user_principal_name.via], ["userIdentity.arn", "aws-cloudtrail/principal_arn"]);
  const kql = intent.plan(ELSEWHERE_AAD, { pack: aad, platform: "sentinel", container: "SigninLogs" });
  const ctKql = kql.union.find((u) => u.container === "AWSCloudTrail");
  assert.deepEqual([ctKql.columns.result_type.column, ctKql.columns.user_principal_name.column], ["ErrorCode", "UserIdentityArn"]);
  // Two outcome concepts bound as widely: result_type, declared before result_signature, wins on the Entra tables.
  const aadKql = intent.plan(ELSEWHERE_CT, { pack: ct, platform: "sentinel", container: "AWSCloudTrail" }).union.find((u) => u.container === "SigninLogs");
  assert.equal(aadKql.columns.error_code.via, "entra-signin/result_type");
  // The summary shape: by and measures name their aliases; the measure without a concept has none.
  assert.deepEqual(kql.shape.by, [{ concept: "result_type", type: "outcome", alias: "outcome" }]);
  assert.deepEqual(kql.shape.measures.map((m) => [m.fn, m.concept, m.alias, m.as]), [["count", null, null, "attempts"], ["dcount", "user_principal_name", "principal", "users"]]);
  assert.deepEqual(kql.shape.order, { by: "attempts", dir: "desc" });
});

test("plan scope type: a container that cannot resolve a filter concept is dropped; none left is a PlanError; a type is required", () => {
  const withUa = { ...ELSEWHERE_CT, filter: [{ concept: "source_ip", op: "eq", value: "$value" }, { concept: "user_agent", op: "contains", value: "$ua" }] };
  const p = intent.plan(withUa, { pack: ct, platform: "splunk", container: "aws:cloudtrail" });
  assert.deepEqual(p.union.map((u) => u.container), ["aws:cloudtrail", "azure:aad:signin", "OktaIM2:log"]);
  // crowdstrike and all three gws containers carry no user_agent concept, so this filter drops them; okta does bind one and survives.
  assert.deepEqual(p.dropped, [
    { container: "crowdstrike:events:sensor", reason: "no column for user_agent (user_agent)" },
    { container: "gws:reports:admin", reason: "no column for user_agent (user_agent)" },
    { container: "gws:reports:drive", reason: "no column for user_agent (user_agent)" },
    { container: "gws:reports:login", reason: "no column for user_agent (user_agent)" },
  ]);
  assert.deepEqual(p.params.sort(), ["earliest", "latest", "ua", "value"]);
  // The Falcon host id lands on no other feed: only Falcon's containers qualify.
  const falcon = packs.pack("crowdstrike-falcon");
  const host = intent.plan({ scope: "type", filter: [{ concept: "aid", op: "eq", value: "$value" }], window: { since: "$earliest" }, shape: { kind: "list", project: ["event_simple_name"] } }, { pack: falcon, platform: "sentinel", container: "ReachCrowdStrike_CL" });
  assert.deepEqual(host.union.map((u) => u.container), ["ReachCrowdStrike_CL"]);
  // No container carries both a host id (Falcon only) and a user agent (the other two): nothing to union.
  assert.throws(() => intent.plan({ ...ELSEWHERE_CT, filter: [{ concept: "source_ip", op: "eq", value: "$value" }, { concept: "crowdstrike-falcon/aid", op: "eq", value: "$aid" }, { concept: "user_agent", op: "exists" }] }, { pack: ct, platform: "sentinel", container: "SigninLogs" }), (e) => e instanceof intent.PlanError && e.code === "no_containers" && /SigninLogs: no column for crowdstrike-falcon\/aid \(host_id\)/.test(e.message) && /ReachCrowdStrike_CL: no column for user_agent \(user_agent\)/.test(e.message));
  // A filter concept without a taxonomy type (here: none at all) cannot span feeds; an explicit type option stands in.
  assert.throws(() => intent.plan({ ...ELSEWHERE_CT, filter: [{ concept: "no_such", op: "eq", value: "$value" }] }, { pack: ct, platform: "splunk", container: "aws:cloudtrail" }), (e) => e instanceof intent.PlanError && e.code === "no_type");
  const given = intent.plan({ ...ELSEWHERE_CT, shape: { kind: "list", project: ["event_name"] } }, { pack: ct, platform: "splunk", container: "aws:cloudtrail", type: "hostname" });
  assert.deepEqual(given.union.map((u) => u.container), ["crowdstrike:events:sensor"], "the given type decides the containers; the filter still resolves by its own concept");
  assert.equal(given.union[0].filters[0].column, "aip");
  // A projected concept the type never lands on anywhere is listed unresolved, not fatal.
  const q = intent.plan({ ...ELSEWHERE_CT, shape: { kind: "list", project: ["event_name", "tls_cipher_suite"] } }, { pack: ct, platform: "splunk", container: "azure:aad:signin" });
  assert.deepEqual(q.unresolved, []);
  assert.equal(q.union.find((u) => u.container === "azure:aad:signin").columns.tls_cipher_suite, null);
  // Two projected concepts of one type would share an alias: refused.
  assert.throws(() => intent.plan({ ...ELSEWHERE_CT, shape: { kind: "list", project: ["principal_arn", "session_issuer_arn"] } }, { pack: ct, platform: "splunk", container: "aws:cloudtrail" }), (e) => e instanceof intent.PlanError && e.code === "alias_clash");
});
