// The other side of the concept model: this file pins the platform to
// Sentinel (each test file is its own process), so the same packs answer
// for tables and columns, in KQL.
import "./_sentinel.js";
import "./_bundle.js";
import "./_core-packs.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as concepts from "../app/lib/concepts.js";
import * as packs from "../app/lib/packs.js";
import * as workflows from "../app/lib/workflows.js";
import * as catalogue from "../app/lib/catalogue.js";
import { generate } from "../app/lib/pivot.js";
import { PLATFORM } from "../app/lib/platform.js";

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

beforeEach(async () => {
  await catalogue.importUser({ format: "reach-catalogue", version: 2, sourcetypes: {}, concepts: {} }, { mode: "replace" });
});

const ARN = "aws-cloudtrail/principal_arn";

test("the sample Falcon table carries the hash and path the verdict reads, and records that it has no signing columns", () => {
  assert.equal(catalogue.fieldOn("ReachCrowdStrike_CL", "SHA256HashData").concept.key, "crowdstrike-falcon/sha256");
  assert.equal(catalogue.fieldOn("ReachCrowdStrike_CL", "ImageFileName").concept.key, "crowdstrike-falcon/image_file_name");
  assert.equal(catalogue.fieldOn("ReachCrowdStrike_CL", "SigningId"), null, "not in the seeded sample, so not bound");
  assert.equal(catalogue.fieldOn("ReachCrowdStrike_CL", "TeamId"), null);
  assert.equal(concepts.bindingsOf("crowdstrike-falcon/signing_id", "sentinel").length, 0);
  assert.match(concepts.container("sentinel", "ReachCrowdStrike_CL").note, /no SigningId, TeamId, CodeSigningFlags or CsValidationCategory column/);
});

test("a Sentinel value click on PrincipalArn shows the CloudTrail feed's one record", () => {
  const v = catalogue.fieldOn("ReachCloudTrail_CL", "PrincipalArn");
  assert.equal(v.concept.key, ARN);
  assert.equal(v.concept.label, "Principal ARN");
  assert.equal(v.meaning.source, "pack");
  assert.equal(v.meaning.packId, "aws-cloudtrail");
  assert.equal(v.meaning.description, concepts.concept(ARN).description, "the same prose Splunk's userIdentity.arn shows");
  assert.equal(v.binding.column, "PrincipalArn");
  assert.equal(v.scope, "sourcetype");
  // The nested path and Microsoft's connector column resolve to it too.
  assert.equal(catalogue.fieldOn("ReachCloudTrail_CL", "UserIdentity.arn").concept.key, ARN);
  assert.match(catalogue.fieldOn("ReachCloudTrail_CL", "UserIdentity.arn").binding.note, /dynamic column/);
  assert.equal(catalogue.fieldOn("AWSCloudTrail", "UserIdentityArn").concept.key, ARN);
  // The v1 sample pack's own prose is gone; the samples pack only binds.
  assert.equal(Object.keys(packs.pack("reach-sentinel-samples").concepts).length, 3);
  assert.equal(catalogue.fieldOn("ReachCloudTrail_CL", "RawEvent").concept.key, "reach-sentinel-samples/raw_event");
});

test("tables, columns, discriminators and decodes come through the bindings", () => {
  const names = catalogue.sourcetypes().map((s) => s.name);
  for (const t of ["ReachCloudTrail_CL", "ReachAzureAD_CL", "ReachCrowdStrike_CL", "AWSCloudTrail", "SigninLogs"]) assert.ok(names.includes(t), t);
  assert.ok(!names.includes("aws:cloudtrail"), "Splunk containers are not listed here");
  const ct = catalogue.sourcetype("ReachCloudTrail_CL");
  assert.equal(ct.packId, "aws-cloudtrail", "the feed, not the loader, is the table's pack");
  assert.equal(ct.discriminator, "EventName");
  assert.equal(catalogue.discriminators().ReachAzureAD_CL, "Category");
  assert.equal(catalogue.discriminators().ReachCrowdStrike_CL, "EventSimpleName");
  assert.equal(catalogue.discriminators().AWSCloudTrail, "EventName");
  assert.ok(catalogue.fieldsOn("ReachCloudTrail_CL").includes("UserIdentity.accessKeyId"));
  assert.deepEqual(Object.keys(catalogue.decodeOn("ReachAzureAD_CL", "ResultType").values).slice(0, 2), ["0", "50034"]);
  assert.equal(catalogue.decodeOn("SigninLogs", "ResultType").source, "pack", "the decode follows the concept onto the production table");
  assert.equal(catalogue.fieldOn("SigninLogs", "IPAddress").concept.key, "entra-signin/caller_ip");
  assert.equal(catalogue.fieldOn("ReachAzureAD_CL", "IpAddress").binding.alias_of, "CallerIpAddress");
});

test("edges resolve onto the table in hand and render KQL that lints", () => {
  const es = catalogue.edgesFrom("ReachCloudTrail_CL", "PrincipalArn");
  const ids = es.map((e) => e.id);
  assert.ok(ids.includes("ct_principal_activity") && ids.includes("ct_principal_calls") && ids.includes("ct_principal_failures"), ids.join(","));
  assert.ok(!ids.includes("ct_identity_arn"), "the nested-path twin edge is gone");
  for (const e of es) {
    assert.equal(e.dst.sourcetype, "ReachCloudTrail_CL");
    assert.ok(e.kql, e.id);
    const out = generate(e, { value: "arn:aws:iam::1:user/x", earliest: "-24h", latest: "now" }, { pack: packs.pack(e.packId) });
    assert.equal(out.lang, "kql");
    assert.ok(out.spl.startsWith("ReachCloudTrail_CL"), out.spl);
    assert.ok(out.hazards.length >= 1, `${e.id}: the edge's hazards ride along`);
  }
  // The nested path shares the concept's edges.
  assert.ok(catalogue.edgesFrom("ReachCloudTrail_CL", "UserIdentity.arn").some((e) => e.id === "ct_principal_activity"));
  // A key created here is followed to its later use: a real pivot between two concepts.
  const created = catalogue.edgesFrom("ReachCloudTrail_CL", "ResponseElements.accessKey.accessKeyId");
  assert.deepEqual(created.map((e) => [e.id, e.dst.field]), [["ct_key_created_use", "AccessKeyId"]]);
  // Since 0.4.46 every within-feed edge is compiled from its intent on the sample table too (the hand-written KQL was retired).
  assert.equal(es.find((e) => e.id === "ct_principal_activity").compiled, true);
  const logins = es.find((e) => e.id === "ct_console_logins");
  assert.equal(logins.compiled, true, "the intent compiles onto the sample table");
  assert.match(generate(logins, { value: "arn:x", earliest: "-1d" }, { pack: packs.pack("aws-cloudtrail") }).spl, /EventName == "ConsoleLogin"/);
});

test("a production table with bindings and no template gets its pivots compiled from intent", () => {
  const ms = catalogue.edgesFrom("AWSCloudTrail", "UserIdentityArn");
  const activity = ms.find((e) => e.id === "ct_principal_activity");
  assert.ok(activity, ms.map((e) => e.id).join(","));
  assert.equal(activity.compiled, true);
  assert.ok(activity.kql && Array.isArray(activity.kql.lines));
  assert.equal(activity.spl, undefined);
  assert.deepEqual(activity.dst, { sourcetype: "AWSCloudTrail", field: "UserIdentityArn" });
  assert.equal(activity.templatePackId, null);
  assert.ok(activity.hazards.some((h) => /TimeGenerated/.test(h.text)) && !activity.hazards.some((h) => /_time/.test(h.text)), "the edge's own hazards, worded for Sentinel");
  const out = generate(activity, { value: "arn:aws:iam::1:user/x", earliest: "-24h", latest: "now", account: "1" }, { pack: packs.pack("aws-cloudtrail") });
  assert.equal(out.lang, "kql");
  assert.ok(out.spl.startsWith("AWSCloudTrail\n| where TimeGenerated > ago(24h)"), out.spl);
  assert.match(out.spl, /UserIdentityArn == "arn:aws:iam::1:user\/x"/);
  assert.match(out.spl, /RecipientAccountId == "1"/);
  assert.match(out.spl, /summarize calls = count\(\)/);
  assert.deepEqual(out.missing, []);
  assert.ok(ms.length >= 3, "calls and failures come along");
  assert.ok(ms.every((e) => e.compiled && e.dst.sourcetype === "AWSCloudTrail"));
  // The same on the Entra vendor table, from the other pack.
  const signins = catalogue.edgesFrom("SigninLogs", "UserPrincipalName").find((e) => e.id === "aad_user_signins");
  assert.ok(signins && signins.compiled && signins.kql);
  const r = generate(signins, { value: "a@b.c", earliest: "-7d" }, { pack: packs.pack("entra-signin") });
  assert.match(r.spl, /^SigninLogs\n/);
  assert.match(r.spl, /UserPrincipalName =~ "a@b.c"/);
  assert.match(r.spl, /\| project TimeGenerated, ResultType, ResultDescription, IPAddress/);
  // Every resolved edge on every Sentinel table renders and lints (generate throws on a lint failure).
  const all = catalogue.sourcetypes().flatMap((s) => packs.edgesOn(s.name));
  assert.ok(all.length >= 40, String(all.length));
  assert.ok(all.every((e) => e.compiled), "no hand-written KQL remains: every view is compiled from intent");
  for (const e of all) {
    const g = generate(e, { value: "v", earliest: "-1d", latest: "now", aid: "a", account: "1" }, { pack: packs.pack(e.packId) });
    assert.equal(g.lang, "kql", e.id);
    assert.deepEqual(g.missing, [], `${e.id} on ${e.dst.sourcetype}`);
  }
});

test("cross-feed pivots come from the taxonomy: this address in every table of the type, compiled as one union led by the table in hand", () => {
  const fromEntra = catalogue.edgesFrom("ReachAzureAD_CL", "CallerIpAddress").find((e) => e.id === "aad_ip_elsewhere");
  assert.ok(fromEntra && fromEntra.compiled && fromEntra.kql);
  assert.deepEqual(fromEntra.dst, { sourcetype: "ReachAzureAD_CL", field: "CallerIpAddress" });
  assert.equal(fromEntra.label, "This address in other feeds");
  assert.equal(fromEntra.concept.type, "source_ip");
  assert.deepEqual(fromEntra.union, ["ReachAzureAD_CL", "AWSCloudTrail", "GWorkspace_ReportsAPI_admin_CL", "GWorkspace_ReportsAPI_drive_CL", "GWorkspace_ReportsAPI_login_CL", "Okta_CL", "ReachCloudTrail_CL", "ReachCrowdStrike_CL", "SigninLogs"]);
  const r = generate(fromEntra, { value: "203.0.113.9", earliest: "-7d" }, { pack: packs.pack("entra-signin") });
  assert.match(r.spl, /^union \(ReachAzureAD_CL\n/);
  assert.match(r.spl, /\(ReachCloudTrail_CL\n  \| where TimeGenerated > ago\(7d\)\n  \| where SourceIpAddress == "203.0.113.9"/);
  assert.match(r.spl, /\| project TimeGenerated, Type, record_type = tostring\(EventName\), principal = tostring\(PrincipalArn\), outcome = tostring\(ErrorCode\), user_agent = tostring\(UserAgent\)\)/);
  assert.deepEqual(r.missing, []);
  const fromCt = catalogue.edgesFrom("ReachCloudTrail_CL", "SourceIpAddress").find((e) => e.id === "ct_ip_elsewhere");
  assert.deepEqual(fromCt.dst, { sourcetype: "ReachCloudTrail_CL", field: "SourceIpAddress" });
  assert.equal(fromCt.union[0], "ReachCloudTrail_CL");
  assert.ok(catalogue.edgesFrom("AWSCloudTrail", "SourceIpAddress").some((e) => e.id === "ct_ip_elsewhere" && e.union[0] === "AWSCloudTrail"), "the connector table has it too");
  assert.ok(!catalogue.edgesFrom("ReachCloudTrail_CL", "SourceIpAddress").some((e) => e.id === "aad_ip_elsewhere"), "not offered from another feed's source");
  assert.equal(packs.pack("reach-sentinel-samples").templates.length, 0, "the hand-written cross-feed KQL is retired");
});

test("a compiled pivot on a sample table carries the replay-time hazard; one on a production table does not", () => {
  assert.deepEqual(concepts.container("sentinel", "ReachCloudTrail_CL").hazards.map((h) => h.id), ["replay_time"]);
  for (const st of ["ReachAzureAD_CL", "ReachCrowdStrike_CL", "ReachCloudTrail_CL"]) {
    const es = packs.edgesOn(st).filter((e) => e.compiled);
    assert.ok(es.length > 0, st);
    for (const e of es) assert.ok(e.hazards.some((h) => h.id === "replay_time"), `${st}/${e.id}: ${e.hazards.map((h) => h.id)}`);
  }
  for (const st of ["AWSCloudTrail", "SigninLogs"]) {
    const es = packs.edgesOn(st).filter((e) => e.compiled);
    assert.ok(es.length > 0, st);
    for (const e of es) assert.ok(!e.hazards.some((h) => h.id === "replay_time"), `${st}/${e.id}: production table, no sample-loader hazard`);
  }
});

test("params and workflow entries resolve to this table's columns", () => {
  assert.equal(packs.params("aws-cloudtrail", "ReachCloudTrail_CL").account.from_field, "RecipientAccountId");
  assert.match(packs.params("aws-cloudtrail", "ReachCloudTrail_CL").earliest.hint, /TimeGenerated/, "the pack's words for this platform");
  const activity = catalogue.edgesFrom("ReachCloudTrail_CL", "PrincipalArn").find((e) => e.id === "ct_principal_activity");
  assert.ok(activity.hazards.some((h) => /TimeGenerated/.test(h.text)) && !activity.hazards.some((h) => /_time/.test(h.text)), "hazards worded for Sentinel");
  assert.equal(packs.params("crowdstrike-falcon", "ReachCrowdStrike_CL").aid.from_field, "Aid");
  const w = packs.workflow("ct_principal");
  assert.ok(w.entries.some((e) => e.sourcetype === "ReachCloudTrail_CL" && e.field === "PrincipalArn" && e.param === "arn"));
  assert.ok(w.entries.some((e) => e.sourcetype === "AWSCloudTrail" && e.field === "UserIdentityArn" && e.param === "arn"), "the connector table's pivots are compiled from intent, so the workflow is offered there too");
  assert.deepEqual(workflows.forField("AWSCloudTrail", "UserIdentityArn").map((r) => [r.id, r.param]), [["ct_principal", "arn"]]);
  assert.deepEqual(workflows.forField("ReachCloudTrail_CL", "PrincipalArn").map((r) => [r.id, r.param]), [["ct_principal", "arn"]]);
  assert.ok(!w.entries.some((e) => e.sourcetype === "aws:cloudtrail"));
  const def = workflows.get("ct_principal", { params: { st: "ReachCloudTrail_CL" } });
  const results = def.results({ arn: "arn:x", earliest: "-1d" });
  const withPivot = results.filter((r) => r.pivot);
  assert.ok(withPivot.length >= 4, "every result renders: three from the sample table's KQL templates, console sign-ins compiled from intent");
  const logins = results.find((r) => r.id === "logins").pivot;
  assert.equal(logins.edge.compiled, true);
  assert.match(generate(logins.edge, { value: "arn:x", earliest: "-1d" }, { pack: packs.pack("aws-cloudtrail") }).spl, /EventName == "ConsoleLogin"/);
  for (const r of withPivot) assert.equal(r.pivot.edge.dst.sourcetype, "ReachCloudTrail_CL", r.id);
  const ms = workflows.get("ct_principal", { params: { st: "AWSCloudTrail" } }).results({ arn: "arn:x", earliest: "-1d" });
  assert.ok(ms.filter((r) => r.pivot).length >= 4, "on the connector table every result is a compiled pivot");
  for (const r of ms.filter((r) => r.pivot)) assert.equal(r.pivot.edge.dst.sourcetype, "AWSCloudTrail", r.id);
  const e = packs.edge("aws-cloudtrail", "ct_principal_activity");
  assert.ok(["AWSCloudTrail", "ReachCloudTrail_CL"].includes(e.dst.sourcetype), "without a container in hand, the first Sentinel table with a compiled view");
  assert.ok(e.kql);
  assert.equal(packs.edge("aws-cloudtrail", "ct_principal_activity", { container: "ReachCloudTrail_CL" }).dst.sourcetype, "ReachCloudTrail_CL");
});

test("a note written on Splunk shows here, labelled; one written here is keyed the same way", async () => {
  const fromSplunk = {
    format: "reach-catalogue",
    version: 2,
    sourcetypes: {},
    concepts: { [ARN]: { description: "Platform team role sessions.", updated_at: "2026-09-01T00:00:00Z", written_on: { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn" } } },
  };
  await catalogue.importUser(fromSplunk, { mode: "merge" });
  const v = catalogue.fieldOn("ReachCloudTrail_CL", "PrincipalArn");
  assert.equal(v.meaning.source, "user");
  assert.equal(v.meaning.description, "Platform team role sessions.");
  assert.deepEqual(v.meaning.writtenOn, { platform: "splunk", container: "aws:cloudtrail", column: "userIdentity.arn" });
  assert.equal(catalogue.fieldOn("AWSCloudTrail", "UserIdentityArn").meaning.description, "Platform team role sessions.");

  await catalogue.annotate("ReachCloudTrail_CL", "UserIdentity.arn", { description: "Edited in the portal." });
  const u = catalogue.userLayer();
  assert.deepEqual(u.concepts[ARN].written_on, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "UserIdentity.arn" });
  assert.equal(catalogue.fieldOn("ReachCloudTrail_CL", "PrincipalArn").meaning.description, "Edited in the portal.");
  assert.deepEqual(catalogue.fieldOn("ReachCloudTrail_CL", "PrincipalArn").meaning.writtenOn, { platform: "sentinel", container: "ReachCloudTrail_CL", column: "UserIdentity.arn" }, "a different column of the same table still says where");
  assert.equal(catalogue.fieldOn("ReachCloudTrail_CL", "UserIdentity.arn").meaning.writtenOn, undefined);
});

test("a click with no table still names a column: one bound table is the table, several on one concept is the meaning", () => {
  assert.deepEqual(catalogue.inferSourcetype("PrincipalArn"), { sourcetype: "ReachCloudTrail_CL", concept: ARN, basis: "column" });
  assert.deepEqual(catalogue.inferSourcetype("UserIdentityArn"), { sourcetype: "AWSCloudTrail", concept: ARN, basis: "column" });
  const raw = catalogue.inferSourcetype("RawEvent");
  assert.deepEqual(raw.sourcetypes, ["ReachAzureAD_CL", "ReachCloudTrail_CL", "ReachCrowdStrike_CL"]);
  assert.equal(raw.concept, "reach-sentinel-samples/raw_event");
  const ua = catalogue.inferSourcetype("UserAgent");
  assert.equal(ua.concept, null, "UserAgent is a column on several feeds' tables: no single concept");
  assert.ok(ua.sourcetypes.length >= 3);
  assert.deepEqual(catalogue.inferSourcetype("UserAgent", ["ReachAzureAD_CL"]), { sourcetype: "ReachAzureAD_CL", concept: "entra-signin/user_agent", basis: "column" }, "the page's candidates narrow it");
  assert.equal(catalogue.inferSourcetype("NoSuchColumn"), null);
});
