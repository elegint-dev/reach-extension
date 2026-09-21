import { test } from "node:test";
import assert from "node:assert/strict";
import * as kql from "../app/lib/kql.js";

test("quote escapes the four KQL escapes and never breaks out", () => {
  assert.equal(kql.quote('a"b\\c\nd'), '"a\\"b\\\\c\\nd"');
  assert.equal(kql.quote(null), '""');
});

test("identifiers and columns are validated, never interpolated raw", () => {
  assert.equal(kql.table("ReachCloudTrail_CL"), "ReachCloudTrail_CL");
  assert.throws(() => kql.table("Bad Name"), /identifier/);
  assert.throws(() => kql.table("T | where 1==1"), /identifier/);
  assert.equal(kql.column("UserIdentity.type"), "UserIdentity.type");
  assert.throws(() => kql.column("x; drop"), /column/);
});

test("time literals accept Splunk and KQL shapes", () => {
  assert.equal(kql.timeLiteral("-24h"), "ago(24h)");
  assert.equal(kql.timeLiteral("7d"), "ago(7d)");
  assert.equal(kql.timeLiteral("now"), "now()");
  assert.equal(kql.timeLiteral("ago(30m)"), "ago(30m)");
  assert.equal(kql.timeLiteral("2026-09-17T23:06:00Z"), "datetime(2026-09-17T23:06:00Z)");
  assert.throws(() => kql.timeLiteral('"); drop'), /not a time/);
});

test("lint refuses shape hazards and warns on a missing time predicate", () => {
  assert.equal(kql.lint("").ok, false);
  assert.equal(kql.lint("| where x").ok, false);
  assert.match(kql.lint("search * | take 1").violations[0], /unbounded/);
  assert.match(kql.lint('T | where a == "x').violations[0], /unterminated/);
  assert.match(kql.lint("T | where (a == 1").violations[0], /parentheses/);
  const ok = kql.lint("T | where TimeGenerated > ago(1d) | take 5");
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.warnings, []);
  assert.match(kql.lint("T | take 5").warnings[0], /time predicate/);
});

test("tablesIn finds the tables a query reads", () => {
  assert.deepEqual(kql.tablesIn("ReachCloudTrail_CL\n| where TimeGenerated > ago(1d)\n| project Type"), ["ReachCloudTrail_CL"]);
  assert.deepEqual(kql.tablesIn("union withsource=T ReachAzureAD_CL, ReachCrowdStrike_CL | summarize count() by T"), ["ReachAzureAD_CL", "ReachCrowdStrike_CL"]);
  assert.deepEqual(kql.tablesIn("let S = SecurityEvent | take 5;\nS | join kind=inner (SigninLogs | project UserPrincipalName) on $left.Account == $right.UserPrincipalName"), ["SecurityEvent", "S", "SigninLogs"]);
  assert.deepEqual(kql.tablesIn('// a comment naming Heartbeat\nUsage | where DataType == "Perf"'), ["Usage"]);
});

test("resource ids and deep links", async () => {
  const rid = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
  assert.equal(kql.isResourceId(rid), true);
  assert.equal(kql.isResourceId("/subscriptions/x"), false);
  assert.equal(kql.workspaceNameOf(rid), "sentinel");
  const hash = `#view/Microsoft_Azure_Monitoring_Logs/LogsBlade/resourceId/${encodeURIComponent(rid)}/source/LogsBlade.AnalyticsShareLinkToQuery/q/abc/timespan/P2D`;
  assert.equal(kql.resourceIdFromHash(hash), rid);
  assert.equal(kql.resourceIdFromHash("#home"), null);
  assert.equal(kql.timespanFor("7d"), "P7D");
  assert.equal(kql.timespanFor("12h"), "PT12H");
  const url = await kql.deepLink({ resourceId: rid, kql: "ReachCloudTrail_CL | take 1", timespan: "P1D" });
  assert.match(url, /^https:\/\/portal\.azure\.com\/#view\/Microsoft_Azure_Monitoring_Logs\/LogsBlade\/resourceId\/%2Fsubscriptions%2F/);
  assert.match(url, /\/source\/LogsBlade\.AnalyticsShareLinkToQuery\/q\/H4sI/);
  assert.match(url, /\/timespan\/P1D$/);
  const q = decodeURIComponent(url.split("/q/")[1].split("/timespan/")[0]);
  const zlib = await import("node:zlib");
  assert.equal(zlib.gunzipSync(Buffer.from(q, "base64")).toString(), "ReachCloudTrail_CL | take 1");
  await assert.rejects(() => kql.deepLink({ resourceId: "nope", kql: "T" }), /resource id/);
});

test("the workspace is read off every blade hash the portal lands on, not only the Logs deep link", () => {
  const rid = "/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel";
  const enc = encodeURIComponent(rid);
  const hashes = {
    "Sentinel menu blade (portal search → workspace → Logs)": `#view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/8/id/${enc}`,
    "Sentinel menu blade, other item": `#view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/0/id/${enc}`,
    "workspace resource menu, raw id, Logs item": `#@contoso.onmicrosoft.com/resource${rid}/logs`,
    "workspace resource menu, raw id, overview": `#@contoso.onmicrosoft.com/resource${rid}/Overview`,
    "Logs.ReactView after the deep link redirects": `#view/Microsoft_OperationsManagementSuite_Workspace/Logs.ReactView/resourceId/${enc}/source/LogsBlade.AnalyticsShareLinkToQuery/q/abc/timespan/P1D`,
    "legacy #blade form": `#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/resourceId/${enc}`,
    "encoded twice": `#view/Microsoft_Azure_Monitoring_Logs/LogsBlade/resourceId/${encodeURIComponent(enc)}/source/x`,
    "lower-case segments": `#view/Microsoft_Azure_Security_Insights/MainMenuBlade/~/8/id/${encodeURIComponent(rid.replace("resourceGroups", "resourcegroups"))}`,
  };
  for (const [what, hash] of Object.entries(hashes)) {
    const got = kql.resourceIdFromHash(hash);
    assert.ok(got && got.toLowerCase() === rid.toLowerCase(), `${what}: ${got}`);
  }
  assert.equal(kql.resourceIdFromHash("#view/Microsoft_Azure_Security_Insights/WorkspaceSelectorBlade"), null);
  assert.equal(kql.resourceIdFromHash(`#@contoso/resource/subscriptions/ddf67caf-c4c0-41c7-876e-9cc944494a46/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1/overview`), null, "another resource type is not a workspace");
  assert.equal(kql.resourceIdFromHash("%E0%A4%A"), null, "a hash that does not decode is no workspace");
  assert.equal(kql.resourceIdFromHash(""), null);
});
