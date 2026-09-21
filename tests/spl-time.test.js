// Workflow time inputs: relative forms pass through, an ISO stamp is
// rendered as Splunk reads it (or as a KQL datetime on Sentinel), and the
// process-events shape reaches the children through ParentProcessId. The
// searches are the crowdstrike-falcon pack's queries, so the packs load first.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as spl from "../app/lib/spl.js";
import * as kql from "../app/lib/kql.js";
import * as fdr from "../app/lib/fdr-queries.js";
import * as catalogue from "../app/lib/catalogue.js";

await catalogue.load();

const AID = "a".repeat(32);

test("timeModifier: relative forms and epochs pass through untouched", () => {
  for (const v of ["-24h", "-7d@d", "now", "@d", "1658918400", "+1h"]) assert.equal(spl.timeModifier(v), v);
});

test("timeModifier: a zone-less ISO stamp becomes %m/%d/%Y:%H:%M:%S, quoted", () => {
  assert.equal(spl.timeModifier("2022-07-27T10:40:00"), '"07/27/2022:10:40:00"');
  assert.equal(spl.timeModifier("2022-07-27 10:40"), '"07/27/2022:10:40:00"');
  assert.equal(spl.timeModifier("2022-07-27"), '"07/27/2022:00:00:00"');
  assert.equal(spl.timeModifier("2022-07-27T10:40:00.250"), '"07/27/2022:10:40:00"');
});

test("timeModifier: an ISO stamp with Z or an offset names an instant and becomes epoch seconds", () => {
  assert.equal(spl.timeModifier("2022-07-27T10:40:00Z"), "1658918400");
  assert.equal(spl.timeModifier("2022-07-27T10:40:00+02:00"), "1658911200");
  assert.equal(spl.timeModifier("2022-07-27T10:40:00-0500"), "1658936400");
});

test("timeModifier: anything else is quoted as given", () => {
  assert.equal(spl.timeModifier("last tuesday"), '"last tuesday"');
});

test("an ISO window on the pid lookup renders a search Splunk accepts, inline and through the macro", () => {
  const params = { aid: AID, pid: "936", earliest: "2022-07-27T10:40:00", latest: "2022-07-27T10:50:00" };
  const inline = fdr.generate({ kind: "pid_lookup" }, params);
  assert.match(inline.spl, /earliest="07\/27\/2022:10:40:00" latest="07\/27\/2022:10:50:00"/);
  assert.ok(!inline.spl.includes("2022-07-27T"), "the ISO form never reaches the search");
  const macro = fdr.generate({ kind: "pid_lookup" }, { ...params, latest: "now" }, { form: "macro" });
  assert.equal(macro.form, "macro");
  assert.match(macro.spl, /`cs_pid_lookup\("a{32}", "936", "07\/27\/2022:10:40:00"\)`/);
});

test("KQL renders the same ISO stamp as a datetime literal", () => {
  assert.equal(kql.timeLiteral("2022-07-27T10:40:00"), "datetime(2022-07-27T10:40:00)");
  assert.equal(kql.timeLiteral("2022-07-27T10:40:00Z"), "datetime(2022-07-27T10:40:00Z)");
  assert.equal(kql.timeLiteral("-24h"), "ago(24h)");
});

test("process_events matches the process as ContextProcessId, TargetProcessId or ParentProcessId, so its children are in the result", () => {
  const out = fdr.generate({ kind: "process_events" }, { aid: AID, tpid: "255667414", earliest: "-24h", latest: "now" });
  assert.match(out.spl, /\(ContextProcessId="255667414" OR TargetProcessId="255667414" OR ParentProcessId="255667414"\)/);
  assert.match(out.spl, /\| table [^\n]*ParentProcessId/);
  assert.equal(out.asserted, true);
});
