import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseJob, explain } from "../app/lib/advisor.js";

const fx = JSON.parse(readFileSync(new URL("./fixtures/efficiency-env.json", import.meta.url), "utf8"));
const entry = fx.job.entry[0];

test("job stats: a job entry parses to numbers, the sid and the text Splunk actually ran", () => {
  const s = parseJob(entry);
  assert.equal(s.sid, "1758211200.4242");
  assert.equal(s.scanCount, 120000);
  assert.equal(s.eventCount, 400);
  assert.equal(s.resultCount, 400);
  assert.equal(s.runDuration, 12.53);
  assert.equal(s.isDone, true);
  assert.ok(s.optimizedSearch.startsWith("| search index=main"));
  assert.equal(s.earliestTime, "2026-09-17T12:00:00.000+00:00");
});

test("job stats: strings from the REST answer parse, content alone parses, nothing numeric is null", () => {
  const s = parseJob({ scanCount: "12", eventCount: "3", resultCount: "3", runDuration: "0.4", isDone: "1" });
  assert.equal(s.scanCount, 12);
  assert.equal(s.isDone, true);
  assert.equal(parseJob({ name: "x", content: { search: "index=main" } }), null);
  assert.equal(parseJob(null), null);
  assert.equal(parseJob("no"), null);
});

test("job stats: a high scan ratio is explained by the scan rule the job's own optimizedSearch trips", () => {
  const r = explain(parseJob(entry));
  assert.equal(r.ratio, 300);
  assert.equal(r.finding.rule, "spl/leading-wildcard");
  assert.match(r.line, /read 120,000 events to match 400 \(300:1\) in 12.5 s: leading wildcard is the likely reason/);
});

test("job stats: a pipeline drop is explained by a filter that ran after the scan", () => {
  const stats = { scanCount: 1000, eventCount: 900, resultCount: 30, runDuration: 2, optimizedSearch: 'search index=main sourcetype=okta | where action="login" | stats count by user' };
  const r = explain(stats);
  assert.equal(r.finding.rule, "spl/filter-after-scan");
  assert.match(r.line, /matched 900 events for 30 results \(30:1\)/);
  assert.match(r.line, /filter after the scan is where they went/);
});

test("job stats: a narrowed scan says the terms did the work, with a lesser note when one remains", () => {
  const clean = explain({ scanCount: 410, eventCount: 400, resultCount: 400, runDuration: 0.3, optimizedSearch: "search index=main sourcetype=okta user=admin earliest=-1h" });
  assert.equal(clean.finding, null);
  assert.match(clean.line, /the terms did the narrowing$/);
  const noted = explain({ scanCount: 410, eventCount: 400, resultCount: 400, runDuration: 0.3, optimizedSearch: "search index=main sourcetype=okta user!=admin earliest=-1h" });
  assert.equal(noted.finding.rule, "spl/neq-null");
  assert.match(noted.line, /still worth a look/);
});

test("job stats: no rule to blame still gives a reading, and no counts says so", () => {
  const r = explain({ scanCount: 5000, eventCount: 10, resultCount: 10, optimizedSearch: "search index=main sourcetype=okta risk_score=90 earliest=-1h" });
  assert.equal(r.finding, null);
  assert.match(r.line, /no rule here names the reason/);
  const withClass = explain({ scanCount: 5000, eventCount: 10, resultCount: 10, optimizedSearch: "search index=main sourcetype=okta risk_score=90 earliest=-1h" }, "", { classOf: () => "calculated" });
  assert.equal(withClass.finding.rule, "spl/scan-not-narrowed");
  const none = explain({ scanCount: null, eventCount: null, resultCount: null, runDuration: null, isDone: false });
  assert.match(none.line, /no counts yet \(still running\)/);
  const empty = explain({ scanCount: 100, eventCount: 0, resultCount: 0, optimizedSearch: "search index=main x=1" });
  assert.equal(empty.ratio, Infinity);
  assert.match(empty.line, /everything read, nothing matched/);
});

test("job stats: the job read takes a real sid only, never one that is only dots or dashes, on both sides of the relay", () => {
  const agent = readFileSync(new URL("../discovery-agent.js", import.meta.url), "utf8");
  const app = readFileSync(new URL("../app/lib/discovery.js", import.meta.url), "utf8");
  const agentRe = new RegExp(/const JOB_RE = \/(.+)\/;/.exec(agent)[1]);
  const appRe = new RegExp(/const SID_RE = \/(.+)\/;/.exec(app)[1]);
  const good = ["1758211200.4242", "1758211200.4242_5F3A-1", "scheduler__admin__search__RMD5abc_at_1758_1", "rt_1758.2"];
  const bad = ["", ".", "..", "-", "_.-", "a/b", "1758 2", "x".repeat(201), "1758?x=1", "1758#"];
  for (const s of good) {
    assert.ok(appRe.test(s), `app accepts ${s}`);
    assert.ok(agentRe.test(`servicesNS/-/-/search/v2/jobs/${s}`), `agent accepts ${s}`);
  }
  for (const s of bad) {
    assert.ok(!appRe.test(s), `app refuses ${JSON.stringify(s)}`);
    assert.ok(!agentRe.test(`servicesNS/-/-/search/v2/jobs/${s}`), `agent refuses ${JSON.stringify(s)}`);
  }
  assert.ok(!agentRe.test("services/search/jobs/1758.1"), "only the v2 path the table lists");
});

test("job stats: the Measure control is drawn on Splunk only, and enabled only with a job id and the extension", async () => {
  const { controlsFor } = await import("../app/components/advisor.js");
  const sentinel = controlsFor({ platform: "sentinel", sid: "1758211200.4242", available: true });
  assert.equal(sentinel.measure, false, "not drawn on Sentinel, not merely disabled");
  assert.equal(sentinel.advise, true);
  assert.match(sentinel.hint, /Splunk only/);
  const splunk = controlsFor({ platform: "splunk", sid: "1758211200.4242", available: true });
  assert.equal(splunk.measure, true);
  assert.equal(splunk.measureEnabled, true);
  assert.equal(controlsFor({ platform: "splunk", sid: "", available: true }).measureEnabled, false);
  assert.equal(controlsFor({ platform: "splunk", sid: "x", available: false }).measureEnabled, false);
  assert.match(controlsFor({ platform: "splunk", sid: "" }).hint, /row click/);
});

test("job stats: the Measure hint always names the second step, with or without a row click yet", async () => {
  const { controlsFor } = await import("../app/components/advisor.js");
  assert.match(controlsFor({ platform: "splunk", sid: "" }).hint, /then press Measure/);
  assert.match(controlsFor({ platform: "splunk", sid: "1758211200.4242" }).hint, /then press Measure/);
});
