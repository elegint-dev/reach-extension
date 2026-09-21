import { test } from "node:test";
import assert from "node:assert/strict";
import { lint, summary, rulesFor, RULES, SEVERITIES } from "../app/lib/advisor.js";
import { mask, stages, subsearches, fieldTests } from "../app/lib/advisor-rules/_text.js";
import { ORDER } from "../app/lib/ladder.js";
import * as spl from "../app/lib/spl.js";
import * as kql from "../app/lib/kql.js";

// Every rule's own cases, read from the rule modules: each hit text yields
// the rule at least once with a span that slices to real text, each miss
// text never does.
for (const rule of RULES) {
  const ctx = rule.cases.ctx || {};
  test(`advisor rule ${rule.id}: declares a platform, a severity, a why and both kinds of case`, () => {
    assert.ok(rule.platform === "spl" || rule.platform === "kql");
    assert.ok(SEVERITIES.includes(rule.severity));
    assert.ok(rule.why && !rule.why.includes("\n"), "one line of why");
    assert.ok(rule.cases.hit.length >= 2 && rule.cases.miss.length >= 2, "at least two cases each way");
  });
  for (const text of rule.cases.hit) {
    test(`advisor rule ${rule.id}: finds ${JSON.stringify(text)}`, () => {
      const found = lint(text, rule.platform, ctx).filter((f) => f.rule === rule.id);
      assert.ok(found.length >= 1, "at least one finding");
      for (const f of found) {
        assert.ok(f.span[0] < f.span[1] && f.span[1] <= text.length, `span inside the text: ${f.span}`);
        assert.equal(f.text, text.slice(f.span[0], f.span[1]));
        assert.ok(f.text.trim().length, "the span is not whitespace");
        assert.ok(SEVERITIES.includes(f.severity));
        assert.ok(f.why.length > 20, "a why");
        if (f.fix && f.fix.construct) assert.ok(ORDER.includes(f.fix.construct) || ["stats", "fields", "not", "has", "term", "literal"].includes(f.fix.construct), `fix names a known construct: ${f.fix.construct}`);
      }
    });
  }
  for (const text of rule.cases.miss) {
    test(`advisor rule ${rule.id}: passes ${JSON.stringify(text)}`, () => {
      const found = lint(text, rule.platform, ctx).filter((f) => f.rule === rule.id);
      assert.deepEqual(found.map((f) => f.text), []);
    });
  }
}

test("advisor: rules run only on their own platform", () => {
  assert.ok(rulesFor("spl").every((r) => r.platform === "spl"));
  assert.ok(rulesFor("kql").every((r) => r.platform === "kql"));
  assert.ok(rulesFor("sentinel").every((r) => r.platform === "kql"));
  assert.ok(rulesFor("splunk").every((r) => r.platform === "spl"));
  assert.deepEqual(lint("index=* user=*admin", "kql").map((f) => f.rule).filter((r) => r.startsWith("spl/")), []);
});

test("advisor: findings come back by position, empty text has none, and a rule that throws is skipped", () => {
  const text = 'index=* sourcetype=okta user="*admin" | join user [search index=b]';
  const f = lint(text, "spl");
  for (let i = 1; i < f.length; i++) assert.ok(f[i - 1].span[0] <= f[i].span[0]);
  assert.deepEqual(lint("", "spl"), []);
  assert.deepEqual(lint("   ", "kql"), []);
  assert.deepEqual(lint(null, "spl"), []);
});

test("advisor: the summary line counts notes and cautions", () => {
  assert.equal(summary([]), "advisor: no notes");
  assert.equal(summary([{ severity: "note" }]), "advisor: 1 note");
  assert.equal(summary([{ severity: "note" }, { severity: "note" }, { severity: "caution" }]), "advisor: 2 notes, 1 caution");
  assert.equal(summary([{ severity: "caution" }, { severity: "caution" }]), "advisor: 2 cautions");
});

test("advisor: what Reach generates is quiet (a bound pivot in SPL and in KQL has no notes)", () => {
  const s = 'search index=main sourcetype=aws:cloudtrail earliest=$earliest:time$ latest=$latest:time$ eventName="ConsoleLogin"\n| stats count by userIdentity.arn';
  assert.deepEqual(lint(s, "spl").map((f) => f.rule), []);
  const k = 'AWSCloudTrail\n| where TimeGenerated > ago(24h)\n| where TimeGenerated < now()\n| where EventName == "ConsoleLogin"\n| project TimeGenerated, EventName';
  assert.deepEqual(lint(k, "kql").map((f) => f.rule), []);
});

test("advisor: a finding never blocks emission (the linters still pass what the advisor notes)", () => {
  const s = "index=* sourcetype=okta user=*admin | table user | stats count by user";
  assert.ok(lint(s, "spl").length >= 3);
  assert.equal(spl.lint(s).ok, true);
  const k = 'SigninLogs | where UserPrincipalName =~ "a@b" | where ResultType contains "500"';
  assert.ok(lint(k, "kql").length >= 2);
  assert.equal(kql.lint(k).ok, true);
});

test("advisor: the context's class of a field feeds the scan rule and the filter rule", () => {
  const classOf = (f) => ({ risk_score: "calculated", owner: "lookup_output", u: "pipeline_derived" })[f] || "raw_token";
  const scan = lint("index=main risk_score=90 owner=alice", "spl", { classOf }).find((f) => f.rule === "spl/scan-not-narrowed");
  assert.ok(scan && scan.severity === "caution", "only calculated and lookup tests: a caution");
  assert.equal(lint("index=main risk_score=90 user=alice", "spl", { classOf }).find((f) => f.rule === "spl/scan-not-narrowed"), undefined);
  assert.equal(lint("index=main | where u=1", "spl", { classOf }).find((f) => f.rule === "spl/filter-after-scan"), undefined, "a pipeline-derived field cannot be a term");
});

test("advisor text: mask keeps the length and blanks strings and comments only", () => {
  const s = 'index=main user="a | b" ```note | x``` | stats';
  const m = mask(s, "spl");
  assert.equal(m.length, s.length);
  assert.ok(!m.includes("a | b") && !m.includes("note"));
  assert.ok(m.includes("| stats"));
  const k = 'T | where x == "a|b" // c | d\n| take 1';
  const mk = mask(k, "kql");
  assert.equal(mk.length, k.length);
  assert.ok(!mk.includes("a|b") && !mk.includes("c | d") && mk.includes("| take 1"));
  assert.equal(mask("x", "spl"), "x");
});

test("advisor text: stages split on top-level pipes only, and name the search block", () => {
  const st = stages('index=main [search x | fields y] user="a|b" | eval z=if(a="|",1,0) | stats count', "spl");
  assert.deepEqual(st.map((s) => s.head), ["", "eval", "stats"]);
  assert.equal(stages("| tstats count where index=main | stats sum(count)", "spl").map((s) => s.head).join(","), "tstats,stats");
  assert.equal(stages("search index=main | head 1", "spl")[0].head, "");
  const k = stages("T | join (U | where a == 1) on k | where b == 2", "kql");
  assert.deepEqual(k.map((s) => s.head), ["t", "join", "where"]);
  assert.deepEqual(subsearches("a [b [c]] d [e]").map((s) => [s.start, s.end]), [[2, 9], [12, 15]]);
});

test("advisor text: field tests read the operator and the literal on both platforms", () => {
  const spl1 = fieldTests({ start: 0, end: 30, text: 'user="a b" host!=w1 n>=3 earliest=-1h' }, "spl");
  assert.deepEqual(spl1.map((t) => [t.field, t.op, t.value, t.quoted]), [["user", "=", "a b", true], ["host", "!=", "w1", false], ["n", ">=", "3", false]]);
  const k1 = fieldTests({ start: 0, end: 60, text: 'where a contains "x" and b.c == 1 and d matches regex @"^y"' }, "kql");
  assert.deepEqual(k1.map((t) => [t.field, t.op, t.value]), [["a", "contains", "x"], ["b.c", "==", "1"], ["d", "matches regex", "^y"]]);
});
