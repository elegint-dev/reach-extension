// The notebook page lists investigations by the rule each started from
// (app/views/notebook.js): one group per rule under Investigations, its
// name linking the runbook page with the count and the close tally, the
// ones that started elsewhere last; an investigation's line says how it
// closed; the title block's chip reads "closed as benign" and its scope
// names the rule; with no origin anywhere the list is flat as before.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";

dom.install();
const store = await import("../app/lib/store.js");
const modules = await import("../app/lib/modules.js");
const notebook = await import("../app/lib/notebook.js");
const view = await import("../app/views/notebook.js");

const from = { platform: "splunk", container: "stash", scope: "main", column: "dest" };
const KERB = { ruleKey: "escu:name:disabled kerberos preauthentication discovery with getaduser", ruleName: "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser", platform: "splunk" };
const GITLAB = { ruleKey: "sentinel:name:gitlab - brute-force attempts", ruleName: "GitLab - Brute-force Attempts", platform: "sentinel" };
const ctx = { params: {}, navigate() {} };
const settle = () => new Promise((r) => setTimeout(r, 2));
const groupsOf = (el) => el.querySelectorAll(".r-nb__rulegroup");

async function closedOne(title, origin, outcome) {
  const inv = await notebook.start({ title, origin });
  const p = await notebook.record({ field: "dest", value: title, from }, { investigation: inv.id });
  await notebook.close(inv.id, outcome ? { outcome, evidence: { entry: p.id } } : {});
  await settle();
  return inv;
}

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
  modules.reset();
});

test("Investigations groups by rule: the rule's name links its runbook page, the group says how many closed each way, and the unattributed come last", async () => {
  await closedOne("k1", KERB, "benign");
  await closedOne("k2", KERB, "escalated");
  await closedOne("g1", GITLAB, "benign");
  await notebook.start({ title: "loose" });
  await settle();
  await closedOne("k3", KERB, "benign");
  const el = view.render({ ...ctx });
  await settle();
  const groups = groupsOf(el);
  assert.equal(groups.length, 3);
  assert.deepEqual(groups.map((g) => g.dataset.ruleKey), [KERB.ruleKey, GITLAB.ruleKey, ""]);
  const kerb = groups[0];
  const link = kerb.querySelector("h3").querySelector("a");
  assert.equal(dom.text(link), KERB.ruleName);
  assert.equal(link.getAttribute("href"), `#/runbook/${encodeURIComponent(KERB.ruleKey)}?rule=${encodeURIComponent(KERB.ruleName)}`);
  assert.equal(dom.text(kerb.querySelector("h3").querySelector(".r-nb__meta")), "3 investigations, 3 closed (2 benign, 1 escalated)");
  assert.deepEqual(kerb.querySelectorAll(".r-nb__inv").map((li) => dom.text(li.querySelector("a"))), ["k3", "k2", "k1"]);
  assert.match(dom.text(kerb.querySelectorAll(".r-nb__inv")[0].querySelector(".r-nb__meta")), /^closed as benign · 1 value, 1 entry · /);
  assert.equal(kerb.querySelectorAll(".r-nb__inv")[0].dataset.outcome, "benign");
  assert.equal(dom.text(groups[2].querySelector("h3")).startsWith("Not from an alert row"), true);
  assert.deepEqual(groups[2].querySelectorAll(".r-nb__inv").map((li) => dom.text(li.querySelector("a"))), ["loose"]);
  assert.match(dom.text(el.querySelector(".r-nb__list").querySelector(".r-secondary")), /^By the alert rule each started from/);
});

test("with no origin anywhere the list stays flat: no rule group, no by-rule line", async () => {
  await notebook.start({ title: "a" });
  await settle();
  await notebook.start({ title: "b" });
  const el = view.render({ ...ctx });
  await settle();
  assert.equal(groupsOf(el).length, 0);
  assert.deepEqual(el.querySelector(".r-nb__list").querySelectorAll(".r-nb__inv").map((li) => dom.text(li.querySelector("a"))), ["b", "a"]);
  assert.equal(el.querySelector(".r-nb__list").querySelector(".r-secondary"), null);
});

test("the title block of a closed investigation reads closed as benign, its scope names the rule with a link to the runbook page, and an open one from a rule shows the rule too", async () => {
  const inv = await closedOne("k1", KERB, "benign");
  const el = view.render({ ...ctx, params: { id: inv.id } });
  await settle();
  const first = el.children[0];
  assert.equal(dom.text(first.querySelector(".r-title__chips")), "closed as benign");
  const rule = first.querySelector(".r-nb__rule");
  assert.equal(dom.text(rule), `from rule ${KERB.ruleName}`);
  assert.equal(rule.querySelector("a").getAttribute("href"), `#/runbook/${encodeURIComponent(KERB.ruleKey)}?rule=${encodeURIComponent(KERB.ruleName)}`);
  const m = view.model(notebook.get(inv.id));
  assert.match(m.status, /^closed .* as benign$/);
  assert.equal(m.rule, `${KERB.ruleName} (${KERB.ruleKey}, Splunk)`);
  assert.equal(m.outcome, "benign, on Hold of dest = k1");
  const open = await notebook.start({ title: "open one", origin: GITLAB });
  const el2 = view.render({ ...ctx, params: { id: open.id } });
  await settle();
  assert.equal(dom.text(el2.children[0].querySelector(".r-title__chips")), "current");
  assert.equal(dom.text(el2.children[0].querySelector(".r-nb__rule")), `from rule ${GITLAB.ruleName}`);
});
