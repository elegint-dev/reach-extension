// A runbook as Sentinel incident tasks (app/lib/runbooks-tasks.js): one
// AddIncidentTask automation rule action per step in step order, the same
// tasks as Incident Tasks PUT bodies with status New, the close step
// carrying the benign and escalation conditions, a step with no question
// making no task, the escalation block surviving a long benign list, and
// the titles clipped to what the portal shows.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as tasks from "../app/lib/runbooks-tasks.js";

const edited = JSON.parse(await readFile(new URL("./fixtures/runbook-edited.json", import.meta.url), "utf8"));

test("one automation rule action per step, in order, with the shape the Automation Rules API accepts", () => {
  const out = tasks.taskList(edited);
  assert.equal(out.format, "sentinel-incident-tasks");
  assert.equal(out.api_version, "2025-06-01");
  assert.equal(out.rule.name, "GitLab - Brute-force Attempts");
  assert.deepEqual(out.rule.keys, edited.rule.keys);
  assert.equal(out.source, edited.id);
  assert.equal(out.actions.length, 4);
  out.actions.forEach((a, i) => {
    assert.equal(a.order, i + 1);
    assert.equal(a.actionType, "AddIncidentTask");
    assert.deepEqual(Object.keys(a.actionConfiguration), ["title", "description"]);
  });
  assert.deepEqual(out.actions.map((a) => a.actionConfiguration.title), edited.steps.map((s) => s.question));
  assert.equal(out.actions[1].actionConfiguration.description, "A password spray shows as many accounts from one address.\nPivot: reach-sentinel-samples/sentinel_signin_by_ip on SigninLogs (value from IPAddress).");
});

test("the same tasks as Incident Tasks PUT bodies: properties.title, description and status New", () => {
  const out = tasks.taskList(edited);
  assert.equal(out.tasks.length, out.actions.length);
  out.tasks.forEach((t, i) => {
    assert.deepEqual(Object.keys(t), ["properties"]);
    assert.deepEqual(Object.keys(t.properties), ["title", "description", "status"]);
    assert.equal(t.properties.status, "New");
    assert.equal(t.properties.title, out.actions[i].actionConfiguration.title);
  });
});

test("the close step carries the benign and escalation conditions; a step with no question makes no task", () => {
  const out = tasks.taskList(edited);
  const close = out.tasks[3].properties;
  assert.equal(close.description, "Benign when:\n- The source is a corporate VPN egress address.\n- The account is a load-test service account during a scheduled run.\nEscalate when:\n- Any success after the failures from the same address.");
  assert.equal(out.tasks[0].properties.description.includes("Benign when"), false);
  const noClose = tasks.taskList({ ...edited, steps: [edited.steps[0], { question: "   " }, edited.steps[2]] });
  assert.equal(noClose.tasks.length, 2);
  assert.match(noClose.tasks[1].properties.description, /Benign when/, "without a close step the last step carries the conditions");
  assert.deepEqual(tasks.taskList(null).tasks, []);
});

test("titles and descriptions are clipped, and taskText is the document as indented JSON", () => {
  const out = tasks.taskList({ ...edited, steps: [{ question: "q".repeat(500), why: "w".repeat(5000) }] });
  assert.equal(out.tasks[0].properties.title.length, 200);
  assert.equal(out.tasks[0].properties.description.length, 2000);
  assert.ok(out.tasks[0].properties.title.endsWith("…"));
  const text = tasks.taskText(edited);
  assert.equal(JSON.parse(text).actions.length, 4);
  assert.match(text, /^\{\n  "format": "sentinel-incident-tasks",/);
});

test("the close task keeps the escalation conditions when the benign list alone outruns the description budget", () => {
  const long = { ...edited, benign_when: Array.from({ length: 60 }, (_, i) => ({ text: `Benign case ${i + 1}: a scheduled load test from the address on the egress list.` })) };
  const close = tasks.taskList(long).tasks[3].properties.description;
  assert.ok(close.length <= 2000, `description is ${close.length} chars`);
  assert.match(close, /^Benign when:\n- Benign case 1:/);
  assert.match(close, /…\nEscalate when:\n- Any success after the failures from the same address\.$/);
  const alone = { ...long, escalate_when: [{ text: "x".repeat(2100) }] };
  const only = tasks.taskList(alone).tasks[3].properties.description;
  assert.ok(only.length <= 2000);
  assert.match(only, /^Escalate when:\n- x+…$/, "an escalation block that fills the budget leaves no room for the rest");
});
