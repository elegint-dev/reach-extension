// A runbook as Sentinel incident tasks. Sentinel adds a task list to an
// incident through an automation rule scoped to the analytics rule
// (https://learn.microsoft.com/en-us/azure/sentinel/incident-tasks, read
// 2026-09-20: "Set the Analytics rule name condition in your automation
// rule to determine the scope"; within one rule the actions' order is the
// tasks' order). The two JSON shapes the API accepts, both read 2026-09-20
// from the Sentinel REST reference, api-version 2025-06-01:
//
//   Automation Rules - Create Or Update, one action per task:
//     { "order": 1, "actionType": "AddIncidentTask", "actionConfiguration": { "title", "description" } }
//   Incident Tasks - Create Or Update, one PUT body per task (properties.title and properties.status required):
//     { "properties": { "title", "description", "status": "New" } }
//
//   taskList(runbook)  → { format, generated, rule: { name, keys }, api_version, actions: [...], tasks: [...] }
//   taskText(runbook)  → the same, as indented JSON
//
// A step with no question makes no task; the close step carries the benign
// and escalation conditions in its description, the escalation block kept
// whole and the rest clipped to the room left. No DOM.

const TITLE_MAX = 200;
const DESCRIPTION_MAX = 2000;
export const API_VERSION = "2025-06-01";
export const FORMAT = "sentinel-incident-tasks";

function clip(s, max) {
  const t = String(s || "").replace(/[ \t]+/g, " ").replace(/\s*\n\s*/g, "\n").trim();
  if (max <= 0) return "";
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function lines(parts) {
  return parts.filter(Boolean).join("\n");
}

function pivotLine(step) {
  const p = step.pivot;
  if (!p) return "";
  const binds = Object.entries(p.binds || {}).map(([param, field]) => `${param} from ${field}`);
  return `Pivot: ${p.packId}/${p.edge}${p.container ? ` on ${p.container}` : ""}${binds.length ? ` (${binds.join(", ")})` : ""}.`;
}

function conditions(label, list) {
  if (!list || !list.length) return "";
  return `${label}:\n${list.map((c) => `- ${c.text}`).join("\n")}`;
}

export function taskList(runbook) {
  const rb = runbook || {};
  const steps = Array.isArray(rb.steps) ? rb.steps : [];
  const tasks = [];
  const closeAt = steps.findIndex((s) => s && s.kind === "close");
  steps.forEach((s, i) => {
    const title = clip(s && s.question, TITLE_MAX);
    if (!title) return;
    const closing = closeAt >= 0 ? i === closeAt : i === steps.length - 1;
    const escalate = closing ? clip(conditions("Escalate when", rb.escalate_when), DESCRIPTION_MAX) : "";
    const room = DESCRIPTION_MAX - (escalate ? escalate.length + 1 : 0);
    const lead = clip(lines([s.why, pivotLine(s), closing ? conditions("Benign when", rb.benign_when) : ""]), room);
    tasks.push({ title, description: lines([lead, escalate]) });
  });
  return {
    format: FORMAT,
    generated: new Date().toISOString(),
    api_version: API_VERSION,
    rule: { name: rb.title || (rb.rule && rb.rule.name) || null, keys: rb.rule && Array.isArray(rb.rule.keys) ? rb.rule.keys.slice() : [] },
    source: rb.id || null,
    actions: tasks.map((t, i) => ({ order: i + 1, actionType: "AddIncidentTask", actionConfiguration: { title: t.title, description: t.description } })),
    tasks: tasks.map((t) => ({ properties: { title: t.title, description: t.description, status: "New" } })),
  };
}

export function taskText(runbook) {
  return JSON.stringify(taskList(runbook), null, 2);
}

export default { API_VERSION, FORMAT, taskList, taskText };
