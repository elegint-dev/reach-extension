// Runbook page: #/runbook/<key>?rule=…&<entity>=…&edit=1
// The runbook kept for one rule (app/lib/runbooks-store.js), seeded from
// the bundle on the first open (app/lib/runbooks.js) and walked the way
// views/workflow.js walks a workflow: one step at a time, each with a
// checkbox, the pivot steps bound from the alert row (the URL's entity
// params, else this tab's last clicked row) and selected into the drawer,
// then Benign conditions and Escalation conditions. Hold and Mark benign
// on the row's primary entity are the title block's action row, as on
// the value page. The Hold carries the rule as the
// origin of the investigation it starts; a pivot copied from the drawer
// is recorded on the held entity; the close step closes the current
// investigation as benign, escalated or inconclusive on that Hold or Mark
// benign. Once three investigations of the rule have closed, a draft
// (runbooks-store draftFrom) sits beside the seed: the pivots they ran,
// how they closed, and Adopt. With edit=1 the steps, their questions,
// notes and bound pivots, the two condition lists and the notes are
// editable, each change written on commit; Reset to seed puts the
// bundle's runbook back. Export writes the runbook as a file; on Sentinel
// the steps also leave as an incident task list. Checks live for the page.

import { h, replace } from "../components/h.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { titleBlock } from "../components/titleBlock.js";
import { download, slug } from "../components/download.js";
import { headingNode } from "../lib/headings.js";
import { openFold, fillFrom } from "../components/drawer.js";
import { absentPage, backAction } from "./unknown.js";
import * as runbooks from "../lib/runbooks.js";
import * as rbStore from "../lib/runbooks-store.js";
import * as store from "../lib/store.js";
import * as tasks from "../lib/runbooks-tasks.js";
import * as notebook from "../lib/notebook.js";
import * as searches from "../lib/searches.js";
import { displayTitle } from "../lib/notebook-md.js";
import { recordPivot } from "../lib/popup-ui.js";
import * as modules from "../lib/modules.js";
import * as packs from "../lib/packs.js";
import * as pivot from "../lib/pivot.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import * as lastEvent from "../lib/last-event.js";
import * as kql from "../lib/kql.js";
import { PLATFORM, TERMS, isSentinel } from "../lib/platform.js";
import { KEYS } from "../lib/storage-keys.js";
import { holdAction, benignAction, keepRow } from "./value.js";
import { windowDefaults } from "../components/packPivots.js";

const WORKSPACE_KEY = KEYS.sentinelWorkspace;
const OWN_PARAMS = new Set(["key", "rule", "st", "sel", "edit"]);

// The row the runbook binds from: the URL's entity params first (a tab
// opened from the popup's link), else the last clicked row in this tab.
function rowFor(params) {
  const row = { ...(lastEvent.recall(null) || {}) };
  for (const [k, v] of Object.entries(params || {})) {
    if (OWN_PARAMS.has(k) || scope.isScopeKey(k)) continue;
    if (v !== undefined && v !== null && v !== "") row[k] = String(v);
  }
  return row;
}

// The Logs blade workspace the grid script remembered, for Open in portal.
async function currentWorkspace() {
  try {
    const out = await store.getLiteral(WORKSPACE_KEY);
    return out[WORKSPACE_KEY] || null;
  } catch {
    return null;
  }
}

function generateFor(step, userParams) {
  const edge = step.pivot.edge;
  const on = (edge.dst && edge.dst.sourcetype) || edge.src.sourcetype;
  const params = scope.bind({ ...windowDefaults(step.pivot.meta), ...facts.bound(), ...step.pivot.params, ...userParams }, on);
  const out = pivot.generate(edge, params, { pack: packs.pack(step.pivot.packId) });
  return { text: out.spl, hazards: [...out.hazards, ...scope.notes(on)], missing: out.missing, on };
}

function copyText(text, btn, done = "Copied") {
  const label = btn.textContent;
  const nav = typeof navigator !== "undefined" ? navigator : null;
  const back = () => setTimeout(() => (btn.textContent = label), 1200);
  if (nav && nav.clipboard && nav.clipboard.writeText) nav.clipboard.writeText(text).then(() => { btn.textContent = done; back(); }, () => { btn.textContent = "Could not copy"; back(); });
  else {
    btn.textContent = "Could not copy";
    back();
  }
}

function when(t) {
  return t ? new Date(t).toLocaleString() : "";
}

export function render(ctx) {
  const key = String(ctx.params.key || "");
  const parsed = runbooks.parseKey(key);
  const el = h("div", { class: "r-view r-view--runbook" });
  if (!parsed) {
    return absentPage({
      name: "No such runbook",
      chip: "no rule key",
      why: "a runbook is keyed by the rule that fired: open one from the alert row's popup",
      actions: [backAction(ctx.goBack), h("a", { class: "r-btn", href: "#/" }, "Start")],
    });
  }
  const row = rowFor(ctx.params);
  const ruleKey = { platform: PLATFORM, key, keys: [parsed], name: ctx.params.rule ? String(ctx.params.rule) : null };
  const container = (ctx.params.st && String(ctx.params.st)) || row.sourcetype || row.Type || null;
  const editing = String(ctx.params.edit || "") === "1";
  const status = h("p", { class: "r-secondary r-runbook__status", role: "status" });

  function fail(err) {
    status.textContent = err && err.message ? err.message : String(err);
  }

  function seedNow() {
    return runbooks.seedFor(ruleKey, { row, platform: PLATFORM });
  }

  function goto(params) {
    ctx.navigate("runbook", { ...ctx.params, key, ...params });
  }

  let rb = null; // the stored runbook
  let vm = null; // rb bound to the row: steps with their edges and params
  let draft = null; // runbooks-store draftFrom, from the notebook's closed investigations of this rule
  let primary = null; // the entity the close step holds or marks benign
  let workspace = null;
  const userParams = {};
  let current = null;
  const checks = new Set();
  let stepNodes = new Map();
  let resetArmed = false;
  const origin = runbooks.originOf(ruleKey, PLATFORM);

  // The title block: the rule's name, the origin chip (seeded from the
  // bundle, or edited by you) and the techniques, the scope line (runbook,
  // the platform, the entities bound from the row, the rule's own page),
  // the seed note in the callout slot, then the action row: Hold and Mark
  // benign on the primary entity (their bodies in the keep row under it,
  // as on the value page), Run (the first pivot into the fold) or Copy
  // KQL, and Edit; while editing, Done and Reset to seed. Drawn once while
  // the store and the bundle are read and again with the runbook, swapped
  // in place so it stays the view's first child.
  function titleFor() {
    // A fresh button reads "Reset to seed", so a redraw disarms.
    resetArmed = false;
    const seeded = rb ? rb.seeded_from : null;
    const first = vm ? vm.steps.find((s) => s.pivot && s.pivot.edge) || null : null;
    const runLabel = isSentinel() ? `Copy ${TERMS.lang}` : "Run";
    const run = h(
      "button",
      { type: "button", class: "r-btn", disabled: !first, title: first ? `step ${vm.steps.indexOf(first) + 1} into the drawer` : "no pivot step on this runbook", onClick: () => { if (!first) return; select(first); if (isSentinel()) ctx.drawer.copy(); else openFold(); } },
      runLabel,
    );
    const chips = [];
    if (!rb) chips.push(chip({ kind: "trust", value: "inferred", text: "reading the bundle" }));
    else {
      if (rb.origin === "edited") chips.push(chip({ kind: "trust", value: "confirmed", text: "edited by you", title: rb.edited_at ? `last edit ${when(rb.edited_at)}` : "" }));
      chips.push(chip({ kind: "trust", value: seeded ? "confirmed" : "inferred", text: seeded ? seeded.label : "not in the bundled rules", title: seeded && seeded.ref ? `bundle ref ${seeded.ref}` : "" }));
      for (const t of rb.techniques.slice(0, 3)) chips.push(chip({ kind: "route", value: "one-hop", text: t }));
    }
    const keep = editing || !primary ? { row: null, buttons: [] } : keepRow([holdAction({ container, field: primary.field, value: primary.value, origin }), benignAction({ catalogue: ctx.catalogue, container, field: primary.field, value: primary.value })]);
    const actions = editing
      ? [
          h("button", { type: "button", class: "r-btn r-btn--primary", onClick: () => goto({ edit: undefined }) }, "Done"),
          h("button", { type: "button", class: "r-btn r-runbook__reset", disabled: !rb, onClick: (e) => { if (!resetArmed) { resetArmed = true; e.target.textContent = "Reset: sure?"; return; } resetArmed = false; seedNow().then((seed) => rbStore.reset(key, seed)).catch(fail); } }, "Reset to seed"),
        ]
      : [...keep.buttons, run, h("button", { type: "button", class: "r-btn", disabled: !rb, onClick: () => goto({ edit: "1" }) }, "Edit")];
    const title = titleBlock({
      kind: "runbook",
      h1: (rb && rb.title) || ruleKey.name || parsed.value,
      chips,
      scope: [
        "runbook",
        `on ${TERMS.platform}`,
        vm ? (vm.entities.length ? `${vm.entities.length} entit${vm.entities.length === 1 ? "y" : "ies"} from the row` : "no entities on the row") : null,
        seeded && seeded.url ? h("a", { class: "r-scope__name", href: seeded.url, target: "_blank", rel: "noopener" }, "the rule's own page ↗") : null,
        editing ? "editing" : null,
      ],
      callout: rb && !seeded && rb.origin !== "edited" ? callout({ kind: "note", label: "Not seeded", body: `No bundled rule index carries ${rb.title || parsed.value}: the steps below are the pivots the packs know for the row's entities and the close, nothing from the rule's author.` }) : null,
      actions,
    });
    if (keep.buttons.length) title.appendChild(keep.row);
    return title;
  }
  let head = titleFor();
  el.appendChild(head);
  const body = h("div");
  el.appendChild(body);

  function fill(step, rebuild) {
    current = step;
    const edge = step.pivot.edge;
    const meta = step.pivot.meta || {};
    fillFrom(
      ctx.drawer,
      {
        title: edge.label,
        subtitle: `${edge.src.field} → ${edge.dst.field} on ${edge.dst.sourcetype}`,
        params: (out) => out.missing.map((n) => ({ name: n, label: (meta[n] && meta[n].label) || n, value: userParams[n] ?? "", placeholder: (meta[n] && meta[n].placeholder) || "", hint: (meta[n] && meta[n].hint) || "", required: true })),
        errorParams: () => [],
        catchAll: true,
      },
      () => {
        const out = generateFor(step, userParams);
        return { ...out, spl: out.text };
      },
      rebuild,
    );
  }

  if (ctx.setDrawerParamHandler) {
    ctx.setDrawerParamHandler((n, v) => {
      userParams[n] = v;
      if (current) fill(current, false);
    });
  }
  // A pivot copied from the drawer is an edge on the held entity it was
  // bound from, named by the pack edge so the draft counts it; nothing is
  // recorded for an entity not held.
  if (ctx.setDrawerCopyHandler) {
    ctx.setDrawerCopyHandler((text) => {
      if (!current || !current.pivot || !current.pivot.edge) return;
      const p = current.pivot;
      if (p.params.value === undefined) return;
      recordPivot({ field: p.binds.value, value: p.params.value, container, platform: PLATFORM, query: text, name: p.edge.label }).catch(() => {});
    });
  }
  scope.follow(el, () => {
    if (current) fill(current, true);
  });

  function select(step) {
    for (const [id, node] of stepNodes) node.classList.toggle("r-selected", id === step.id);
    ctx.setUrl("runbook", { ...ctx.params, key, sel: step.id });
    fill(step, true);
  }

  // The pivot's line under a pivot step: the edge, the row value bound
  // to it, the other parameters bound from the row, and what is missing.
  function boundLine(step) {
    const p = step.pivot;
    const edge = p.edge;
    const parts = [`${edge.src.field} → ${edge.dst.field} on ${edge.dst.sourcetype}`];
    if (p.params.value !== undefined) parts.push(`${p.binds.value} = ${p.params.value}`);
    const others = p.bound.filter((b) => b !== "value");
    if (others.length) parts.push(`${others.join(", ")} bound from the row`);
    if (p.missing.length) parts.push(`needs ${p.missing.map((m) => m.field).join(", ")} from the row`);
    return h("p", { class: "r-muted r-runbook__bound" }, parts.join(" · "));
  }

  function pivotActions(step) {
    const actions = [];
    if (!step.pivot.edge) {
      actions.push(h("p", { class: "r-muted r-runbook__bound" }, `Pivot ${step.pivot.packId}/${step.pivot.edgeId} is not in the loaded packs on ${TERMS.platform}.`));
      return actions;
    }
    actions.push(boundLine(step));
    if (isSentinel()) {
      actions.push(h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => { select(step); ctx.drawer.copy(); } }, "Copy KQL"));
      const deep = h("a", { class: "r-btn r-btn--small", href: "#", target: "_blank", rel: "noopener", hidden: true }, "Open in portal ↗");
      actions.push(deep);
      if (workspace && workspace.resourceId) {
        try {
          const out = generateFor(step, userParams);
          kql.deepLink({ resourceId: workspace.resourceId, kql: out.text, timespan: "P1D" }).then((url) => { deep.href = url; deep.hidden = false; }).catch(() => {});
          deep.addEventListener("click", () => searches.record({ text: out.text, platform: PLATFORM, source: "open", origin: "runbook", container, name: step.pivot.edge.label, field: step.pivot.binds && step.pivot.binds.value, value: step.pivot.params && step.pivot.params.value }).catch(() => {}));
        } catch {
          /* the step's query needs a parameter: the drawer says which */
        }
      } else {
        actions.push(h("span", { class: "r-muted" }, "open the Logs blade once for a portal link"));
      }
    } else {
      actions.push(h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => select(step) }, "Run"));
    }
    return actions;
  }

  // The Hold or Mark benign of the primary entity in the investigation,
  // the latest of the kind the outcome calls for (a benign close on the
  // mark, the others on the pin), else the latest of either; with no
  // outcome yet, whichever came last.
  function evidenceIn(inv, outcome) {
    if (!inv || !primary) return null;
    const same = (e) => e.value === primary.value && (e.field || (e.from && e.from.column)) === primary.field;
    const marks = inv.entries.filter((e) => e.kind === "benign" && same(e));
    const pins = inv.entries.filter((e) => e.kind === "pin" && same(e));
    if (!outcome) return inv.entries.filter((e) => (e.kind === "benign" || e.kind === "pin") && same(e)).pop() || null;
    const first = outcome === "benign" ? marks : pins;
    const second = outcome === "benign" ? pins : marks;
    return first[first.length - 1] || second[second.length - 1] || null;
  }

  // The close step's row: the current investigation, what in it stands as
  // evidence, and one button per outcome. The outcome closes the
  // investigation and records nothing else; the Hold and Mark benign
  // rows above are the only way a value gets into it.
  function closeRow() {
    const inv = notebook.current();
    const line = h("p", { class: "r-muted r-runbook__bound r-runbook__closeline" });
    if (!inv) {
      line.textContent = "Nothing to close yet: Hold the entity or mark it benign above and the outcome closes that investigation.";
      return [line];
    }
    const ev = evidenceIn(inv, null);
    const attributed = inv.origin && inv.origin.ruleKey === key;
    line.textContent = [
      `Closes ${displayTitle(inv)}`,
      ev ? `on the ${ev.kind === "benign" ? "Mark benign" : "Hold"} of ${primary.field} = ${primary.value}` : primary ? `with ${primary.field} = ${primary.value} neither held nor marked` : "with no entity on the row",
      attributed ? "" : inv.origin ? "(it started from another rule, so it does not count toward this runbook's draft)" : "(it did not start from an alert row, so it does not count toward this runbook's draft)",
    ].filter(Boolean).join(" ") + ".";
    const btns = notebook.OUTCOMES.map((o) =>
      h(
        "button",
        { type: "button", class: "r-btn r-btn--small r-runbook__outcome", dataset: { outcome: o }, onClick: (e) => {
          for (const b of e.target.parentNode.children) b.disabled = true;
          const evidence = evidenceIn(inv, o);
          notebook.close(inv.id, { outcome: o, evidence: evidence ? { entry: evidence.id } : null, reason: evidence && evidence.reason ? evidence.reason : null })
            .then(() => { status.textContent = `Closed ${displayTitle(inv)} as ${o}.`; })
            .catch(fail);
        } },
        `Close as ${o}`,
      ),
    );
    return [line, h("div", { class: "r-runbook__actions r-runbook__closeacts" }, ...btns)];
  }

  function stepEl(step, n) {
    const label = step.kind === "false_positive" ? "Benign when" : step.kind === "pivot" ? "Note" : step.kind === "check" ? "Note" : "The rule says";
    const box = h("input", { type: "checkbox", class: "r-runbook__check", id: `rb-step-${n}`, "aria-label": `Step ${n} done`, checked: checks.has(step.id), onChange: (e) => { if (e.target.checked) checks.add(step.id); else checks.delete(step.id); wrap.classList.toggle("r-step--done", e.target.checked); } });
    const actions = step.pivot ? pivotActions(step) : step.kind === "close" ? closeRow() : [];
    const wrap = h(
      "section",
      { class: ["r-step", "r-runbook__step", step.kind === "pivot" && "r-runbook__step--pivot", checks.has(step.id) && "r-step--done"], dataset: { stepId: step.id, kind: step.kind } },
      h("header", { class: "r-step__head" }, h("span", { class: "r-step__n", "aria-hidden": "true" }, String(n)), h("h3", { class: "r-step__title" }, h("label", { for: `rb-step-${n}`, class: "r-runbook__label" }, box, " ", step.question))),
      h("div", { class: "r-step__body" }, step.why ? callout({ kind: step.kind === "false_positive" ? "caution" : "why", label, body: step.why }) : null, actions.length ? h("div", { class: "r-runbook__actions" }, ...actions) : null),
    );
    return wrap;
  }

  // The same step with its question, note and pivot as inputs; a change
  // on any of them is one write, and the store's change redraws the page.
  function editStepEl(step, n, options, total) {
    const q = h("input", { class: "r-input r-runbook__q", type: "text", value: step.question, "aria-label": `Step ${n} question`, autocomplete: "off", spellcheck: "false", onChange: (e) => rbStore.updateStep(key, step.id, { question: e.target.value }).catch(fail) });
    const why = h("textarea", { class: "r-input r-runbook__ta", rows: 2, placeholder: "why this step, or what the rule's author says", "aria-label": `Step ${n} note`, onChange: (e) => rbStore.updateStep(key, step.id, { why: e.target.value }).catch(fail) });
    why.value = step.why || "";
    const currentId = step.pivot ? `${step.pivot.packId}/${step.pivot.edgeId}` : "";
    const sel = h("select", { class: "r-input r-runbook__pivot", "aria-label": `Step ${n} pivot` }, h("option", { value: "" }, "no pivot"));
    let found = false;
    for (const o of options) {
      if (o.id === currentId) found = true;
      sel.appendChild(h("option", { value: o.id, selected: o.id === currentId }, `${o.label} (${o.type} from ${o.field})`));
    }
    if (currentId && !found) sel.appendChild(h("option", { value: currentId, selected: true }, `${currentId} (not loaded here)`));
    sel.addEventListener("change", () => {
      const o = options.find((x) => x.id === sel.value) || null;
      rbStore.updateStep(key, step.id, { pivot: o ? o.pivot : null }).catch(fail);
    });
    const ctl = (label, title, disabled, fn) => h("button", { type: "button", class: "r-btn r-btn--small", title, "aria-label": title, disabled, onClick: fn }, label);
    const controls = h(
      "div",
      { class: "r-runbook__controls" },
      ctl("↑", `Move step ${n} up`, n === 1, () => rbStore.moveStep(key, step.id, -1).catch(fail)),
      ctl("↓", `Move step ${n} down`, n === total, () => rbStore.moveStep(key, step.id, 1).catch(fail)),
      ctl("Remove", `Remove step ${n}`, total <= 1, () => rbStore.removeStep(key, step.id).catch(fail)),
    );
    return h(
      "section",
      { class: ["r-step", "r-runbook__step", "r-runbook__step--edit", step.kind === "pivot" && "r-runbook__step--pivot"], dataset: { stepId: step.id, kind: step.kind } },
      h("header", { class: "r-step__head" }, h("span", { class: "r-step__n", "aria-hidden": "true" }, String(n)), h("h3", { class: "r-step__title" }, q)),
      h("div", { class: "r-step__body" }, h("label", { class: "r-runbook__field" }, "Note", why), h("label", { class: "r-runbook__field" }, "Pivot", sel), step.pivot && step.pivot.edge ? boundLine(step) : null, controls),
    );
  }

  function conditionsEditor(name, list, label) {
    const ta = h("textarea", { class: "r-input r-runbook__ta", rows: Math.max(2, Math.min(6, list.length + 1)), placeholder: "one condition per line", "aria-label": label, onChange: (e) => rbStore.update(key, { [name]: e.target.value.split("\n").map((t) => t.trim()).filter(Boolean) }).catch(fail) });
    ta.value = list.map((c) => c.text).join("\n");
    return ta;
  }

  function shareRow() {
    const out = [];
    if (modules.on("share")) {
      out.push(h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => download(`reach-runbook-${slug(rb.title)}.json`, JSON.stringify(rb, null, 2)) }, "Export runbook"));
    }
    if (isSentinel()) {
      out.push(h("button", { type: "button", class: "r-btn r-btn--small", title: "the steps as Sentinel incident tasks (automation rule actions), to the clipboard", onClick: (e) => copyText(tasks.taskText(rb), e.target) }, "Copy as incident tasks"));
      out.push(h("button", { type: "button", class: "r-btn r-btn--small", title: "the steps as Sentinel incident tasks (automation rule actions), as a file", onClick: () => download(`sentinel-tasks-${slug(rb.title)}.json`, tasks.taskText(rb)) }, "Download tasks"));
    }
    return out.length ? h("div", { class: "r-runbook__share" }, ...out) : null;
  }

  // Beside the seed: the draft from the notebook, once three investigations
  // of this rule have closed; under three, one line saying how many.
  function draftSection() {
    if (!draft || !draft.investigations) return null;
    const n = draft.investigations;
    if (!draft.ready) return h("section", { class: "r-section r-runbook__draftnote" }, h("p", { class: "r-secondary" }, `${n} closed investigation${n === 1 ? "" : "s"} of this rule in the notebook; a draft runbook appears once ${draft.needed} have closed.`));
    const have = (k) => new Set(rb[k].map((c) => c.text.toLowerCase()));
    const newConditions = ["benign_when", "escalate_when"].reduce((acc, k) => acc + draft[k].filter((c) => !have(k).has(c.text.toLowerCase())).length, 0);
    const missing = draft.steps.filter((s) => !s.present).length + newConditions;
    const steps = draft.steps.length
      ? h("ol", { class: "r-list r-runbook__draftsteps" }, draft.steps.map((s) => h("li", { class: ["r-runbook__draftstep", s.present && "r-runbook__draftstep--present"] }, s.question, " ", h("span", { class: "r-muted" }, `${s.count} of ${s.of}${s.present ? ", in the runbook already" : s.pivot ? "" : ", as a note with the query"}`))))
      : h("p", { class: "r-muted" }, "No pivot was run in a third of them.");
    const outcome = draft.outcome ? `Closed as ${draft.outcome.result} in ${draft.outcome.count} of ${draft.outcome.of}.` : "No close outcome recorded on them.";
    const conditions = (k, label) => draft[k].length ? h("p", { class: "r-runbook__draftcond" }, h("strong", null, `${label}. `), draft[k].map((c) => `${c.text} (${c.count})`).join("; ")) : null;
    const adopt = h("button", { type: "button", class: "r-btn r-btn--small r-btn--primary r-runbook__adopt", disabled: !missing, title: missing ? `${missing} addition${missing === 1 ? "" : "s"} to the runbook` : "the runbook has all of it already", onClick: (e) => { e.target.disabled = true; rbStore.adoptDraft(key, draft).then(() => { status.textContent = `Adopted ${draft.label.replace(/^from /, "from ")}: ${missing} addition${missing === 1 ? "" : "s"}.`; }).catch(fail); } }, "Adopt");
    return h(
      "section",
      { class: "r-section r-runbook__draft" },
      headingNode("draft-runbook", draft.steps.length),
      h("p", { class: "r-secondary" }, chip({ kind: "trust", value: "inferred", text: draft.label }), " The pivots run in at least a third of them, in the order they were usually run, and how they closed. Adopt adds what the runbook lacks before its close step; nothing is written until then."),
      steps,
      h("p", { class: "r-runbook__draftoutcome" }, outcome),
      conditions("benign_when", "Benign when"),
      conditions("escalate_when", "Escalate when"),
      h("div", { class: "r-runbook__actions" }, adopt),
    );
  }

  function refreshDraft() {
    return rbStore.draftFrom(key, { row, platform: PLATFORM }).then((d) => { draft = d; }).catch(() => { draft = null; });
  }

  function draw() {
    vm = rbStore.bind(rb, row, { platform: PLATFORM });
    primary = runbooks.primaryEntity({ entities: vm.entities }, row);
    const seeded = rb.seeded_from;
    const next = titleFor();
    head.replaceWith(next);
    head = next;
    const originLine = rb.origin === "edited"
      ? `Edited by you${rb.edited_at ? ` on ${when(rb.edited_at)}` : ""}${seeded ? `; seeded from ${runbooks.label(seeded.source)} on the first open` : ""}${rb.learned_from ? `; ${rb.learned_from.investigations} of your investigations adopted${rb.learned_from.at ? ` on ${when(rb.learned_from.at)}` : ""}` : ""}. Reset to seed puts the bundle's runbook back.`
      : seeded
        ? `Seeded from ${runbooks.label(seeded.source)}: the description${rb.benign_when.length ? " and the known false positives" : ""} are ${seeded.author ? `the rule's own author's (${seeded.author})` : "the author's"}; the pivots are the packs', bound from this row. Edit makes it yours.`
        : null;
    const seedLine = originLine ? h("section", { class: "r-section" }, h("p", { class: "r-secondary" }, originLine)) : null;
    const total = vm.steps.length;
    const steps = h("section", { class: "r-section" }, headingNode("steps", total), h("p", { class: "r-secondary" }, editing ? "Rename a step, change its note or the pivot it runs, move it, remove it, or add one; each change is saved as you leave the field." : `${vm.bound} of ${total} bind a value from the row. Tick a step when it is done; a pivot lands in the drawer.`));
    stepNodes = new Map();
    const options = editing ? runbooks.pivotOptions(row, PLATFORM) : [];
    vm.steps.forEach((s, i) => {
      const node = editing ? editStepEl(s, i + 1, options, total) : stepEl(s, i + 1);
      stepNodes.set(s.id, node);
      steps.appendChild(node);
    });
    if (editing) steps.appendChild(h("div", { class: "r-runbook__actions" }, h("button", { type: "button", class: "r-btn r-btn--small r-runbook__add", onClick: () => rbStore.addStep(key, { question: "New step" }).catch(fail) }, "Add step")));
    if (editing) {
      const notes = h("textarea", { class: "r-input r-runbook__ta", rows: 3, placeholder: "anything the next analyst on this rule should know", "aria-label": "Notes", onChange: (e) => rbStore.update(key, { notes: e.target.value }).catch(fail) });
      notes.value = rb.notes || "";
      steps.appendChild(h("label", { class: "r-runbook__field" }, "Notes", notes));
    } else if (rb.notes) {
      steps.appendChild(h("p", { class: "r-runbook__notes" }, h("strong", null, "Notes. "), rb.notes));
    }
    const share = shareRow();
    if (share) steps.appendChild(share);
    const benign = h(
      "section",
      { class: "r-section" },
      headingNode("benign-conditions", rb.benign_when.length),
      editing ? conditionsEditor("benign_when", rb.benign_when, "Benign conditions") : rb.benign_when.length ? h("ul", { class: "r-list" }, rb.benign_when.map((b) => h("li", null, b.text))) : h("p", { class: "r-muted" }, seeded ? "The rule's author lists no false-positive condition." : "No seed: nothing is known to be benign yet."),
      primary ? null : h("p", { class: "r-muted" }, "No entity on the row to mark benign."),
    );
    const escalate = h(
      "section",
      { class: "r-section" },
      headingNode("escalation-conditions", rb.escalate_when.length),
      editing ? conditionsEditor("escalate_when", rb.escalate_when, "Escalation conditions") : rb.escalate_when.length ? h("ul", { class: "r-list" }, rb.escalate_when.map((b) => h("li", null, b.text))) : h("p", { class: "r-muted" }, "No escalation condition yet."),
      primary ? null : h("p", { class: "r-muted" }, "No entity on the row to hold."),
    );
    replace(body, seedLine, draftSection(), steps, benign, escalate, status);
    const sel = !editing && ctx.params.sel && vm.steps.find((s) => s.id === ctx.params.sel && s.pivot && s.pivot.edge);
    if (sel) select(sel);
  }

  let drawn = false;
  const off = rbStore.subscribe(() => {
    if (!el.isConnected) {
      off();
      return;
    }
    if (!drawn) return;
    const next = rbStore.get(key);
    if (!next) return;
    rb = next;
    draw();
    // The draft's "in the runbook already" marks follow the stored steps.
    refreshDraft().then(() => {
      if (el.isConnected && rbStore.get(key) === rb) draw();
    });
  });
  // A notebook change (a Hold, a close) moves the close row and the draft.
  const offNb = notebook.subscribe(() => {
    if (!el.isConnected) {
      offNb();
      return;
    }
    if (!drawn) return;
    refreshDraft().then(() => {
      if (el.isConnected && rb) draw();
    });
  });

  // Resolves once the store (and the seed, on the first open; on
  // Sentinel the workspace lookup too) has filled the page; tests await
  // this instead of a timer.
  el.ready = (async () => {
    await rbStore.load();
    rb = rbStore.get(key);
    if (!rb) rb = await rbStore.seed(await seedNow());
    workspace = isSentinel() ? await currentWorkspace() : null;
    await notebook.load();
    await refreshDraft();
    draw();
    drawn = true;
  })().catch((err) => {
    replace(body, h("section", { class: "r-section" }, callout({ kind: "caution", label: "Could not seed", body: String((err && err.message) || err) })));
  });

  return el;
}

export default { render };
