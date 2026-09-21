// Notebook: #/notebook, the investigation the analyst is on, and
// #/notebook?id=<id>, one from the list. The store is app/lib/notebook.js;
// the words are notebook-md.js's, drawn here as DOM instead of Markdown.
// The title block first (the name as an input inside the h1, the status
// chip, the scope line, the action row: Copy with a format choice, Close
// or Reopen, Start new), then the sections in the registry's order:
// Threads (N), the entries grouped by thread with parked threads folded;
// Timeline, the trigger input then the narrative by UTC day; Search
// history (N), every query Reach handed on (app/lib/searches.js), newest
// first and this investigation's first, drawn with no investigation open
// too, each with Re-run through the editor bridge and Copy; Investigations,
// the list to reopen, grouped by the alert rule each started from (the
// ones that started elsewhere last), each with how it closed; Import an
// investigation, a copy pasted back (the hold module's own, on every install).
//
// The pure half, tested without a DOM (tests/notebook-view.test.js):
//
//   threads(inv) → [{ id, root, entries, parked }]
//       entries joined by on / origin / target / links are one thread, in
//       entry order; root is its first entry; parked when its last parked
//       entry was not picked up again
//   threadTitle(thread, inv, md?) → the root's field = value, or its sentence
//   model(inv, { surface }) → { title, status, trigger, rule, outcome, started, lastChange, days, threads, open(thread) }
//       days from notebook-md narrative, each line with its entry; rule and
//       outcome the header's words for the origin and the close; open()
//       says whether a thread's fold starts open: never in the panel, never
//       for a parked thread, else yes
//   groups() → [{ ruleKey, ruleName, platform, investigations }]   notebook.byRule()
//   foldState(thread, surface) → boolean   the same rule alone
//   searchRows(entries, inv) → [{ entry, name, where, time, preview, badge }]
//       the search history's rows in list order, one line of text each
//   preview(text) → one line of at most PREVIEW_CHARS characters
//
// Local only: nothing here leaves the browser except through the clipboard
// when a copy button is pressed.

import { h, replace } from "../components/h.js";
import { chip } from "../components/chip.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import * as notebook from "../lib/notebook.js";
import * as searches from "../lib/searches.js";
import * as bridge from "../lib/editor-bridge.js";
import * as discovery from "../lib/discovery.js";
import { isPortalOrigin } from "../lib/platform.js";
import * as modules from "../lib/modules.js";
import { when } from "../lib/when.js";
import * as md from "../lib/notebook-md.js";
import { surface as currentSurface } from "../lib/surface.js";
import { copyText } from "../lib/runtime.js";

// ---------------------------------------------------------------------------
// The pure half

function refsOf(e) {
  const out = [];
  for (const k of ["on", "origin", "target"]) if (e[k]) out.push(e[k]);
  for (const l of e.links || []) if (l && l.to) out.push(l.to);
  return out;
}

export function threads(inv) {
  const entries = Array.isArray(inv && inv.entries) ? inv.entries : [];
  const ids = new Set(entries.map((e) => e.id));
  const parent = new Map();
  const find = (x) => {
    while (parent.get(x) !== x) {
      parent.set(x, parent.get(parent.get(x)));
      x = parent.get(x);
    }
    return x;
  };
  const union = (a, b) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(rb, ra);
  };
  for (const e of entries) parent.set(e.id, e.id);
  for (const e of entries) for (const r of refsOf(e)) if (ids.has(r)) union(e.id, r);
  const groups = new Map();
  for (const e of entries) {
    const root = find(e.id);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(e);
  }
  const out = [];
  for (const list of groups.values()) {
    const parkedEntries = list.filter((e) => e.kind === "parked");
    const last = parkedEntries[parkedEntries.length - 1];
    out.push({ id: list[0].id, root: list[0], entries: list, parked: Boolean(last && last.state !== "resumed") });
  }
  // Threads in the order they started; the root is the earliest entry.
  return out.sort((a, b) => (a.root.at || 0) - (b.root.at || 0));
}

export function threadTitle(thread, inv, useMd = false) {
  const root = thread.root;
  const field = root.field || (root.from && root.from.column);
  if (root.value !== undefined && root.value !== null && root.value !== "") return field ? `${field} = ${root.value}` : String(root.value);
  const ids = new Map((inv && inv.entries ? inv.entries : []).map((e) => [e.id, e]));
  return md.sentence(root, ids, useMd);
}

export function foldState(thread, surface = "wide") {
  if (thread.parked) return false;
  return surface !== "panel";
}

export function model(inv, { surface = "wide" } = {}) {
  if (!inv) return null;
  const ids = new Map((inv.entries || []).map((e) => [e.id, e]));
  const days = md.narrative(inv, null, false).map((g) => ({ day: g.day, lines: g.lines.map((l) => ({ ...l })) }));
  // narrative() walks the entries in order, one line each, so the lines
  // line up with them.
  let n = 0;
  for (const g of days) for (const l of g.lines) l.entry = inv.entries[n++];
  const ts = threads(inv);
  const status = inv.status === "closed" ? `closed ${md.stamp(inv.closed || inv.updated)}${inv.outcome ? ` as ${inv.outcome.result}` : ""}` : "open";
  return {
    title: md.displayTitle(inv),
    untitled: !inv.title,
    status,
    trigger: inv.trigger || "",
    rule: md.originWords(inv.origin),
    outcome: md.outcomeWords(inv.outcome),
    started: md.stamp(inv.created),
    lastChange: md.stamp(inv.updated || inv.created),
    days,
    threads: ts,
    ids,
    open: (t) => foldState(t, surface),
  };
}

// ---------------------------------------------------------------------------
// The DOM half

const KIND_WORD = { pin: "held", pivot: "pivot", note: "note", enrichment: "result", parked: "parked", verdict: "verdict", benign: "benign" };

function fail(status, err) {
  status.textContent = err && err.message ? err.message : String(err);
}

// One entry as a line: its kind, the sentence, and what can be done to it.
function entryLine(e, m, inv, status) {
  const sentence = md.sentence(e, m.ids, false);
  const actions = h("span", { class: "r-nb__acts" });
  const editor = h("div", { class: "r-nb__edit", hidden: true });
  const line = h("div", { class: ["r-nb__entry", `r-nb__entry--${e.kind}`], dataset: { entryId: e.id } }, h("span", { class: "r-nb__kind" }, KIND_WORD[e.kind] || e.kind), h("span", { class: "r-nb__text" }, sentence), actions, editor);

  const openEditor = (mode) => {
    const isNote = mode === "note";
    const key = e.kind === "note" ? "text" : e.kind === "parked" ? "why" : "reason";
    const input = h("textarea", { class: "r-input r-nb__ta", rows: 2, placeholder: isNote ? "a note on this entry" : key === "text" ? "the note" : key === "why" ? "why it was parked" : "why you are holding it", "aria-label": isNote ? "Note" : "Edit" });
    if (!isNote) input.value = e[key] || "";
    const save = h("button", { type: "button", class: "r-btn r-btn--small r-btn--primary" }, isNote ? "Add note" : "Save");
    const finding = isNote ? h("label", { class: "r-nb__finding" }, h("input", { type: "checkbox" }), " finding") : null;
    const cancel = h("button", { type: "button", class: "r-btn r-btn--small", onClick: () => { editor.hidden = true; editor.replaceChildren(); } }, "Cancel");
    save.addEventListener("click", async () => {
      const text = input.value.trim();
      try {
        if (isNote) {
          if (!text) return;
          await notebook.note(text, { on: e.id, finding: Boolean(finding && finding.querySelector("input").checked), investigation: inv.id });
        } else await notebook.update(e.id, { [key]: text }, { investigation: inv.id });
      } catch (err) {
        fail(status, err);
      }
    });
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" && (ev.metaKey || ev.ctrlKey)) save.click();
      if (ev.key === "Escape") cancel.click();
    });
    replace(editor, input, h("div", { class: "r-nb__editacts" }, save, finding, cancel));
    editor.hidden = false;
    input.focus();
  };

  const act = (label, title, fn) => h("button", { type: "button", class: "r-nb__act", title, onClick: fn }, label);
  actions.append(act("note", "Attach a note to this entry", () => openEditor("note")));
  actions.append(act("edit", e.kind === "note" ? "Edit the note" : e.kind === "parked" ? "Edit why it was parked" : "Edit the reason", () => openEditor("edit")));
  if (e.kind === "parked" && e.state !== "resumed") actions.append(act("resume", "Pick this thread up again", () => notebook.resume(e.id, { investigation: inv.id }).catch((err) => fail(status, err))));
  if (e.kind === "pin") actions.append(act("park", "Park this thread: keep it, come back later", () => notebook.park({ on: e.id, field: e.field, value: e.value, why: "", from: e.from }, { investigation: inv.id }).catch((err) => fail(status, err))));
  actions.append(act("×", "Remove this entry", () => notebook.removeEntry(e.id, { investigation: inv.id }).catch((err) => fail(status, err))));
  return line;
}

// The Copy action: one button, a menu with the two formats under it.
function copyMenu(inv) {
  const menu = h("div", { class: "r-nb__copymenu", hidden: true, role: "menu" });
  const btn = h("button", { type: "button", class: "r-btn", "aria-haspopup": "menu", "aria-expanded": "false", onClick: () => open(menu.hidden) }, "Copy ▾");
  const open = (on) => {
    menu.hidden = !on;
    btn.setAttribute("aria-expanded", on ? "true" : "false");
  };
  const choice = (label, title, text) =>
    h("button", { type: "button", class: "r-btn r-btn--small", role: "menuitem", title, onClick: (e) => { open(false); copyText(text(), btn, `Copied ${label.toLowerCase()}`); } }, label);
  menu.append(
    choice("Markdown", "The whole investigation as Markdown, with a machine copy that imports back", () => notebook.exportMarkdown(inv.id)),
    choice("Plain text", "For a notes box that takes no Markdown: an ES notable's notes, an incident comment", () => notebook.exportText(inv.id)),
  );
  return h("span", { class: "r-nb__copy" }, btn, menu);
}

function header(inv, m, ctx, status) {
  const title = h("input", { class: "r-input r-nb__title", type: "text", value: inv.title || "", placeholder: m.untitled ? `${m.title}: name it` : "name", "aria-label": "Investigation name", autocomplete: "off", spellcheck: "false" });
  const commit = () => {
    const t = title.value.trim();
    if (t === (inv.title || "")) return;
    notebook.rename(inv.id, t).catch((err) => fail(status, err));
  };
  title.addEventListener("change", commit);
  title.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      commit();
      title.blur();
    }
  });

  const isCurrent = notebook.currentId() === inv.id;
  const closed = inv.status === "closed";
  const btn = (label, fn, titleText = "") => h("button", { type: "button", class: "r-btn", title: titleText || null, onClick: fn }, label);
  const platform = inv.from && inv.from.platform ? (inv.from.platform === "sentinel" ? "Sentinel" : "Splunk") : null;
  const scopeWord = inv.from && inv.from.platform === "sentinel" ? "workspace" : "index";
  const outcome = closed && inv.outcome ? inv.outcome.result : null;
  return titleBlock({
    kind: "notebook",
    h1: title,
    chips: [chip({ kind: "trust", value: closed ? "inferred" : "confirmed", text: closed ? (outcome ? `closed as ${outcome}` : "closed") : isCurrent ? "current" : "open", title: m.outcome || "" })],
    scope: [`started ${m.started}`, `last change ${m.lastChange}`, platform, inv.from && inv.from.scope ? `${scopeWord} ${inv.from.scope}` : null, inv.origin ? h("span", { class: "r-nb__rule", title: inv.origin.ruleKey }, "from rule ", h("a", { class: "r-idlink", href: `#/runbook/${encodeURIComponent(inv.origin.ruleKey)}${inv.origin.ruleName ? `?rule=${encodeURIComponent(inv.origin.ruleName)}` : ""}` }, inv.origin.ruleName || inv.origin.ruleKey)) : null],
    actions: [
      copyMenu(inv),
      closed
        ? btn("Reopen", () => notebook.reopen(inv.id).catch((err) => fail(status, err)), "Open it again and make it the current one")
        : btn("Close", () => notebook.close(inv.id).catch((err) => fail(status, err)), "Done with it: the next Hold starts a new one"),
      btn("Start new", () => notebook.start({}).then(() => ctx.navigate("notebook", {})).catch((err) => fail(status, err)), "A new, unnamed investigation; this one stays"),
      !isCurrent && !closed ? btn("Make current", () => notebook.setCurrent(inv.id).catch((err) => fail(status, err))) : null,
    ],
  });
}

// Timeline: the trigger as its first row, then the entries by day.
function timeline(m, inv, status) {
  const trigger = h("input", { class: "r-input r-nb__trigger", type: "text", value: inv.trigger || "", placeholder: "what started it (an alert, a ticket, a hunch)", "aria-label": "Trigger", autocomplete: "off", spellcheck: "false" });
  trigger.addEventListener("change", () => notebook.setTrigger(inv.id, trigger.value).catch((err) => fail(status, err)));
  const body = [h("label", { class: "r-nb__label" }, "Trigger ", trigger)];
  if (!m.days.length) body.push(h("p", { class: "r-muted" }, "Nothing recorded yet. Hold a value from a popup or the value page and it lands here with where it came from."));
  for (const g of m.days) {
    body.push(h("h3", { class: "r-nb__day" }, g.day));
    body.push(h("div", { class: "r-nb__lines" }, g.lines.map((l) => h("div", { class: "r-nb__line" }, h("span", { class: "r-nb__time" }, l.time), entryLine(l.entry, m, inv, status)))));
  }
  return h("section", { class: "r-section r-nb__timeline" }, headingNode("timeline"), ...body);
}

function threadList(m, inv, status) {
  if (!m.threads.length) return null;
  const folds = m.threads.map((t) =>
    h(
      "details",
      { class: ["r-nb__thread", t.parked && "r-nb__thread--parked"], open: m.open(t) },
      h("summary", { class: "r-nb__summary" }, h("span", { class: "r-nb__threadtitle" }, threadTitle(t, inv)), h("span", { class: "r-nb__count" }, `${t.entries.length} ${t.entries.length === 1 ? "entry" : "entries"}`), t.parked ? chip({ kind: "trust", value: "inferred", text: "parked" }) : null),
      h("div", { class: "r-nb__lines" }, t.entries.map((e) => h("div", { class: "r-nb__line" }, h("span", { class: "r-nb__time" }, md.clock(e.at)), entryLine(e, m, inv, status)))),
    ),
  );
  return h("section", { class: "r-section r-nb__threads" }, headingNode("threads", m.threads.length), h("p", { class: "r-secondary" }, "A held value with what was done from it. A parked thread is folded until it is picked up again."), ...folds);
}

function investigationItem(inv, cur, ctx, status) {
  const pins = inv.entries.filter((e) => e.kind === "pin").length;
  const open = h("a", { href: `#/notebook?id=${encodeURIComponent(inv.id)}`, class: "r-idlink" }, md.displayTitle(inv));
  const acts = h(
    "span",
    { class: "r-nb__acts" },
    inv.status === "closed"
      ? h("button", { type: "button", class: "r-nb__act", title: "Open it again and make it current", onClick: () => notebook.reopen(inv.id).then(() => ctx.navigate("notebook", {})).catch((err) => fail(status, err)) }, "reopen")
      : inv.id !== cur
        ? h("button", { type: "button", class: "r-nb__act", title: "Make it the one the next Hold lands in", onClick: () => notebook.setCurrent(inv.id).then(() => ctx.navigate("notebook", {})).catch((err) => fail(status, err)) }, "make current")
        : null,
    h("button", { type: "button", class: "r-nb__act", title: "Remove it from the notebook", onClick: () => { if (window.confirm(`Remove ${md.displayTitle(inv)}? Copy it first if you want to keep it.`)) notebook.remove(inv.id).catch((err) => fail(status, err)); } }, "×"),
  );
  const state = inv.status === "closed" ? (inv.outcome ? `closed as ${inv.outcome.result}` : "closed") : inv.id === cur ? "current" : "open";
  return h(
    "li",
    { class: ["r-nb__inv", inv.id === cur && "r-nb__inv--current"], dataset: { outcome: inv.outcome ? inv.outcome.result : "" } },
    open,
    h("span", { class: "r-nb__meta" }, `${state} · ${pins} ${pins === 1 ? "value" : "values"}, ${inv.entries.length} ${inv.entries.length === 1 ? "entry" : "entries"} · ${md.stamp(inv.updated || inv.created)}`),
    acts,
  );
}

export function groups() {
  return notebook.byRule();
}

// ---------------------------------------------------------------------------
// Search history

export const PREVIEW_CHARS = 160;

// The query as one line: whitespace folded, cut with an ellipsis past the limit.
export function preview(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  return t.length > PREVIEW_CHARS ? `${t.slice(0, PREVIEW_CHARS - 1)}…` : t;
}

const SOURCE_WORD = { copy: "copied", run: "ran", open: "opened", insert: "inserted", history: "from History" };

export function searchRows(entries, inv = null) {
  return (entries || []).map((e) => {
    const where = [e.container ? `on ${e.container}` : "", e.origin ? `from ${e.origin}` : "", SOURCE_WORD[e.source] || e.source || ""].filter(Boolean).join(" · ");
    return {
      entry: e,
      name: e.name || (e.field && e.value ? `${e.field} = ${e.value}` : e.field || ""),
      where,
      time: when(e.at),
      preview: preview(e.text),
      badge: e.language === "kql" ? "KQL" : "SPL",
      mine: Boolean(inv && e.investigation === inv.id),
    };
  });
}

async function splunkOrigin() {
  if (!discovery.available()) return undefined;
  const list = await discovery.environments().catch(() => []);
  const envs = list.filter((o) => o && o.origin && !isPortalOrigin(o.origin));
  const withTab = envs.find((o) => o.tabs);
  return (withTab || envs[0] || {}).origin;
}

// The bridge's notice lands on the page's status line: the hand-off is a
// write to the document, which redraws the rows under the click.
function searchLine(row, status) {
  const e = row.entry;
  const act = (label, title, fn) => h("button", { type: "button", class: "r-nb__act", title, onClick: fn }, label);
  const rerun = act("Re-run", e.platform === "sentinel" ? "Put it in the Logs editor, or copy it when none is open" : "Put it in the open Splunk tab's search bar, or copy it when none is open", async () => {
    status.textContent = "";
    try {
      // The active tab first (the panel sits beside it); from the app's own
      // tab, the search pages open on an enabled Splunk instance.
      const origin = e.platform === "splunk" ? await splunkOrigin() : undefined;
      const res = await bridge.apply({ text: e.text, mode: "set", form: "stage", platform: e.platform, origin, trace: { source: "run", origin: e.origin, container: e.container, name: e.name, value: e.value } });
      status.textContent = res && res.notice ? res.notice : res && res.ok ? "Done" : "Nothing happened";
    } catch (err) {
      fail(status, err);
    }
  });
  const copy = act("Copy", "Copy the query", (ev) => {
    copyText(e.text, ev.currentTarget, "copied");
    searches.record({ ...e, id: undefined, at: undefined, investigation: undefined, source: "copy" }).catch(() => {});
  });
  const rm = act("×", "Remove this entry", () => searches.remove(e.id).catch((err) => fail(status, err)));
  const head = h("span", { class: "r-nb__text" }, row.name ? h("b", { class: "r-nb__sname" }, row.name) : null, row.name && row.where ? " · " : "", row.where);
  return h(
    "div",
    { class: ["r-nb__line", "r-nb__search", row.mine && "r-nb__search--mine"], dataset: { searchId: e.id } },
    h("span", { class: "r-nb__time" }, row.time),
    h("div", { class: ["r-nb__entry", "r-nb__entry--search"] }, h("span", { class: "r-nb__kind" }, row.badge), head, h("code", { class: "r-nb__query", title: e.text }, row.preview), h("span", { class: "r-nb__acts" }, rerun, copy, rm)),
  );
}

// Newest first, this investigation's entries first; drawn with no
// investigation open once the log has an entry.
function searchList(inv, status) {
  const rows = searchRows(searches.list({ investigation: inv ? inv.id : null }), inv);
  if (!rows.length && !inv) return null;
  const clear = h("button", { type: "button", class: "r-btn r-btn--small", title: "Forget every query here; the notebook keeps its own entries", onClick: () => { if (window.confirm(`Clear the search history? ${rows.length} ${rows.length === 1 ? "entry goes" : "entries go"}.`)) searches.clear().catch((err) => fail(status, err)); } }, "Clear history");
  return h(
    "section",
    { class: "r-section r-nb__searches" },
    headingNode("search-history", rows.length),
    h("p", { class: "r-secondary" }, "Every query Reach copied, ran, opened or inserted for you, newest first. Re-run puts it back in the editor."),
    rows.length ? h("div", { class: "r-nb__lines" }, rows.map((r) => searchLine(r, status))) : h("p", { class: "r-muted" }, "Nothing handed on yet. Copy or run a pivot and it lands here."),
    rows.length ? h("div", { class: "r-nb__headacts" }, clear) : null,
  );
}

// The list by the rule each investigation started from: one group per
// rule (its name linking the runbook page, the count, how many closed
// each way), the investigations that started elsewhere last.
function investigationList(ctx, status) {
  const rows = notebook.list();
  const cur = notebook.currentId();
  if (!rows.length) return null;
  const parts = [];
  const byRule = groups();
  const grouped = byRule.some((g) => g.ruleKey !== null);
  for (const g of byRule) {
    const items = g.investigations.map((inv) => investigationItem(inv, cur, ctx, status));
    if (!grouped) {
      parts.push(h("ul", { class: "r-nb__invs" }, items));
      continue;
    }
    const n = g.investigations.length;
    const closed = g.investigations.filter((inv) => inv.status === "closed");
    const tally = [];
    for (const o of notebook.OUTCOMES) {
      const c = closed.filter((inv) => inv.outcome && inv.outcome.result === o).length;
      if (c) tally.push(`${c} ${o}`);
    }
    const meta = `${n} investigation${n === 1 ? "" : "s"}, ${closed.length} closed${tally.length ? ` (${tally.join(", ")})` : ""}`;
    const name = g.ruleKey
      ? h("a", { class: "r-idlink", href: `#/runbook/${encodeURIComponent(g.ruleKey)}${g.ruleName ? `?rule=${encodeURIComponent(g.ruleName)}` : ""}`, title: g.ruleKey }, g.ruleName || g.ruleKey)
      : "Not from an alert row";
    parts.push(h("section", { class: "r-nb__rulegroup", dataset: { ruleKey: g.ruleKey || "" } }, h("h3", { class: "r-nb__rulehead" }, name, " ", h("span", { class: "r-nb__meta" }, meta)), h("ul", { class: "r-nb__invs" }, items)));
  }
  return h("section", { class: "r-section r-nb__list" }, headingNode("investigations"), grouped ? h("p", { class: "r-secondary" }, "By the alert rule each started from; a rule with three closed drafts its runbook.") : null, ...parts);
}

function importer(ctx, status) {
  const ta = h("textarea", { class: "r-input r-nb__ta", rows: 3, placeholder: "Paste a Reach export here (the Markdown with its machine copy, or the JSON)", "aria-label": "Export to import" });
  const bring = async (text) => {
    const inv = await notebook.importDoc(text, { makeCurrent: true });
    ta.value = "";
    status.textContent = `Imported ${md.displayTitle(inv)}; it is the current investigation now.`;
    ctx.navigate("notebook", {});
  };
  const fromClip = h(
    "button",
    {
      type: "button",
      class: "r-btn",
      title: "Read the clipboard once, now",
      onClick: async () => {
        try {
          const nav = globalThis.navigator;
          if (!nav || !nav.clipboard || !nav.clipboard.readText) throw new Error("This page cannot read the clipboard; paste into the box instead.");
          await bring(await nav.clipboard.readText());
        } catch (err) {
          fail(status, err);
        }
      },
    },
    "Import from clipboard",
  );
  const fromBox = h("button", { type: "button", class: "r-btn", onClick: () => bring(ta.value).catch((err) => fail(status, err)) }, "Import the pasted text");
  return h("section", { class: "r-section r-nb__import" }, headingNode("import-investigation"), h("p", { class: "r-secondary" }, "An investigation exported from Reach (Copy as Markdown) comes back whole, under a new id if the same one is already here."), ta, h("div", { class: "r-nb__headacts" }, fromClip, fromBox));
}

// Nothing current: the title block alone, with the way to start one.
function empty(status) {
  return titleBlock({
    kind: "notebook",
    h1: "Notebook",
    chips: [h("span", { class: "r-chip r-chip--state" }, "nothing current")],
    scope: ["The next Hold starts one: a value from a popup or a value page lands here with where it came from."],
    actions: [h("button", { type: "button", class: "r-btn r-btn--primary", onClick: () => notebook.start({}).catch((err) => fail(status, err)) }, "Start one now")],
  });
}

export function render(ctx) {
  const el = h("div", { class: "r-view r-view--notebook" });
  const status = h("p", { class: "r-secondary r-nb__status", role: "status" });
  const wanted = ctx.params && ctx.params.id ? String(ctx.params.id) : null;

  function draw() {
    const inv = wanted ? notebook.get(wanted) : notebook.current();
    const parts = [];
    if (wanted && !inv) parts.push(titleBlock({ kind: "notebook", h1: wanted, chips: [h("span", { class: "r-chip r-chip--state" }, "no such investigation")], scope: ["Nothing in the notebook has that id."], actions: [h("a", { class: "r-btn", href: "#/notebook" }, "The current one")] }));
    else if (!inv) parts.push(empty(status));
    else {
      const m = model(inv, { surface: currentSurface() });
      parts.push(header(inv, m, ctx, status), threadList(m, inv, status), timeline(m, inv, status));
    }
    parts.push(searchList(inv || null, status), investigationList(ctx, status), importer(ctx, status), status);
    replace(el, parts);
  }

  const offNotebook = notebook.subscribe((ev) => {
    if (ev && ev.type === "pruned" && ev.warning) status.textContent = ev.warning;
    draw();
  });
  const offSearches = searches.subscribe((ev) => {
    if (ev && ev.type === "pruned" && ev.warning) status.textContent = ev.warning;
    draw();
  });
  el.unmount = () => {
    offNotebook();
    offSearches();
  };
  Promise.all([notebook.load(), searches.load()]).then(draw).catch((err) => fail(status, err));
  draw();
  return el;
}

export default { render, threads, threadTitle, model, foldState, groups, searchRows, preview, PREVIEW_CHARS };
