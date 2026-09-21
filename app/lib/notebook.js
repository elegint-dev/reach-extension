// notebook: the investigation the analyst is on, and the ones before it.
// Three levels of holding a value: a glance (the value popup, gone when it
// closes), a thread (a pin with where it came from, and what was done with
// it), and an investigation (a named set of threads that survives
// sessions). This store keeps the last two. Environment facts (the index,
// a tenant) stay in app/lib/pinned.js and the tab's case facts in
// app/lib/investigation.js; nothing here reads or writes those. A pin here
// is a value the analyst is tracking, with provenance.
//
// Model. One document under store key "notebook" (reach.notebook in
// chrome.storage.local, so the in-page popups and the app share it;
// localStorage, then memory, when served as a plain page):
//
//   { v: 1, current: id | null, investigations: [investigation, ...] }
//   investigation  { id, title | null, created, updated, trigger, status: open | closed,
//                    closed?, from?: provenance, origin?: origin, outcome?: outcome, entries: [entry, ...] }
//   entry          { id, kind, at, reason?, from?: provenance, links?: [{ to, rel }], ... }
//   provenance     { platform, container, column, scope, event { id, time, summary },
//                    search { text, sid, earliest, latest, at }, at }
//   origin         { ruleKey, ruleName, platform, at }   the alert rule the investigation started
//                    from (a runbook page or band); absent, read as null, when it started anywhere else
//   outcome        { result: benign | escalated | inconclusive, at, evidence { kind: hold | benign,
//                    entry, field, value }, reason }   how it closed, from the runbook page's close step
//
// Provenance is platform-neutral: container is a Splunk sourcetype or a
// Sentinel table, column a field or a column, scope an index or a
// workspace. Entry kinds (the graph is implicit in the ids they carry):
//
//   pin         { field, value, from }            a node; from is required
//   pivot       { origin, target?, query { text, language }, name?, found? }   an edge
//   note        { text, on?, finding? }           attaches to a node
//   enrichment  { source, summary, result?, on }  attaches to a node
//   parked      { field?, value?, why, on?, state: parked | resumed }   an unexpanded thread
//   verdict     { verdict, source?, on }          wave E attaches these
//   benign      { on?, field?, value? }           wave F attaches these
//
// There is always a current investigation: the first record() starts one
// with no title, and the analyst names it when it matters. The document is
// size-bounded; past the bound the oldest closed investigations go first,
// then the oldest open ones, never the current one, and a "pruned" event
// says what went.
//
//   await load()                          → the document. Every write loads first; the
//                                           readers below are synchronous and answer empty
//                                           until it has resolved, so a view awaits it once
//   list({ status?, rule? })              → investigations, newest first; rule narrows to one origin.ruleKey
//   byRule({ status? })                   → [{ ruleKey, ruleName, platform, investigations }], the ones
//                                           with no origin last under ruleKey null
//   get(id), current(), currentId()
//   await start({ title?, trigger?, from?, origin? })   → a new investigation, made current
//   await setCurrent(id), rename(id, title), setTrigger(id, text), setOrigin(id, origin), reopen(id), remove(id)
//   await close(id, { outcome?, evidence?, reason? })   → closed; outcome one of OUTCOMES, evidence the
//                                           Hold or Mark benign it closed on; reopen clears the outcome
//   await record(pin, { investigation?, origin? })   → the pin entry (provenance checked); origin lands
//                                           only on an investigation this record starts
//   await add(entry, { investigation?, origin? })    → any entry kind
//   await note(text, { on?, finding?, reason? }), pivot({...}), enrich({...}), park({...}), resume(entryId)
//   await update(entryId, patch), removeEntry(entryId), link(fromId, toId, rel)
//   thread(entryId, { investigation? })   → entries connected to one entry, in order
//   exportMarkdown(id?, { thread? }), exportText(id?, { thread? }), exportJSON(id?)
//   await importDoc(text | object, { makeCurrent? })   → the imported investigation
//   subscribe(fn)                         → fn({ type: "change" | "pruned", ... }); returns unsubscribe
//   await prune()                         → { pruned: [{ id, title }], warning }
//   bytes()                               → the document's size as stored
//
// Writes go through app/lib/document.js: one serialised chain that rereads
// first, so a pin from a popup and a note from the app do not race on the
// same document. No DOM.

import { versionedDocument, newId as makeId } from "./document.js";
import * as md from "./notebook-md.js";
import * as searches from "./searches.js";

export const KEY = "notebook";
export const VERSION = 1;
export const MAX_BYTES = 1_000_000;
export const KINDS = md.KINDS;
export const OUTCOMES = md.OUTCOMES;

function newId(prefix) {
  return makeId(prefix);
}

function now() {
  return Date.now();
}

function empty() {
  return { v: VERSION, current: null, investigations: [] };
}

// Any stored shape becomes the current one; a foreign or damaged document
// becomes an empty notebook rather than a broken app.
function adopt(raw) {
  const out = empty();
  if (!raw || typeof raw !== "object") return out;
  const seen = new Set();
  for (const inv of Array.isArray(raw.investigations) ? raw.investigations : []) {
    try {
      const s = md.sanitize(inv);
      if (!seen.has(s.id)) {
        seen.add(s.id);
        out.investigations.push(s);
      }
    } catch {
      /* dropped */
    }
  }
  if (typeof raw.current === "string" && seen.has(raw.current)) out.current = raw.current;
  return out;
}

// ---- pruning ----------------------------------------------------------

// The oldest closed investigations go first, then the oldest open ones,
// never the current one.
function pruneInPlace(d, { bytes: size, budget }) {
  const pruned = [];
  const candidates = () =>
    d.investigations
      .filter((inv) => inv.id !== d.current)
      .sort((a, b) => (a.status === "closed") === (b.status === "closed") ? (a.updated || 0) - (b.updated || 0) : a.status === "closed" ? -1 : 1);
  while (size(d) > budget) {
    const victim = candidates()[0];
    if (!victim) break;
    d.investigations = d.investigations.filter((inv) => inv.id !== victim.id);
    pruned.push({ id: victim.id, title: md.displayTitle(victim), status: victim.status });
  }
  let warning = "";
  if (pruned.length) warning = `The notebook was over its ${Math.round(budget / 1000)} KB bound: ${pruned.length === 1 ? "the oldest investigation" : `the ${pruned.length} oldest investigations`} (${pruned.map((p) => p.title).join(", ")}) ${pruned.length === 1 ? "was" : "were"} removed. Export what you want to keep before it grows again.`;
  if (size(d) > budget) warning = `${warning ? warning + " " : ""}The current investigation alone is over the bound; export it and start a new one.`;
  return { pruned, warning };
}

const D = versionedDocument({ key: KEY, version: VERSION, empty, adopt, prune: pruneInPlace, budget: MAX_BYTES });

// A search-history write stamps the current investigation's id; the
// searches document reads it through this hook and never starts one.
searches.useInvestigation(async () => {
  await D.load();
  return D.get().current || null;
});

export function load(opts) {
  return D.load(opts);
}

export function bytes(d) {
  return D.bytes(d);
}

// An explicit prune is an empty write: the write's own pruning step does
// the work and emits once.
export function prune() {
  return D.prune();
}

// ---- investigations ---------------------------------------------------

function find(d, id) {
  return d.investigations.find((inv) => inv.id === id) || null;
}

function need(d, id) {
  const inv = find(d, id);
  if (!inv) throw new Error(`No investigation ${id}.`);
  return inv;
}

function touch(inv) {
  inv.updated = now();
}

export function list({ status = null, rule = null } = {}) {
  const all = D.get().investigations.slice();
  let out = status ? all.filter((inv) => inv.status === status) : all;
  if (rule) out = out.filter((inv) => inv.origin && inv.origin.ruleKey === rule);
  return out.sort((a, b) => (b.updated || 0) - (a.updated || 0));
}

// The investigations grouped by the rule they started from, groups in
// the order of their newest investigation, the ones with no origin last.
export function byRule({ status = null } = {}) {
  const groups = new Map();
  for (const inv of list({ status })) {
    const key = inv.origin ? inv.origin.ruleKey : null;
    if (!groups.has(key)) groups.set(key, { ruleKey: key, ruleName: inv.origin ? inv.origin.ruleName || null : null, platform: inv.origin ? inv.origin.platform || null : null, investigations: [] });
    groups.get(key).investigations.push(inv);
  }
  const out = Array.from(groups.values());
  const none = out.find((g) => g.ruleKey === null);
  return [...out.filter((g) => g.ruleKey !== null), ...(none ? [none] : [])];
}

export function get(id) {
  return find(D.get(), id);
}

export function currentId() {
  return D.get().current;
}

export function current() {
  const d = D.get();
  return d.current ? find(d, d.current) : null;
}

function makeInvestigation({ title = null, trigger = "", from = null, origin = null } = {}) {
  const t = now();
  const inv = { id: newId("inv"), title: title ? String(title).trim() || null : null, created: t, updated: t, trigger: String(trigger || "").trim(), status: "open", entries: [] };
  const f = md.sanitizeFrom(from);
  if (f) inv.from = f;
  const o = md.sanitizeOrigin(origin ? { at: t, ...origin } : null);
  if (o) inv.origin = o;
  return inv;
}

export function start(opts = {}) {
  return D.update((d) => {
    const inv = makeInvestigation(opts);
    d.investigations.push(inv);
    d.current = inv.id;
    return inv;
  });
}

export function setCurrent(id) {
  return D.update((d) => {
    const inv = need(d, id);
    d.current = inv.id;
    return inv;
  });
}

export function rename(id, title) {
  return D.update((d) => {
    const inv = need(d, id);
    inv.title = String(title || "").trim() || null;
    touch(inv);
    return inv;
  });
}

export function setTrigger(id, trigger) {
  return D.update((d) => {
    const inv = need(d, id);
    inv.trigger = String(trigger || "").trim();
    touch(inv);
    return inv;
  });
}

// The rule the investigation started from; null takes it off.
export function setOrigin(id, origin) {
  return D.update((d) => {
    const inv = need(d, id);
    const o = md.sanitizeOrigin(origin ? { at: now(), ...origin } : null);
    if (o) inv.origin = o;
    else delete inv.origin;
    touch(inv);
    return inv;
  });
}

// Closing the current investigation leaves nothing current; the next
// record() starts a new one. An outcome outside OUTCOMES rejects; the
// evidence is an entry already in the investigation (a pin for a Hold, a
// benign mark), never something this call records.
export function close(id, { outcome = null, evidence = null, reason = null } = {}) {
  if (outcome !== null && outcome !== undefined && !OUTCOMES.includes(outcome)) return Promise.reject(new Error(`An outcome is one of ${OUTCOMES.join(", ")}, not ${JSON.stringify(outcome)}.`));
  return D.update((d) => {
    const inv = need(d, id);
    inv.status = "closed";
    inv.closed = now();
    if (outcome) {
      let ev = null;
      if (evidence && typeof evidence === "object") {
        const entry = typeof evidence.entry === "string" ? inv.entries.find((e) => e.id === evidence.entry) : evidence.entry && evidence.entry.id ? inv.entries.find((e) => e.id === evidence.entry.id) : null;
        const kind = evidence.kind || (entry ? (entry.kind === "benign" ? "benign" : "hold") : null);
        ev = { kind, entry: entry ? entry.id : undefined, field: evidence.field || (entry && entry.field) || undefined, value: evidence.value || (entry && entry.value) || undefined };
      }
      const o = md.sanitizeOutcome({ result: outcome, at: inv.closed, evidence: ev, reason });
      if (o) inv.outcome = o;
    } else delete inv.outcome;
    touch(inv);
    if (d.current === inv.id) d.current = null;
    return inv;
  });
}

export function reopen(id) {
  return D.update((d) => {
    const inv = need(d, id);
    inv.status = "open";
    delete inv.closed;
    delete inv.outcome;
    touch(inv);
    d.current = inv.id;
    return inv;
  });
}

export function remove(id) {
  return D.update((d) => {
    const inv = need(d, id);
    d.investigations = d.investigations.filter((x) => x.id !== inv.id);
    if (d.current === inv.id) d.current = null;
    return inv;
  });
}

// The implicit current investigation, made on first use.
function currentOrStart(d, seed) {
  let inv = d.current ? find(d, d.current) : null;
  if (inv && inv.status === "closed") inv = null;
  if (!inv) {
    inv = makeInvestigation(seed);
    d.investigations.push(inv);
    d.current = inv.id;
  }
  return inv;
}

function targetInvestigation(d, id, seed) {
  if (id) return need(d, id);
  return currentOrStart(d, seed);
}

// ---- entries ------------------------------------------------------------

function hasValue(v) {
  return v !== undefined && v !== null && String(v) !== "";
}

// A pin without provenance is a glance, not a thread: value, field and a
// platform are required; the container may be unknown (a value clicked
// where Reach could not tell the sourcetype), the event and the search are
// kept whenever the click had them.
export function checkPin(pin) {
  if (!pin || typeof pin !== "object") throw new Error("A pin needs a value, a field and where it came from.");
  const missing = [];
  if (!hasValue(pin.value)) missing.push("value");
  if (!hasValue(pin.field) && !(pin.from && hasValue(pin.from.column))) missing.push("field");
  if (!pin.from || typeof pin.from !== "object") missing.push("from");
  else if (!hasValue(pin.from.platform)) missing.push("from.platform");
  if (missing.length) throw new Error(`A pin needs provenance: missing ${missing.join(", ")}.`);
}

function build(entry) {
  const at = typeof entry.at === "number" ? entry.at : now();
  const raw = { ...entry, id: entry.id || newId("e"), at };
  if (raw.kind === "pin") {
    checkPin(raw);
    raw.field = raw.field || raw.from.column;
    raw.from = { ...raw.from, column: raw.from.column || raw.field, at: typeof raw.from.at === "number" ? raw.from.at : at };
  }
  if (raw.kind === "parked" && !raw.state) raw.state = "parked";
  const e = md.sanitizeEntry(raw);
  if (!e) throw new Error(`Not an entry kind this notebook keeps: ${entry && entry.kind}.`);
  return e;
}

function seedFrom(entry) {
  const f = entry && entry.from;
  if (!f) return {};
  const trigger = entry.kind === "pin" ? `${entry.field || f.column} = ${entry.value}${f.container ? ` on ${f.container}` : ""}` : "";
  return { trigger, from: { platform: f.platform, container: f.container, scope: f.scope } };
}

export async function add(entry, { investigation = null, origin = null } = {}) {
  const e = build(entry || {}); // a bad entry rejects, same as a bad write
  return D.update((d) => {
    const inv = targetInvestigation(d, investigation, { ...seedFrom(e), origin });
    if (inv.entries.some((x) => x.id === e.id)) throw new Error(`Entry ${e.id} is already in ${md.displayTitle(inv)}.`);
    for (const ref of [e.on, e.origin, e.target]) {
      if (ref && !inv.entries.some((x) => x.id === ref)) throw new Error(`Entry ${ref} is not in ${md.displayTitle(inv)}.`);
    }
    inv.entries.push(e);
    touch(inv);
    return e;
  });
}

// notebook.record(pin): the one call the pin actions wire in. The pin is
// { field, value, from: { platform, container, column, scope, event, search }, reason }.
export function record(pin, opts) {
  return add({ ...pin, kind: "pin" }, opts);
}

export function note(text, { on = null, finding = false, reason = null, from = null, investigation = null } = {}) {
  return add({ kind: "note", text, on, finding, reason, from }, { investigation });
}

export function pivot({ origin, target = null, query = null, name = null, found = null, reason = null, from = null, at = undefined }, { investigation = null } = {}) {
  return add({ kind: "pivot", origin, target, query, name, found, reason, from, at }, { investigation });
}

export function enrich({ on, source, summary = "", result = null, reason = null, at = undefined }, { investigation = null } = {}) {
  return add({ kind: "enrichment", on, source, summary, result, reason, at }, { investigation });
}

export function park({ on = null, field = null, value = null, why = "", from = null, at = undefined }, { investigation = null } = {}) {
  return add({ kind: "parked", on, field, value, why, from, at }, { investigation });
}

function locate(d, entryId, investigation) {
  const invs = investigation ? [need(d, investigation)] : d.investigations;
  for (const inv of invs) {
    const e = inv.entries.find((x) => x.id === entryId);
    if (e) return { inv, e };
  }
  throw new Error(`No entry ${entryId}.`);
}

export function update(entryId, patch, { investigation = null } = {}) {
  return D.update((d) => {
    const { inv, e } = locate(d, entryId, investigation);
    const next = md.sanitizeEntry({ ...e, ...(patch || {}), id: e.id, kind: e.kind });
    if (!next) throw new Error("The change does not leave a valid entry.");
    if (next.kind === "pin") checkPin(next);
    inv.entries[inv.entries.indexOf(e)] = next;
    touch(inv);
    return next;
  });
}

export function resume(entryId, opts) {
  return update(entryId, { state: "resumed" }, opts);
}

export function removeEntry(entryId, { investigation = null } = {}) {
  return D.update((d) => {
    const { inv, e } = locate(d, entryId, investigation);
    inv.entries = inv.entries.filter((x) => x.id !== e.id);
    for (const x of inv.entries) {
      if (x.links) x.links = x.links.filter((l) => l.to !== e.id);
      for (const k of ["on", "origin", "target"]) if (x[k] === e.id) delete x[k];
    }
    touch(inv);
    return e;
  });
}

export function link(fromId, toId, rel = "related", { investigation = null } = {}) {
  return D.update((d) => {
    const { inv, e } = locate(d, fromId, investigation);
    if (!inv.entries.some((x) => x.id === toId)) throw new Error(`Entry ${toId} is not in ${md.displayTitle(inv)}.`);
    e.links = (e.links || []).filter((l) => !(l.to === toId && l.rel === rel));
    e.links.push({ to: toId, rel });
    touch(inv);
    return e;
  });
}

// Everything connected to one entry (its pivots, what they surfaced, the
// notes and results attached, the thread it was parked from), in entry
// order: the thread level.
export function thread(entryId, { investigation = null } = {}) {
  let found;
  try {
    found = locate(D.get(), entryId, investigation);
  } catch {
    return [];
  }
  const { inv } = found;
  const adj = new Map();
  const join = (a, b) => {
    if (!a || !b) return;
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a).add(b);
    adj.get(b).add(a);
  };
  for (const e of inv.entries) {
    for (const k of ["on", "origin", "target"]) join(e.id, e[k]);
    for (const l of e.links || []) join(e.id, l.to);
  }
  const seen = new Set([entryId]);
  const stack = [entryId];
  while (stack.length) {
    const id = stack.pop();
    for (const n of adj.get(id) || []) {
      if (!seen.has(n)) {
        seen.add(n);
        stack.push(n);
      }
    }
  }
  return inv.entries.filter((e) => seen.has(e.id));
}

// ---- export and import ------------------------------------------------

function pickInv(id) {
  const inv = id ? get(id) : current();
  if (!inv) throw new Error(id ? `No investigation ${id}.` : "No current investigation.");
  return inv;
}

// The export carries the searches Reach handed on during the investigation
// (app/lib/searches.js), under their own heading, when there are any.
export function exportMarkdown(id = null, { thread: threadOf = null } = {}) {
  const inv = pickInv(id);
  return md.toMarkdown(inv, { entries: threadOf ? thread(threadOf, { investigation: inv.id }) : null, searches: threadOf ? null : searches.forInvestigation(inv.id) });
}

export function exportText(id = null, { thread: threadOf = null } = {}) {
  const inv = pickInv(id);
  return md.toText(inv, { entries: threadOf ? thread(threadOf, { investigation: inv.id }) : null, searches: threadOf ? null : searches.forInvestigation(inv.id) });
}

export function exportJSON(id = null) {
  return { kind: md.DOC_KIND, v: md.DOC_VERSION, investigation: pickInv(id) };
}

// Markdown carrying the machine copy, or JSON. An investigation whose id is
// already in the notebook comes in under a new id; the copy is kept.
export async function importDoc(text, { makeCurrent = false } = {}) {
  const inv = md.parse(text); // unreadable text rejects
  return D.update((d) => {
    if (find(d, inv.id)) inv.id = newId("inv");
    d.investigations.push(inv);
    if (makeCurrent) d.current = inv.id;
    return inv;
  });
}

export function subscribe(fn) {
  return D.subscribe(fn);
}

export default { load, list, byRule, get, current, currentId, start, setCurrent, rename, setTrigger, setOrigin, close, reopen, remove, record, add, note, pivot, enrich, park, resume, update, removeEntry, link, thread, exportMarkdown, exportText, exportJSON, importDoc, subscribe, prune, bytes, checkPin, KEY, KINDS, OUTCOMES, MAX_BYTES };
