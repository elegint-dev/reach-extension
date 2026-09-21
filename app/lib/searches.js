// searches: every query Reach handed to the analyst or to the SIEM, newest
// first, so "what did I search an hour ago" has one answer that does not
// depend on a value being held. A write happens on the click that copies,
// runs, opens or inserts a query; a click that only displays one writes
// nothing. The hold module owns the document.
//
// Store. One document under store key "searches" (reach.searches in
// chrome.storage.local, shared by the in-page popups and the app):
//
//   { v: 1, entries: [entry, ...] }            oldest first as stored
//   entry { id, at, platform, language, text, source, origin, ran, sid?,
//           container?, field?, value?, name?, investigation? }
//
//   source        the control: copy | run | open | insert | history
//   origin        the surface: pivot | workflow | discovery | pattern |
//                 exclusion | runbook | advisor | history
//   ran, sid      true with the job id when Reach dispatched the search itself
//   name          the pivot's or workflow's name
//   investigation the current investigation's id at the write, when one exists
//
// The newest entry absorbs a repeat: a write whose text equals the newest
// entry's text moves that entry's time and updates its source, ran and sid
// instead of adding a second one. At most MAX_ENTRIES are kept, oldest
// out first, and the document is pruned to MAX_BYTES the same way. A
// write never starts an investigation and never touches the notebook.
//
//   await load()                          → the document; the readers are synchronous
//   list({ investigation? })              → entries newest first, the investigation's first when given
//   forInvestigation(id)                  → that investigation's entries, oldest first
//   count()                               → how many entries
//   await record({ text, platform?, language?, source?, origin?, container?, field?, value?, name?, ran?, sid?, at? })
//                                         → the entry written or refreshed, null for an empty text
//   await remove(id)                      → the removed entry | null
//   await clear()                         → how many were removed
//   await prune()                         → { pruned, warning }
//   useInvestigation(fn)                  → fn() answers the current investigation id (the notebook registers it)
//   subscribe(fn)                         → fn({ type: "change" | "pruned", ... })
//
// Plain ES module. No DOM.

import { versionedDocument, newId } from "./document.js";

export const KEY = "searches";
export const VERSION = 1;
export const MAX_BYTES = 500_000;
export const MAX_ENTRIES = 200;
export const SOURCES = Object.freeze(["copy", "run", "open", "insert", "history"]);
export const ORIGINS = Object.freeze(["pivot", "workflow", "discovery", "pattern", "exclusion", "runbook", "advisor", "history"]);
const MAX_TEXT = 20_000;
const MAX_SHORT = 500;

function str(v, max) {
  if (v === undefined || v === null) return undefined;
  const s = typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
  const t = s.trim();
  if (!t) return undefined;
  return t.length > max ? t.slice(0, max) : t;
}

function normPlatform(p) {
  const s = String(p == null ? "" : p).toLowerCase();
  if (s === "splunk" || s === "spl") return "splunk";
  if (s === "sentinel" || s === "kql") return "sentinel";
  return "splunk";
}

function empty() {
  return { v: VERSION, entries: [] };
}

function sane(e) {
  if (!e || typeof e !== "object") return null;
  const text = str(e.text, MAX_TEXT);
  if (!text) return null;
  const platform = normPlatform(e.platform);
  const out = {
    id: str(e.id, 80) || newId("s"),
    at: typeof e.at === "number" && Number.isFinite(e.at) ? e.at : 0,
    platform,
    language: e.language === "kql" || e.language === "spl" ? e.language : platform === "sentinel" ? "kql" : "spl",
    text,
    source: SOURCES.includes(e.source) ? e.source : "copy",
    origin: ORIGINS.includes(e.origin) ? e.origin : "pivot",
    ran: e.ran === true,
  };
  const sid = str(e.sid, 80);
  if (sid) out.sid = sid;
  for (const k of ["container", "field", "value", "name", "investigation"]) {
    const v = str(e[k], MAX_SHORT);
    if (v) out[k] = v;
  }
  return out;
}

function adopt(raw) {
  const out = empty();
  if (!raw || typeof raw !== "object" || !Array.isArray(raw.entries)) return out;
  const seen = new Set();
  for (const e of raw.entries) {
    const s = sane(e);
    if (!s || seen.has(s.id)) continue;
    seen.add(s.id);
    out.entries.push(s);
  }
  out.entries.sort((a, b) => a.at - b.at);
  return out;
}

// Oldest out first, until the document fits.
function pruneInPlace(d, { bytes: size, budget }) {
  let n = 0;
  while (d.entries.length > 1 && size(d) > budget) {
    d.entries.shift();
    n += 1;
  }
  const pruned = n ? [{ count: n }] : [];
  const warning = n ? `The search history was over its ${Math.round(budget / 1000)} KB bound: the ${n === 1 ? "oldest entry was" : `${n} oldest entries were`} dropped.` : "";
  return { pruned, warning };
}

const D = versionedDocument({ key: KEY, version: VERSION, empty, adopt, prune: pruneInPlace, budget: MAX_BYTES });

let investigationOf = () => null;

// The notebook registers how the current investigation id is read, so a
// write stamps it without this module importing the notebook.
export function useInvestigation(fn) {
  investigationOf = typeof fn === "function" ? fn : () => null;
}

export function load(opts) {
  return D.load(opts);
}

export function bytes(d) {
  return D.bytes(d);
}

export function prune() {
  return D.prune();
}

export function count() {
  return D.get().entries.length;
}

// Newest first; with an investigation, its entries come before the rest.
export function list({ investigation = null } = {}) {
  const all = D.get().entries.slice().reverse();
  if (!investigation) return all;
  return [...all.filter((e) => e.investigation === investigation), ...all.filter((e) => e.investigation !== investigation)];
}

export function forInvestigation(id) {
  if (!id) return [];
  return D.get().entries.filter((e) => e.investigation === id);
}

export async function record(input = {}) {
  const text = str(input.text, MAX_TEXT);
  if (!text) return null;
  let investigation = str(input.investigation, MAX_SHORT);
  if (!investigation) {
    try {
      investigation = str(await investigationOf(), MAX_SHORT);
    } catch {
      investigation = undefined;
    }
  }
  const at = typeof input.at === "number" && Number.isFinite(input.at) ? input.at : Date.now();
  const entry = sane({ ...input, id: undefined, text, at, investigation });
  return D.update(
    (d) => {
      const newest = d.entries[d.entries.length - 1];
      if (newest && newest.text === entry.text) {
        newest.at = at;
        newest.source = entry.source;
        newest.origin = entry.origin;
        newest.ran = newest.ran || entry.ran;
        if (entry.sid) newest.sid = entry.sid;
        for (const k of ["container", "field", "value", "name", "investigation"]) if (entry[k] && !newest[k]) newest[k] = entry[k];
        return newest;
      }
      d.entries.push(entry);
      while (d.entries.length > MAX_ENTRIES) d.entries.shift();
      return entry;
    },
    { at },
  );
}

export function remove(id) {
  return D.update((d) => {
    const i = d.entries.findIndex((e) => e.id === id);
    if (i < 0) return D.unchanged(null);
    return d.entries.splice(i, 1)[0];
  });
}

export function clear() {
  return D.update((d) => {
    const n = d.entries.length;
    if (!n) return D.unchanged(0);
    d.entries = [];
    return n;
  });
}

export function subscribe(fn) {
  return D.subscribe(fn);
}

export default { KEY, VERSION, MAX_BYTES, MAX_ENTRIES, SOURCES, ORIGINS, load, bytes, prune, count, list, forInvestigation, record, remove, clear, subscribe, useInvestigation };
