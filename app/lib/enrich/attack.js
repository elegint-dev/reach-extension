// MITRE ATT&CK Enterprise techniques as a bundled enrichment source
// (app/lib/enrich.js): the ATT&CK Terms of Use grant a "non-exclusive,
// royalty-free license to use ATT&CK for research, development, and
// commercial purposes" provided MITRE's copyright and licence travel
// with any copy, which docs/COMPLIANCE.md carries. Shipped inside the
// package, projected by tools/dev/fetch-attack.mjs into
// app/data/enrich/attack.json. Never touches the network: fetch() here
// reads the extension's own bundled file, lazily, once per session.
//
//   classify(value)   { kind: "technique", id } | null   (app/lib/shapes.js detectTechnique)
//   linkFor(value)     { href, label } | null   the technique's own attack.mitre.org page
//   load()             the parsed index { generated_at, attackVersion, count, byId } | null
//   summarize(entry)   [line, ...] for one matched technique
//   call(value)        { status, lines, link } (the enrich.js registry contract)
//   reset()            clears the cached index (tests only)
//   source             the ready-to-register object

import { detectTechnique } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/attack.json`, import.meta.url).href;

let cachePromise = null;

export function classify(value) {
  const d = detectTechnique(value);
  return d ? { kind: "technique", id: d.detail } : null;
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  return { href: `https://attack.mitre.org/techniques/${c.id.split(".").join("/")}/`, label: "Open on MITRE ATT&CK ↗" };
}

export async function load() {
  if (!cachePromise) {
    cachePromise = (async () => {
      let res;
      try {
        res = await fetch(DATA_URL);
      } catch {
        return null;
      }
      if (!res || !res.ok) return null;
      let doc;
      try {
        doc = await res.json();
      } catch {
        return null;
      }
      if (!doc || !Array.isArray(doc.techniques)) return null;
      const byId = new Map(doc.techniques.map((t) => [String(t.id || "").toUpperCase(), t]));
      return { generated_at: doc.generated_at || null, attackVersion: doc.attackVersion || null, count: doc.count || doc.techniques.length, byId };
    })();
  }
  return cachePromise;
}

export function reset() {
  cachePromise = null;
}

export function summarize(entry) {
  if (!entry) return [];
  const tactics = (entry.tactics || []).join(", ") || "no tactic listed";
  const lines = [`${entry.name} (${tactics})`];
  if (entry.summary) lines.push(entry.summary);
  return lines;
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const link = linkFor(value);
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled ATT&CK technique index."], link };
  const entry = idx.byId.get(c.id);
  if (!entry) {
    const ver = idx.attackVersion ? ` (bundled index is ATT&CK ${idx.attackVersion})` : "";
    return { status: "empty", lines: [`${c.id} is not in the bundled ATT&CK Enterprise index${ver}.`], link };
  }
  return { status: "ok", lines: summarize(entry), link };
}

export const source = { id: "attack", label: "MITRE ATT&CK", kinds: ["technique"], mode: "bundle", recipients: [], call, linkFor };

export default { classify, linkFor, load, reset, summarize, call, source };
