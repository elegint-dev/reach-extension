// Microsoft Sentinel's analytic-rule index (Azure/Azure-Sentinel) as a
// bundled enrichment source (app/lib/enrich.js), keyed by ATT&CK
// technique. MIT
// (https://github.com/Azure/Azure-Sentinel/blob/master/LICENSE), carried
// in docs/COMPLIANCE.md. Shipped inside the package, projected by
// tools/dev/fetch-sentinel-rules.mjs into
// app/data/enrich/sentinel-rules.json. Never touches the network:
// fetch() here reads the extension's own bundled file, lazily, once per
// session. The bundle is built from ATT&CK v19.2's technique ids; the
// upstream rules were tagged against whatever ATT&CK version Microsoft
// Sentinel currently maps to (Microsoft Learn states v18), so a rule
// tagging a technique id retired or renamed since v18 will not surface
// here even though the tag still exists in the rule file.
//
//   classify(value)     { kind: "technique", id } | null
//   linkFor(value)       { href, label } | null   set per-call from the first matched rule
//   load()                the parsed index { generated_at, ref, count, byTechnique } | null
//   byTechnique(index, id) [rule, ...] tagging this exact technique id
//   summarize(rules, id)  [line, ...] a headline count plus a capped list of matches
//   call(value)           { status, lines, link } (the enrich.js registry contract)
//   reset()                clears the cached index (tests only)
//   source                 the ready-to-register object

import { detectTechnique } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/sentinel-rules.json`, import.meta.url).href;
const SHOWN = 5;

let cachePromise = null;

export function classify(value) {
  const d = detectTechnique(value);
  return d ? { kind: "technique", id: d.detail } : null;
}

export function linkFor(value) {
  return null; // set per-call from the first matched rule; no verified per-technique portal deep link
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
      if (!doc || !Array.isArray(doc.rules)) return null;
      const byTechnique = new Map();
      for (const r of doc.rules) {
        for (const t of r.techniques || []) {
          const key = String(t).toUpperCase();
          if (!byTechnique.has(key)) byTechnique.set(key, []);
          byTechnique.get(key).push(r);
        }
      }
      return { generated_at: doc.generated_at || null, ref: doc.ref || null, count: doc.count || doc.rules.length, byTechnique };
    })();
  }
  return cachePromise;
}

export function reset() {
  cachePromise = null;
}

export function byTechnique(index, id) {
  if (!index) return [];
  const key = String(id || "").toUpperCase();
  return index.byTechnique.get(key) || [];
}

export function summarize(rules, id) {
  if (!rules || !rules.length) return [`No Sentinel analytic rules tag ${id}.`];
  const lines = [`${rules.length} Sentinel analytic rule${rules.length === 1 ? "" : "s"} tag ${id}.`];
  for (const r of rules.slice(0, SHOWN)) {
    const on = [r.connector, r.table].filter(Boolean).join(" / ");
    lines.push(`${r.name}${on ? ` (${on})` : ""}`);
  }
  if (rules.length > SHOWN) lines.push(`${rules.length - SHOWN} more not shown.`);
  return lines;
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled Sentinel analytic-rule index."], link: null };
  const rules = byTechnique(idx, c.id);
  const link = rules.length ? { href: rules[0].url, label: `Open ${rules[0].name} on GitHub ↗` } : null;
  if (!rules.length) return { status: "empty", lines: summarize(rules, c.id), link };
  return { status: "ok", lines: summarize(rules, c.id), link };
}

export const source = { id: "sentinel-rules", label: "Sentinel analytic rules", kinds: ["technique"], mode: "bundle", recipients: [], call, linkFor };

export default { classify, linkFor, load, reset, byTechnique, summarize, call, source };
