// SigmaHQ's rule index as a bundled enrichment source (app/lib/enrich.js),
// keyed by ATT&CK technique: a clicked technique id offers the Sigma
// rules that tag it, not a lookup by rule id. Detection Rule License 1.1
// (https://github.com/SigmaHQ/Detection-Rule-License) allows use,
// modification, distribution, sale and sublicensing if author
// attribution, a link and the licence designation travel with the rule;
// summarize() shows the author line on every match to satisfy "messages
// from Rule matches must retain author identification." Shipped inside
// the package, projected by tools/dev/fetch-sigma.mjs into
// app/data/enrich/sigma.json. Never touches the network: fetch() here
// reads the extension's own bundled file, lazily, once per session.
//
//   classify(value)     { kind: "technique", id } | null
//   linkFor(value)       { href, label } | null   detection.fyi's tag page for the technique
//   load()                the parsed index { generated_at, release, count, byTechnique } | null
//   byTechnique(index, id) [rule, ...] matching this exact technique id (no roll-up:
//       Sigma authors tag both a parent and a sub-technique when a rule fires on
//       either, so an exact match on the clicked id already carries parent clicks)
//   summarize(rules, id)  [line, ...] a headline count plus a capped list of matches
//   call(value)           { status, lines, link } (the enrich.js registry contract)
//   reset()                clears the cached index (tests only)
//   source                 the ready-to-register object

import { detectTechnique } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/sigma.json`, import.meta.url).href;
const SHOWN = 5;

let cachePromise = null;

export function classify(value) {
  const d = detectTechnique(value);
  return d ? { kind: "technique", id: d.detail } : null;
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  return { href: `https://detection.fyi/tags/attack.${c.id.toLowerCase()}/`, label: "Browse on detection.fyi ↗" };
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
      for (const rule of doc.rules) {
        for (const t of rule.techniques || []) {
          const key = String(t).toUpperCase();
          if (!byTechnique.has(key)) byTechnique.set(key, []);
          byTechnique.get(key).push(rule);
        }
      }
      return { generated_at: doc.generated_at || null, release: doc.release || null, count: doc.count || doc.rules.length, byTechnique };
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
  if (!rules || !rules.length) return [`No Sigma rules tag ${id}.`];
  const lines = [`${rules.length} Sigma rule${rules.length === 1 ? "" : "s"} tag ${id}.`];
  for (const rule of rules.slice(0, SHOWN)) {
    const bits = [rule.level, rule.product].filter(Boolean).join(", ");
    lines.push(`${rule.title}${bits ? ` (${bits})` : ""}, by ${rule.author || "an unattributed author"}`);
  }
  if (rules.length > SHOWN) lines.push(`${rules.length - SHOWN} more not shown.`);
  return lines;
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const link = linkFor(value);
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled Sigma rule index."], link };
  const rules = byTechnique(idx, c.id);
  if (!rules.length) return { status: "empty", lines: summarize(rules, c.id), link };
  return { status: "ok", lines: summarize(rules, c.id), link };
}

export const source = { id: "sigma", label: "Sigma rules", kinds: ["technique"], mode: "bundle", recipients: [], call, linkFor };

export default { classify, linkFor, load, reset, byTechnique, summarize, call, source };
