// CISA's Known Exploited Vulnerabilities catalogue as a bundled enrichment
// source (app/lib/enrich.js): a CC0-1.0 dataset shipped inside the
// package, projected by tools/dev/fetch-kev.mjs into
// app/data/enrich/kev.json. Never touches the network: fetch() here reads
// the extension's own bundled file, lazily, once per popup session,
// cached after that.
//
//   classify(value)   { kind: "cve", id } | null                (app/lib/shapes.js detectCve)
//   linkFor(value)    { href, label } | null   the CISA catalogue search, no lookup needed
//   load()            the parsed catalogue { generated_at, catalogVersion, count, byId } | null
//   summarize(entry)  [line, ...] for one matched entry
//   call(value)       { status, lines, link } (the enrich.js registry contract)
//   reset()           clears the cached catalogue (tests only)
//   source            the ready-to-register object

import { detectCve } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/kev.json`, import.meta.url).href;

let cachePromise = null;

export function classify(value) {
  const d = detectCve(value);
  return d ? { kind: "cve", id: d.detail } : null;
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  return { href: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(c.id)}`, label: "Open on CISA ↗" };
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
      if (!doc || !Array.isArray(doc.vulnerabilities)) return null;
      const byId = new Map(doc.vulnerabilities.map((v) => [String(v.cveID || "").toUpperCase(), v]));
      return { generated_at: doc.generated_at || null, catalogVersion: doc.catalogVersion || null, count: doc.count || doc.vulnerabilities.length, byId };
    })();
  }
  return cachePromise;
}

export function reset() {
  cachePromise = null;
}

export function summarize(entry) {
  if (!entry) return [];
  const ransomware = String(entry.knownRansomwareCampaignUse || "").toLowerCase() === "unknown" || !entry.knownRansomwareCampaignUse ? "unknown" : "known";
  const vendor = [entry.vendorProject, entry.product].filter(Boolean).join(" ");
  const headline = `In CISA KEV since ${entry.dateAdded || "an unknown date"}, due ${entry.dueDate || "no stated date"}, ransomware use: ${ransomware}${vendor ? `, ${vendor}` : ""}`;
  const lines = [headline];
  if (entry.shortDescription) lines.push(entry.shortDescription);
  return lines;
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const link = linkFor(value);
  const cat = await load();
  if (!cat) return { status: "error", lines: ["Could not read the bundled CISA KEV catalogue."], link };
  const entry = cat.byId.get(c.id);
  if (!entry) {
    const asOf = cat.generated_at ? ` (catalogue as of ${cat.generated_at.slice(0, 10)})` : "";
    return { status: "empty", lines: [`${c.id} is not in the CISA Known Exploited Vulnerabilities catalogue${asOf}.`], link };
  }
  return { status: "ok", lines: summarize(entry), link };
}

export const source = { id: "kev", label: "CISA KEV", kinds: ["cve"], mode: "bundle", recipients: [], call, linkFor };

export default { classify, linkFor, load, reset, summarize, call, source };
