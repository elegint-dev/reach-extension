// The LOLDrivers project's vulnerable and malicious Windows driver
// catalogue as a bundled enrichment source (app/lib/enrich.js):
// Apache-2.0 (https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE),
// shipped inside the package, projected by tools/dev/fetch-loldrivers.mjs
// into app/data/enrich/loldrivers.json. Never touches the network:
// fetch() here reads the extension's own bundled file, lazily, once per
// popup session, cached after that.
//
// Answers two kinds of click: a SHA-256 hash (the "sha256" kind
// app/lib/enrich.js derives for a 64-hex digest alone, never the wider
// "hash" kind VirusTotal and CIRCL answer: the catalogue indexes no MD5 or
// SHA-1, so an MD5-length id must not reach this row) and a driver file
// name or path ending in .sys (app/lib/shapes.js detectProcessName, the
// "driver_name" kind).
//
//   classify(value, ctx)   { kind: "sha256"|"driver_name", id } | null
//   linkFor(value, ctx)    { href, label } | null   the driver's own loldrivers.io page
//   load()                 the parsed index { generated_at, count, byHash, byName } | null
//   summarize(entry)       [line, ...] for one matched driver
//   call(value, ctx)       { status, lines, link } (the enrich.js registry contract)
//   reset()                clears the cached index (tests only)
//   source                 the ready-to-register object

import { detectProcessName } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/loldrivers.json`, import.meta.url).href;
const HASH_RE = /^[0-9a-f]{64}$/i;

let cachePromise = null;

export function classify(value) {
  const s = String(value ?? "").trim();
  if (HASH_RE.test(s)) return { kind: "sha256", id: s.toLowerCase() };
  const proc = detectProcessName(value);
  if (proc && /\.sys$/i.test(proc.detail)) return { kind: "driver_name", id: proc.detail.toLowerCase() };
  return null;
}

// null always: the driver's page is keyed by loldrivers.io's own uuid,
// which only the matched entry (from call()) carries.
export function linkFor() {
  return null;
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
      if (!doc || !Array.isArray(doc.entries)) return null;
      const byHash = new Map();
      const byName = new Map();
      for (const e of doc.entries) {
        for (const h of e.sha256 || []) byHash.set(h, e);
        for (const n of e.names || []) {
          const key = n.toLowerCase();
          if (!byName.has(key)) byName.set(key, []);
          byName.get(key).push(e);
        }
      }
      return { generated_at: doc.generated_at || null, count: doc.count || doc.entries.length, byHash, byName };
    })();
  }
  return cachePromise;
}

export function reset() {
  cachePromise = null;
}

export function summarize(entry, { via = "" } = {}) {
  if (!entry) return [];
  const name = (entry.names || [])[0] || "an unnamed driver";
  return [`In LOLDrivers as a ${entry.category} driver: ${name}${via ? ` (matched by ${via})` : ""}`];
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled LOLDrivers catalogue."] };
  let entry = null;
  let via = "";
  if (c.kind === "sha256") {
    entry = idx.byHash.get(c.id) || null;
    via = "SHA-256";
  } else {
    const hits = idx.byName.get(c.id) || [];
    entry = hits[0] || null;
    via = "name";
  }
  if (!entry) return { status: "empty", lines: [`${c.id} is not in the bundled LOLDrivers catalogue.`] };
  const link = { href: `https://www.loldrivers.io/drivers/${entry.id}/`, label: "Open on LOLDrivers ↗" };
  return { status: "ok", lines: summarize(entry, { via }), link };
}

export const source = { id: "loldrivers", label: "LOLDrivers", kinds: ["sha256", "driver_name"], mode: "bundle", recipients: [], call, linkFor: () => null };

export default { classify, linkFor, load, reset, summarize, call, source };
