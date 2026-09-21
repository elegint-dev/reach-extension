// Splunk ESCU's detection index as a bundled enrichment source
// (app/lib/enrich.js), keyed by ATT&CK technique. Apache-2.0
// (https://github.com/splunk/security_content/blob/develop/LICENSE),
// carried in docs/COMPLIANCE.md. Shipped inside the package, projected
// by tools/dev/fetch-escu.mjs into app/data/enrich/escu.json. Never
// touches the network: fetch() here reads the extension's own bundled
// file, lazily, once per session.
//
// A technique's containers() names the sourcetypes Reach's own dev
// seeding already has real ESCU-relevant events for (from
// tools/dev/attack-data.json, baked into the bundle at build time), so a
// hit can point at a container the catalogue already knows.
//
//   classify(value)     { kind: "technique", id } | null
//   linkFor(value)       { href, label } | null   the first matched detection's own page
//   load()                the parsed index { generated_at, ref, count, byTechnique, containers } | null
//   byTechnique(index, id) [detection, ...] tagging this exact technique id
//   containersFor(index, id) [container, ...] sourcetypes the catalogue already seeds for it
//   summarize(detections, id, containers) [line, ...] a headline count, matches, then containers
//   call(value)           { status, lines, link } (the enrich.js registry contract)
//   reset()                clears the cached index (tests only)
//   source                 the ready-to-register object

import { detectTechnique } from "../shapes.js";

const DATA_URL = new URL(`../../data/enrich/escu.json`, import.meta.url).href;
const SHOWN = 5;

let cachePromise = null;

export function classify(value) {
  const d = detectTechnique(value);
  return d ? { kind: "technique", id: d.detail } : null;
}

export function linkFor(value) {
  return null; // set per-call from the first matched detection; there is no technique-indexed research.splunk.com page
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
      if (!doc || !Array.isArray(doc.detections)) return null;
      const byTechnique = new Map();
      for (const d of doc.detections) {
        for (const t of d.techniques || []) {
          const key = String(t).toUpperCase();
          if (!byTechnique.has(key)) byTechnique.set(key, []);
          byTechnique.get(key).push(d);
        }
      }
      return { generated_at: doc.generated_at || null, ref: doc.ref || null, count: doc.count || doc.detections.length, byTechnique, containers: doc.containers || {} };
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

export function containersFor(index, id) {
  if (!index) return [];
  const key = String(id || "").toUpperCase();
  return index.containers[key] || [];
}

export function summarize(detections, id, containers) {
  if (!detections || !detections.length) return [`No ESCU detections tag ${id}.`];
  const lines = [`${detections.length} ESCU detection${detections.length === 1 ? "" : "s"} tag ${id}.`];
  for (const d of detections.slice(0, SHOWN)) {
    const ds = (d.dataSources || []).slice(0, 2).join(", ");
    lines.push(`${d.name}${ds ? ` (${ds})` : ""}`);
  }
  if (detections.length > SHOWN) lines.push(`${detections.length - SHOWN} more not shown.`);
  if (containers && containers.length) lines.push(`Already seeded on: ${containers.join(", ")}.`);
  return lines;
}

export async function call(value) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled ESCU detection index."], link: null };
  const detections = byTechnique(idx, c.id);
  const containers = containersFor(idx, c.id);
  const link = detections.length ? { href: detections[0].url, label: `Open ${detections[0].name} on research.splunk.com ↗` } : null;
  if (!detections.length) return { status: "empty", lines: summarize(detections, c.id, containers), link };
  return { status: "ok", lines: summarize(detections, c.id, containers), link };
}

export const source = { id: "escu", label: "Splunk ESCU", kinds: ["technique"], mode: "bundle", recipients: [], call, linkFor };

export default { classify, linkFor, load, reset, byTechnique, containersFor, summarize, call, source };
