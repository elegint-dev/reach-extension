// The LOLRMM project's remote-monitoring-and-management tool catalogue
// as a bundled enrichment source (app/lib/enrich.js): Apache-2.0
// (https://github.com/magicsword-io/LOLRMM/blob/main/LICENSE), shipped
// inside the package, projected by tools/dev/fetch-lolrmm.mjs into
// app/data/enrich/lolrmm.json. Never touches the network: fetch() here
// reads the extension's own bundled file, lazily, once per popup
// session, cached after that.
//
// Answers two kinds of click: a binary or installer name
// (app/lib/shapes.js detectProcessName, the "binary_name" kind
// app/lib/enrich.js derives for anything not a .sys driver or a .dll)
// matched against each tool's installation-path glob, and a domain
// (the same "domain" kind VirusTotal answers) matched against each
// tool's known network domains.
//
//   classify(value, { fieldName })   { kind: "binary_name"|"domain", id } | null
//   linkFor(value, ctx)              { href, label } | null   the tool's own lolrmm.io page
//   load()                           the parsed index { generated_at, count, entries } | null
//   summarize(entry)                 [line, ...] for one matched tool
//   call(value, ctx)                 { status, lines, link } (the enrich.js registry contract)
//   reset()                          clears the cached index (tests only)
//   source                           the ready-to-register object

import { detectProcessName } from "../shapes.js";
import { classify as vtClassify } from "../virustotal.js";

const DATA_URL = new URL(`../../data/enrich/lolrmm.json`, import.meta.url).href;

let cachePromise = null;

export function classify(value, { fieldName = "" } = {}) {
  const proc = detectProcessName(value);
  if (proc) {
    // A file-name shape wins over a domain shape: "iobios64.sys" parses
    // as a hostname-looking string (a label plus a three-letter "tld") to
    // app/lib/virustotal.js classify(), which knows nothing about LOL*
    // extensions, so a process-name match here has to end the check.
    return /\.(sys|dll)$/i.test(proc.detail) ? null : { kind: "binary_name", id: proc.detail.toLowerCase() };
  }
  const vt = vtClassify(value, { fieldName });
  if (vt && vt.kind === "domain") return { kind: "domain", id: vt.id };
  return null;
}

// null always: the tool's page is keyed by lolrmm.io's own slug, which
// only the matched entry (from call()) carries.
export function linkFor() {
  return null;
}

// installation-path globs (InstallationPaths) are simple wildcard forms
// (`zerotier*.exe`, `*\TightVNC\*`): turned into a regex once per glob,
// matched against the clicked basename or full value either way.
function globToRe(glob) {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${esc}$`, "i");
}

// A glob's basename is only usable for a bare basename-to-basename match
// (id carries no path: detectProcessName already stripped one) when it
// keeps at least one literal character; `*\TightVNC\*`'s basename is `*`
// alone, which globToRe turns into /^.*$/ and would otherwise match every
// binary_name or domain value (the TigerVNC-on-anything bug). The whole
// glob still applies, but only against a path-shaped clicked value, so a
// directory-only pattern like that one still answers a real install path.
function hasLiteralChar(s) {
  return /[A-Za-z0-9.-]/.test(s);
}

function nameMatches(entry, id, rawValue) {
  if (id === entry.name.toLowerCase()) return true;
  const raw = typeof rawValue === "string" ? rawValue.trim() : "";
  const pathShaped = /[\\/]/.test(raw);
  return (entry.installationPaths || []).some((glob) => {
    const base = glob.split(/[\\/]/).pop() || glob;
    if (hasLiteralChar(base) && globToRe(base).test(id)) return true;
    if (pathShaped && globToRe(glob).test(raw)) return true;
    return false;
  });
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
      return { generated_at: doc.generated_at || null, count: doc.count || doc.entries.length, entries: doc.entries };
    })();
  }
  return cachePromise;
}

export function reset() {
  cachePromise = null;
}

export function summarize(entry, { via = "" } = {}) {
  if (!entry) return [];
  const cat = entry.category ? ` (${entry.category})` : "";
  return [`Listed in LOLRMM as ${entry.name}${cat}, matched by ${via}.`];
}

function findByBinary(entries, id, rawValue) {
  return entries.find((e) => nameMatches(e, id, rawValue)) || null;
}

function findByDomain(entries, id) {
  return (
    entries.find((e) => (e.domains || []).some((d) => d === id || (d.startsWith("*.") && (id === d.slice(2) || id.endsWith(`.${d.slice(2)}`))))) || null
  );
}

export async function call(value, ctx = {}) {
  const c = classify(value, ctx);
  if (!c) return { status: "refused", lines: [] };
  const idx = await load();
  if (!idx) return { status: "error", lines: ["Could not read the bundled LOLRMM catalogue."] };
  const entry = c.kind === "binary_name" ? findByBinary(idx.entries, c.id, String(value ?? "")) : findByDomain(idx.entries, c.id);
  if (!entry) return { status: "empty", lines: [`${c.id} is not in the bundled LOLRMM index.`] };
  const link = { href: `https://lolrmm.io/tools/${entry.slug}`, label: "Open on LOLRMM ↗" };
  return { status: "ok", lines: summarize(entry, { via: c.kind === "binary_name" ? "the binary name" : "a known RMM domain" }), link };
}

export const source = { id: "lolrmm", label: "LOLRMM", kinds: ["binary_name", "domain"], mode: "bundle", recipients: [], call, linkFor: () => null };

export default { classify, linkFor, load, reset, summarize, call, source };
