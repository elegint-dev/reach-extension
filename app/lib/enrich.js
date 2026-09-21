// The enrichment source registry (P6): every enrichment lookup for a
// clicked value (a bundled dataset, a fetch call under the user's own key,
// a streamed lookup, or a deep link to some other tool) registers itself
// here once, keyed by the value kinds it answers. Pure: no DOM, no
// chrome.*, no fetch. A source's own call() may do those; this module only
// keeps the list, decides which sources apply to a clicked value, and
// gates the ones that can leave the browser behind explicit Settings
// enablement.
//
//   register(source)               add one source (throws on a bad shape or a repeat id)
//   list(kind)                     registered sources offering that kind, registration order
//   get(id)                        one source by id, or undefined
//   all()                          every registered source
//   reset()                        clear the registry (tests only)
//   gate(source, { enabledIds })   { allowed, why, configure }
//       bundle and deeplink sources are always allowed (nothing leaves the
//       browser, or the browser only opens a page the user asked for);
//       fetch and stream sources need source.id in enabledIds, the set of
//       sources configured and permitted right now (enabledIds() below);
//       a refusal for that reason carries configure: true, so the row can
//       point at the module's settings
//   kindsFor(value, { fieldName }) [{ kind, id }] every kind the value shape-matches,
//       whether or not a source is registered for it (ip/domain/hash via
//       app/lib/virustotal.js classify(), sha256 beside hash for a 64-hex
//       digest alone (a source that only indexes SHA-256, LOLDrivers,
//       declares sha256, so an MD5-length id never reaches it),
//       cve via app/lib/shapes.js detectCve(),
//       technique via app/lib/shapes.js detectTechnique(), driver_name/
//       dll_name/binary_name via app/lib/shapes.js detectProcessName(),
//       split by extension so a driver click never offers GTFOBins, url
//       via app/lib/shapes.js detectUrl())
//   refusalFor(value, { fieldName })  { kind, id, why } | null
//       a value shaped like an ip/domain/hash candidate but refused
//       (private, reserved, an id field): virustotal.js already knows why
//   offersFor(value, { fieldName, enabledIds, sources })  [{ source, kind, id, allowed, why, configure }]
//       one row per (matched or refused kind, registered source for that
//       kind); value-popup.js, sentinel-grid.js and app/views/value.js all
//       build enrichBlock's input this way. sources, when given, is the
//       set of source ids whose module is on (app/lib/modules.js
//       sources()): a source outside it is not offered at all, not greyed
//   enabledIds(ask)                 Promise<string[]>
//       the fetch-mode sources actually turned on right now: virustotal (a
//       pasted key), circl and epss (a plain toggle) and selfhosted (a
//       saved origin), each asked once over the caller's ask (the
//       chrome.runtime.sendMessage round trip), in parallel. value.js,
//       value-popup.js and sentinel-grid.js all pass the result straight
//       into offersFor's enabledIds, so a source lit up in Settings shows
//       the same way in every popup, on the page or in-page.
//
// A source: { id, label, kinds: [...], mode: "bundle"|"fetch"|"stream"|"deeplink",
//             recipients: [string, ...], call(value, ctx) -> Promise<{ status, lines, link? }>,
//             linkFor(value, ctx) -> { href, label } | null }  (linkFor optional: a
//             synchronous, no-network "open the page anyway" link shown before any
//             click, VirusTotal's own "Open ↗ (no API call)" generalised)
//   status: "ok" | "empty" | "refused" | "error"
//   lines:  short strings for the popup, in the order they render
//   link:   { href, label } for a deep link; bundle and fetch results may carry one too

import { classify as vtClassify, refusal as vtRefusal } from "./virustotal.js";
import { detectCve, detectTechnique, detectProcessName, detectUrl } from "./shapes.js";
import { source as attackSource } from "./enrich/attack.js";
import { source as sigmaSource } from "./enrich/sigma.js";
import { source as escuSource } from "./enrich/escu.js";
import { source as sentinelRulesSource } from "./enrich/sentinel-rules.js";
import { source as loldriversSource } from "./enrich/loldrivers.js";
import { source as lolrmmSource } from "./enrich/lolrmm.js";
import { source as lolbasSource } from "./enrich/lolbas.js";
import { source as gtfobinsSource } from "./enrich/gtfobins.js";
import { source as hijacklibsSource } from "./enrich/hijacklibs.js";
import { source as circlSource } from "./enrich/circl.js";
import { source as epssSource } from "./enrich/epss.js";
import { source as selfhostedSource } from "./enrich/selfhosted.js";

const MODES = new Set(["bundle", "fetch", "stream", "deeplink"]);
const SHA256_RE = /^[0-9a-f]{64}$/i;

let sources = [];
let byId = new Map();

export function register(source) {
  if (!source || typeof source.id !== "string" || !source.id) throw new Error("enrich.register: id is required");
  if (byId.has(source.id)) throw new Error(`enrich.register: "${source.id}" is already registered`);
  if (typeof source.label !== "string" || !source.label) throw new Error(`enrich.register(${source.id}): label is required`);
  if (!Array.isArray(source.kinds) || !source.kinds.length) throw new Error(`enrich.register(${source.id}): kinds must be a non-empty array`);
  if (!MODES.has(source.mode)) throw new Error(`enrich.register(${source.id}): mode must be one of ${[...MODES].join(", ")}`);
  if (typeof source.call !== "function") throw new Error(`enrich.register(${source.id}): call must be a function`);
  const entry = { recipients: [], linkFor: null, ...source };
  byId.set(entry.id, entry);
  sources.push(entry);
  return entry;
}

export function list(kind) {
  return sources.filter((s) => s.kinds.includes(kind));
}

export function get(id) {
  return byId.get(id);
}

export function all() {
  return sources.slice();
}

export function reset() {
  sources = [];
  byId = new Map();
}

export function gate(source, { enabledIds = [] } = {}) {
  if (source.mode === "bundle" || source.mode === "deeplink") return { allowed: true };
  const ids = enabledIds instanceof Set ? enabledIds : new Set(enabledIds || []);
  if (ids.has(source.id)) return { allowed: true };
  return { allowed: false, why: `${source.label} is not configured. Set it up in Reach's settings before anything is sent to it.`, configure: true };
}

function sourceSet(sources) {
  if (sources === undefined || sources === null) return null;
  return sources instanceof Set ? sources : new Set(sources);
}

export function kindsFor(value, { fieldName = "" } = {}) {
  const kinds = [];
  const cve = detectCve(value);
  if (cve) kinds.push({ kind: "cve", id: cve.detail });
  const technique = detectTechnique(value);
  if (technique) kinds.push({ kind: "technique", id: technique.detail });
  const proc = detectProcessName(value);
  let procKind = null;
  if (proc) {
    const ext = proc.detail.includes(".") ? proc.detail.slice(proc.detail.lastIndexOf(".") + 1).toLowerCase() : "";
    procKind = ext === "sys" ? "driver_name" : ext === "dll" ? "dll_name" : "binary_name";
  }
  const vt = vtClassify(value, { fieldName });
  // A "name.exe" or "name.dll" satisfies app/lib/virustotal.js classify()'s
  // domain shape too (a label plus a short alpha "tld"): once a LOL*
  // extension has already claimed the value as a file name, it is not
  // also offered as a hostname, so a source registered for both kinds
  // (app/lib/enrich/lolrmm.js) never grows two rows for one click.
  if (vt && !(procKind && vt.kind === "domain")) kinds.push({ kind: vt.kind, id: vt.id });
  // "hash" is any digest length VirusTotal and CIRCL answer (MD5, SHA-1,
  // SHA-256); "sha256" is the 64-hex digest alone, for a bundled source
  // that indexes nothing shorter. A 32-hex value (a GuardDuty finding id,
  // an FDR aid) is hash-shaped but never sha256.
  const s = String(value ?? "").trim();
  if (SHA256_RE.test(s)) kinds.push({ kind: "sha256", id: s.toLowerCase() });
  if (procKind) kinds.push({ kind: procKind, id: proc.detail });
  // An absolute URL: no bundled or keyless source answers this kind today,
  // only the self-hosted relay (app/lib/enrich/selfhosted.js), which can
  // forward a URL to MISP or IntelOwl the way VirusTotal cannot.
  if (s && s.length <= 2048 && detectUrl(s)) kinds.push({ kind: "url", id: s });
  return kinds;
}

export function refusalFor(value, { fieldName = "" } = {}) {
  return vtRefusal(value, { fieldName });
}

// Every fetch-mode source gated behind Settings, and the message + status
// shape background.js answers each with (background.js's virusTotal(),
// enrichLookup() and selfHosted()): not uniform (virustotal and selfhosted
// answer "configured", circl and epss answer "enabled"), so each entry
// names its own predicate rather than one shared field read.
const GATED = [
  { id: "virustotal", ask: (ask) => ask({ type: "reach:vt:status" }), on: (s) => Boolean(s && s.ok && s.configured && s.permitted) },
  { id: "circl", ask: (ask) => ask({ type: "reach:enrich:status", source: "circl" }), on: (s) => Boolean(s && s.ok && s.enabled && s.permitted) },
  { id: "epss", ask: (ask) => ask({ type: "reach:enrich:status", source: "epss" }), on: (s) => Boolean(s && s.ok && s.enabled && s.permitted) },
  { id: "selfhosted", ask: (ask) => ask({ type: "reach:selfhosted:status" }), on: (s) => Boolean(s && s.ok && s.configured && s.permitted) },
];

export async function enabledIds(ask) {
  const ids = await Promise.all(GATED.map((g) => g.ask(ask).then((s) => (g.on(s) ? g.id : null))));
  return ids.filter(Boolean);
}

export function offersFor(value, { fieldName = "", enabledIds = [], sources = null } = {}) {
  const offers = [];
  const allowedSources = sourceSet(sources);
  const mounted = (source) => !allowedSources || allowedSources.has(source.id);
  // Registration order across every matched kind, not kind by kind: a
  // value that matches two kinds (a SHA-256 is both hash and sha256)
  // still lists its sources the way they registered.
  const registered = all();
  const matched = [];
  for (const { kind, id } of kindsFor(value, { fieldName })) {
    for (const source of list(kind)) {
      if (!mounted(source)) continue;
      matched.push({ source, kind, id, order: registered.indexOf(source) });
    }
  }
  matched.sort((a, b) => a.order - b.order);
  for (const { source, kind, id } of matched) {
    const g = gate(source, { enabledIds });
    offers.push({ source, kind, id, allowed: g.allowed, why: g.why, ...(g.configure ? { configure: true } : {}) });
  }
  const refused = refusalFor(value, { fieldName });
  if (refused) {
    for (const source of list(refused.kind)) {
      if (!mounted(source)) continue;
      offers.push({ source, kind: refused.kind, id: refused.id, allowed: false, why: `Not sent: ${refused.why}.` });
    }
  }
  return offers;
}

// Every bundle and deep-link source registers itself here rather than at
// each popup's call site (value.js, value-popup.js and sentinel-grid.js
// each only name kev and virustotal, by hand): every caller that imports
// this module gets ATT&CK, Sigma, ESCU, the Sentinel rule index, the
// LOL* living-off-the-land sources, CIRCL hashlookup and EPSS without
// those three files changing. Guarded the same way value.js guards its
// own registration: a second import of this module in the same realm,
// or a hot reload, must not throw on a repeat id.
//
// CIRCL is listed before loldrivers and virustotal are registered
// (virustotal is registered later, by hand, in each popup file): list()
// returns sources in registration order, so a hash offer always shows
// CIRCL first, ahead of VirusTotal, the way a free known-good check
// should sit ahead of a quota-spending one.
for (const s of [attackSource, sigmaSource, escuSource, sentinelRulesSource, circlSource, epssSource, loldriversSource, lolrmmSource, lolbasSource, gtfobinsSource, hijacklibsSource, selfhostedSource]) {
  try {
    register(s);
  } catch {
    /* already registered */
  }
}

export default { register, list, get, all, reset, gate, kindsFor, refusalFor, offersFor, enabledIds };
