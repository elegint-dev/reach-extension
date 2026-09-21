// CIRCL's hashlookup as a fetch-mode enrichment source (app/lib/enrich.js):
// a keyless, no-account REST lookup of MD5/SHA-1/SHA-256 against NIST
// NSRL (all RDS sets) plus indexed Windows and Linux system files
// (https://www.circl.lu/services/hashlookup/, read 2026-09-18: "free and
// served as a best-effort basis"). Off by default (docs/PRIVACY.md and
// docs/COMPLIANCE.md name hashlookup.circl.lu as a recipient only when a
// user turns this on in Settings): the same explicit-click policy as
// VirusTotal governs the fetch itself, gated a step earlier by the
// Settings toggle app/lib/enrich.js's gate() reads through enabledIds.
// Registered ahead of VirusTotal (app/lib/enrich.js's self-registration
// order) so a known-good hit is seen first and can save a VirusTotal
// lookup.
//
//   classify(value, { fieldName })   { kind: "hash", id } | null (the same
//                                     rule as app/lib/virustotal.js classify(),
//                                     so both sources offer the same hashes)
//   linkFor(value, ctx)              null (CIRCL has no per-hash public page)
//   summarize(json)                  [line, ...] for one hashlookup hit
//   call(value, ctx)                 { status, lines, link } (the enrich.js registry
//                                     contract; ctx.ask is the background relay)
//   source                           the ready-to-register object
//   relay                            the background worker's descriptor (background.js
//                                    lookup()): the toggle key, host pattern, URL by digest length

import { classify as vtClassify } from "../virustotal.js";
import { KEYS } from "../storage-keys.js";

const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;

export const relay = Object.freeze({
  id: "circl",
  messages: { status: "reach:enrich:status", lookup: "reach:enrich:lookup" },
  bySource: true,
  keys: [KEYS.circlEnabled],
  config: (got) => ({ enabled: got[KEYS.circlEnabled] === true }),
  hosts: () => ["https://hashlookup.circl.lu/*"],
  configured: (cfg) => cfg.enabled,
  status: (cfg, permitted) => ({ ok: true, enabled: cfg.enabled, permitted }),
  accepts: (kind, id) => kind === "hash" && HASH_RE.test(id),
  method: "GET",
  url: (kind, id) => `https://hashlookup.circl.lu/lookup/${id.length === 32 ? "md5" : id.length === 40 ? "sha1" : "sha256"}/${id}`,
  headers: () => ({ accept: "application/json" }),
  answer: ({ ok, status, body }) => ({ ok, status, data: body }),
  failure: (cfg, why) => ({ ok: false, status: 0, error: `Could not reach circl (${why}).` }),
  errors: {
    unconfigured: "circl is off: turn it on in Reach's settings.",
    unpermitted: "Reach has no permission to contact this source yet. Turn it on again in Reach's settings to grant it.",
    refused: "Lookup refused: not a shape this source answers.",
  },
});

const DB_NAMES = { nsrl_legacy: "NSRL", nsrl: "NSRL", "nsrl-modern": "NSRL" };

function niceDb(db) {
  const key = String(db || "").toLowerCase();
  return DB_NAMES[key] || db || "an indexed source";
}

export function classify(value, { fieldName = "" } = {}) {
  const vt = vtClassify(value, { fieldName });
  return vt && vt.kind === "hash" ? { kind: "hash", id: vt.id } : null;
}

export function linkFor() {
  return null;
}

export function summarize(json) {
  if (!json || typeof json !== "object") return [];
  const names = new Set([niceDb(json.db)]);
  for (const p of Array.isArray(json.parents) ? json.parents : []) {
    if (p && p.PackageName) names.add(p.PackageName);
  }
  const list = [...names];
  const headline = list.length > 1 ? `known in ${list.length} sources (${list.slice(0, 4).join(", ")}${list.length > 4 ? ", …" : ""})` : `known in ${list[0] || "an indexed source"}`;
  const lines = [`Known good, ${headline}.`];
  const fileName = json.FileName ? String(json.FileName).replace(/^\.\//, "") : "";
  if (fileName) lines.push(`File name on record: ${fileName}`);
  const product = json.ProductCode && json.ProductCode.ProductName;
  if (product) lines.push(`Product: ${product}`);
  return lines;
}

export async function call(value, ctx = {}) {
  const c = classify(value, ctx);
  if (!c) return { status: "refused", lines: [] };
  if (typeof ctx.ask !== "function") return { status: "error", lines: ["CIRCL hashlookup needs Reach's background worker, not available here."] };
  let res;
  try {
    res = await ctx.ask({ type: "reach:enrich:lookup", source: "circl", kind: c.kind, id: c.id });
  } catch (err) {
    res = { ok: false, status: 0, error: err && err.message ? err.message : String(err) };
  }
  if (!res || (!res.ok && res.status !== 404)) {
    return { status: "error", lines: [res && res.error ? res.error : "Could not reach CIRCL hashlookup."] };
  }
  if (res.status === 404) return { status: "empty", lines: [`${c.id} is not a known-good hash in CIRCL hashlookup.`] };
  const lines = summarize(res.data);
  if (!lines.length) return { status: "empty", lines: [`${c.id} is not a known-good hash in CIRCL hashlookup.`] };
  return { status: "ok", lines };
}

export const source = { id: "circl", label: "CIRCL hashlookup", kinds: ["hash"], mode: "fetch", recipients: ["hashlookup.circl.lu, only after you turn it on in Reach's settings"], call, linkFor };

export default { classify, linkFor, summarize, call, source, relay };
