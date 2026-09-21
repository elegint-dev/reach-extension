// app/lib/virustotal.js migrated into the enrich.js registry as the one
// fetch-mode source: the same classify()/refusal()/summarize()/
// describeError(), the same background-worker fetch (background.js
// reach:vt:lookup, the user's own key), the same explicit-click-only rule.
// This module only reshapes that into the registry's { status, lines,
// link } contract, and names the relay the worker fetches through.
//
//   relay   the background worker's descriptor (background.js lookup()):
//           the key it reads, the host pattern, the v3 URL, the x-apikey
//           header, the answer shape, and the worker-side cache

import * as virustotal from "../virustotal.js";
import { KEYS } from "../storage-keys.js";

// Reports are cached in the worker for a few minutes: re-opening the same
// popup must not spend another unit of a 4/minute, 500/day quota. A 404
// is cached too (a fact about VirusTotal a second click will not change);
// a quota, auth, permission or network failure never is.
export const relay = Object.freeze({
  id: "virustotal",
  messages: { status: "reach:vt:status", lookup: "reach:vt:lookup" },
  keys: [KEYS.vtApiKey],
  config: (got) => ({ key: typeof got[KEYS.vtApiKey] === "string" ? got[KEYS.vtApiKey].trim() : "" }),
  hosts: () => [virustotal.HOST_PATTERN],
  configured: (cfg) => Boolean(cfg.key),
  status: (cfg, permitted) => ({ ok: true, configured: Boolean(cfg.key), permitted }),
  // Only the three shapes classify() emits, re-checked in the worker so a
  // forged message cannot turn the relay into a proxy for the key.
  accepts: (kind, id) => ["ip", "domain", "hash"].includes(kind) && /^[a-z0-9.:-]{1,253}$/i.test(id),
  method: "GET",
  url: (kind, id) => `${virustotal.API_BASE}${virustotal.pathFor(kind, id)}`,
  headers: (cfg) => ({ "x-apikey": cfg.key, accept: "application/json" }),
  answer: ({ ok, status, body }) => (ok ? { ok: true, status, data: body } : { ok: false, status, body }),
  failure: (cfg, why) => ({ ok: false, status: 0, error: `Could not reach VirusTotal (${why}).` }),
  errors: {
    unconfigured: "VirusTotal is not set up: add your own API key in Reach's settings.",
    unpermitted: "Reach has no permission to contact virustotal.com yet. Save the key again in Reach's settings to grant it.",
    refused: "VirusTotal lookup refused: not an IP, domain or hash.",
  },
  cacheTtlMs: 10 * 60 * 1000,
  cacheable: (res) => res.ok || res.status === 404,
});

export function classify(value, ctx = {}) {
  return virustotal.classify(value, { fieldName: ctx.fieldName });
}

export function linkFor(value, ctx = {}) {
  const vt = classify(value, ctx);
  return vt ? { href: virustotal.guiUrlFor(vt.kind, vt.id), label: "Open ↗ (no API call)" } : null;
}

export async function call(value, ctx = {}) {
  const vt = classify(value, ctx);
  if (!vt) return { status: "refused", lines: [] };
  const link = { href: virustotal.guiUrlFor(vt.kind, vt.id), label: "Open ↗ (no API call)" };
  if (typeof ctx.ask !== "function") return { status: "error", lines: ["VirusTotal needs Reach's background worker, not available here."], link };
  let res;
  try {
    res = await ctx.ask({ type: "reach:vt:lookup", kind: vt.kind, id: vt.id });
  } catch (err) {
    res = { ok: false, status: 0, error: err && err.message ? err.message : String(err) };
  }
  if (!res || !res.ok) {
    const text = res && res.error ? res.error : virustotal.describeError(res ? res.status : 0, res && res.body);
    return { status: res && res.status === 404 ? "empty" : "error", lines: [text], link };
  }
  const s = virustotal.summarize(vt.kind, res.data);
  if (!s) return { status: "empty", lines: ["VirusTotal answered, but the report carried no analysis."], link };
  const headline = s.verdict === "unknown" ? "No vendor verdicts yet" : `${s.stats.malicious} of ${s.stats.total} vendors flag it as malicious${s.stats.suspicious ? `, ${s.stats.suspicious} suspicious` : ""}`;
  const when = s.analysed ? ` (analysed ${s.analysed.slice(0, 10)})` : "";
  const lines = [`${s.verdict}: ${headline}${when}${res.cached ? ", cached" : ""}`, ...s.facts.map(([k, v]) => `${k}: ${v}`)];
  return { status: "ok", lines, link, verdict: s.verdict };
}

export const source = {
  id: "virustotal",
  label: "VirusTotal",
  kinds: ["ip", "domain", "hash"],
  mode: "fetch",
  recipients: ["virustotal.com, with your own account and API key"],
  call,
  linkFor,
};

export default { classify, linkFor, call, source, relay };
