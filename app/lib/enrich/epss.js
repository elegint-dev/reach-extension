// FIRST.org's Exploit Prediction Scoring System (EPSS) as a fetch-mode
// enrichment source (app/lib/enrich.js): a keyless, no-registration REST
// lookup by CVE id (https://api.first.org/data/v1/epss, read 2026-09-18:
// "Public endpoints without authentication are limited to 1000 requests
// per minute"). Off by default, same as CIRCL (docs/PRIVACY.md and
// docs/COMPLIANCE.md name api.first.org as a recipient only when a user
// turns this on in Settings), gated the same way through
// app/lib/enrich.js's gate(). FIRST's Services Terms restrict Content to
// "vulnerability disclosure, incident response, or preventative
// cybersecurity purposes" (docs/COMPLIANCE.md carries the full line);
// an analyst's SIEM lookup is incident response.
//
//   classify(value)   { kind: "cve", id } | null   (app/lib/shapes.js detectCve)
//   linkFor(value)    null (no official per-CVE EPSS page)
//   summarize(row)    [line, ...] for one epss API row, "EPSS 0.93 (top 2 percent)"
//   call(value, ctx)  { status, lines, link } (the enrich.js registry
//                      contract; ctx.ask is the background relay)
//   source            the ready-to-register object
//   relay             the background worker's descriptor (background.js lookup()):
//                     the toggle key, host pattern, URL by CVE id

import { detectCve } from "../shapes.js";
import { KEYS } from "../storage-keys.js";

const CVE_RE = /^CVE-(19|20)\d{2}-\d{4,}$/i;

export const relay = Object.freeze({
  id: "epss",
  messages: { status: "reach:enrich:status", lookup: "reach:enrich:lookup" },
  bySource: true,
  keys: [KEYS.epssEnabled],
  config: (got) => ({ enabled: got[KEYS.epssEnabled] === true }),
  hosts: () => ["https://api.first.org/*"],
  configured: (cfg) => cfg.enabled,
  status: (cfg, permitted) => ({ ok: true, enabled: cfg.enabled, permitted }),
  accepts: (kind, id) => kind === "cve" && CVE_RE.test(id),
  method: "GET",
  url: (kind, id) => `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}`,
  headers: () => ({ accept: "application/json" }),
  answer: ({ ok, status, body }) => ({ ok, status, data: body }),
  failure: (cfg, why) => ({ ok: false, status: 0, error: `Could not reach epss (${why}).` }),
  errors: {
    unconfigured: "epss is off: turn it on in Reach's settings.",
    unpermitted: "Reach has no permission to contact this source yet. Turn it on again in Reach's settings to grant it.",
    refused: "Lookup refused: not a shape this source answers.",
  },
});

export function classify(value) {
  const d = detectCve(value);
  return d ? { kind: "cve", id: d.detail } : null;
}

export function linkFor() {
  return null;
}

// (1 - percentile) as a plain-language "top N percent": one decimal
// place under 10%, whole numbers above, never "top 0 percent" for a
// non-zero score.
function topPercentLabel(percentile) {
  const p = Number(percentile);
  if (!Number.isFinite(p)) return null;
  const top = Math.max(0, (1 - p) * 100);
  if (top === 0) return "top <0.1 percent";
  const rounded = top < 10 ? Math.round(top * 10) / 10 : Math.round(top);
  return `top ${rounded < 0.1 ? "<0.1" : rounded} percent`;
}

export function summarize(row) {
  if (!row) return [];
  const score = Number(row.epss);
  if (!Number.isFinite(score)) return [];
  const top = topPercentLabel(row.percentile);
  const when = row.date ? ` as of ${row.date}` : "";
  return [`EPSS ${score.toFixed(2)}${top ? ` (${top})` : ""}${when}`];
}

export async function call(value, ctx = {}) {
  const c = classify(value);
  if (!c) return { status: "refused", lines: [] };
  if (typeof ctx.ask !== "function") return { status: "error", lines: ["EPSS needs Reach's background worker, not available here."] };
  let res;
  try {
    res = await ctx.ask({ type: "reach:enrich:lookup", source: "epss", kind: c.kind, id: c.id });
  } catch (err) {
    res = { ok: false, status: 0, error: err && err.message ? err.message : String(err) };
  }
  if (!res || !res.ok) return { status: "error", lines: [res && res.error ? res.error : "Could not reach the EPSS API."] };
  const rows = res.data && Array.isArray(res.data.data) ? res.data.data : [];
  const row = rows.find((r) => String(r.cve).toUpperCase() === c.id) || rows[0];
  const lines = summarize(row);
  if (!lines.length) return { status: "empty", lines: [`${c.id} has no EPSS score yet.`] };
  return { status: "ok", lines };
}

export const source = { id: "epss", label: "EPSS", kinds: ["cve"], mode: "fetch", recipients: ["api.first.org, only after you turn it on in Reach's settings"], call, linkFor };

export default { classify, linkFor, summarize, call, source, relay };
