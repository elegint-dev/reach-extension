// HijackLibs (DLLs known to be vulnerable to DLL search-order hijacking)
// as a deep-link enrichment source (app/lib/enrich.js): GPL-3.0
// (https://github.com/wietze/HijackLibs/blob/main/LICENSE). Same
// deferral as LOLBAS and GTFOBins (docs/COMPLIANCE.md): no data ships.
// HijackLibs' own per-entry URL is keyed by a vendor path this module
// does not have (https://hijacklibs.net/entries/{vendor-path}/{dll}.html)
// and its site search is a client-side widget with no URL parameter,
// so the link opens a GitHub code search over the wietze/HijackLibs
// repository for the clicked DLL name instead.
//
//   classify(value)   { kind: "dll_name", id } | null
//   linkFor(value)    { href, label } | null
//   call(value)       { status, lines, link } (the enrich.js registry contract; not
//                      used by popup-ui.js's deep-link row, which reads linkFor() alone)
//   source            the ready-to-register object

import { detectProcessName } from "../shapes.js";

export function classify(value) {
  const proc = detectProcessName(value);
  if (proc && /\.dll$/i.test(proc.detail)) return { kind: "dll_name", id: proc.detail };
  return null;
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  const q = encodeURIComponent(`repo:wietze/HijackLibs "${c.id}"`);
  return { href: `https://github.com/search?q=${q}&type=code`, label: "Search HijackLibs ↗" };
}

export async function call(value) {
  const link = linkFor(value);
  if (!link) return { status: "refused", lines: [] };
  return { status: "ok", lines: [], link };
}

export const source = { id: "hijacklibs", label: "HijackLibs", kinds: ["dll_name"], mode: "deeplink", recipients: [], call, linkFor };

export default { classify, linkFor, call, source };
