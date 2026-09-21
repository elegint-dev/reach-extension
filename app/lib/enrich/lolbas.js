// LOLBAS (Living Off The Land Binaries and Scripts) as a deep-link
// enrichment source (app/lib/enrich.js): GPL-3.0
// (https://github.com/LOLBAS-Project/LOLBAS/blob/main/LICENSE). Per the
// project's accepted answer on GPL-3.0 data inside a proprietary
// extension (defer the bundle, ship the Apache-2.0/CC0 sets, deep-link
// the rest; see docs/COMPLIANCE.md), no LOLBAS data ships in the
// package: nothing is fetched, nothing is read from disk, and no name
// index exists to check a click against. The link opens a GitHub code
// search over the LOLBAS-Project/LOLBAS repository for the clicked
// name, which finds the right page (LOLBAS's own site search is a
// client-side widget with no URL parameter, so a direct per-binary link
// cannot be built without the dataset this module does not carry) and
// needs no lookup to be correct.
//
//   classify(value)   { kind: "binary_name", id } | null
//   linkFor(value)    { href, label }   always non-null when classify() matches
//   call(value)       { status, lines, link } (the enrich.js registry contract; not
//                      used by popup-ui.js's deep-link row, which reads linkFor() alone)
//   source            the ready-to-register object

import { detectProcessName } from "../shapes.js";

export function classify(value) {
  const proc = detectProcessName(value);
  if (proc && !/\.(sys|dll)$/i.test(proc.detail)) return { kind: "binary_name", id: proc.detail };
  return null;
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  const q = encodeURIComponent(`repo:LOLBAS-Project/LOLBAS "${c.id}"`);
  return { href: `https://github.com/search?q=${q}&type=code`, label: "Search LOLBAS ↗" };
}

export async function call(value) {
  const link = linkFor(value);
  if (!link) return { status: "refused", lines: [] };
  return { status: "ok", lines: [], link };
}

export const source = { id: "lolbas", label: "LOLBAS", kinds: ["binary_name"], mode: "deeplink", recipients: [], call, linkFor };

export default { classify, linkFor, call, source };
