// GTFOBins (Unix binaries an attacker can abuse to bypass local
// security restrictions) as a deep-link enrichment source
// (app/lib/enrich.js): GPL-3.0
// (https://github.com/GTFOBins/GTFOBins.github.io/blob/master/LICENSE).
// Same deferral as LOLBAS (docs/COMPLIANCE.md): no data ships, nothing
// is fetched. Unlike LOLBAS, GTFOBins' own page pattern is deterministic
// from the clicked value alone (the site keys every entry by the exact,
// lowercase Unix binary name, https://gtfobins.org/gtfobins/{name}/), so
// this deep link needs no dataset and no search fallback.
//
// classify() is the narrowest of the LOL* sources on purpose
// (app/lib/virustotal.js's own "a bare-name guess is not enough"
// discipline, carried to app/lib/shapes.js detectProcessName): GTFOBins
// entries are bare words with no extension, the shape half of Sysmon,
// auditd and every other row's free-text fields share with a hostname, a
// status word or an id. A bare token with no path never matches; only
// the basename of an absolute or rooted path does (a POSIX binary in a
// process image or command-line field always carries one).
//
//   classify(value)   { kind: "binary_name", id } | null
//   linkFor(value)    { href, label } | null
//   call(value)       { status, lines, link } (the enrich.js registry contract; not
//                      used by popup-ui.js's deep-link row, which reads linkFor() alone)
//   source            the ready-to-register object

import { detectProcessName } from "../shapes.js";

export function classify(value) {
  const proc = detectProcessName(value);
  // detectProcessName only returns an extension-less name when the value
  // carried a path separator, so this already excludes a bare word; a
  // Windows-extension name (the binary_name kind also carries those) is
  // excluded here too, since GTFOBins entries have none.
  if (!proc || proc.detail.includes(".")) return null;
  return { kind: "binary_name", id: proc.detail.toLowerCase() };
}

export function linkFor(value) {
  const c = classify(value);
  if (!c) return null;
  return { href: `https://gtfobins.org/gtfobins/${encodeURIComponent(c.id)}/`, label: "Open on GTFOBins ↗" };
}

export async function call(value) {
  const link = linkFor(value);
  if (!link) return { status: "refused", lines: [] };
  return { status: "ok", lines: [], link };
}

export const source = { id: "gtfobins", label: "GTFOBins", kinds: ["binary_name"], mode: "deeplink", recipients: [], call, linkFor };

export default { classify, linkFor, call, source };
