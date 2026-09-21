// copy: the lines that are written twice. A placeholder, a hint, a chip or
// a card line composed for a 1440px tab is cut mid-word or wraps into a
// paragraph in a 320px side panel. Truncation is not an answer, so each
// such line has a short variant written for the panel, and the caller asks
// for the line by key. Prose paragraphs are not here: they wrap at word
// boundaries and read fine at any width.
//
//   copy("omnibox.placeholder")   -> the string for the current surface
//   copy("discover.imported", { when, rows }) -> a line with its parts filled
//
// The surface comes from app/lib/surface.js. A view renders on navigation,
// so it picks up a surface change on the next route; the chrome (omnibox,
// paste, Holding, Settings) lives for the whole session, and app.js
// re-asks its lines when the surface changes.

import { TERMS, isSentinel } from "./platform.js";
import { pick } from "./surface.js";

const LINES = {
  "omnibox.placeholder": {
    wide: () => (isSentinel() ? `hold anything: ${TERMS.sourcetype}, ${TERMS.field}, hash, IP, user` : "hold anything: field, event, CIM name, hash, IP, PID"),
    panel: () => (isSentinel() ? `${TERMS.sourcetype}, ${TERMS.field}, hash, IP, user` : "field, event, hash, IP, PID"),
  },
  "drawer.empty": {
    wide: () => `Click a value or a row in the catalogue and the ${TERMS.lang} for it appears here, with its parameters and its hazards, ready to copy into ${TERMS.host}.`,
    panel: () => `Click a value or a row and its ${TERMS.lang} appears here, ready to copy.`,
  },
  "paste.summary.empty": {
    wide: () => "Nothing selected yet",
    panel: () => "nothing selected",
  },
  "holding.empty": {
    wide: () => "Nothing held. Press Hold on a value, or add one below.",
    narrow: () => "Nothing held. Press Hold on a value, or press Add.",
    panel: () => "Nothing held. Press Hold on a value, or Add.",
  },
  "holding.hint": {
    wide: () => "Bound into every search that asks for one of these. Held values live in the notebook; pinned ones stay in this browser.",
    panel: () => "Bound into every search. Held values live in the notebook; pins stay.",
  },
  "holding.key": { wide: () => "key: aid, hostname, tenant…", panel: () => "key" },
  "holding.value": { wide: () => "value", panel: () => "value" },
  "holding.pinned": { wide: () => "Pinned, kept across sessions", panel: () => "Pinned" },
  "settings.kept": { wide: () => "Kept across sessions, this browser only", panel: () => "Kept in this browser" },
  "settings.pins": { wide: () => "Pinned values: bound into every search that asks for one", panel: () => "Pinned values, bound into every search" },
  "settings.pinkey": { wide: () => "key: tenant, region…", panel: () => "key" },
  "settings.index.placeholder": { wide: () => "derived per sourcetype", panel: () => "per sourcetype" },
  "settings.index.derived": {
    wide: () => "Each search takes the index discovery found its sourcetype in; set one here to use it everywhere instead. The FDR pack falls back to the cs_index macro.",
    panel: () => "Each search takes the index its sourcetype was found in; set one to use it everywhere.",
  },
  "settings.index.override": {
    wide: ({ index }) => `Every search runs in ${index}. Clear it to derive the index per sourcetype again.`,
    panel: ({ index }) => `Every search runs in ${index}; clear to derive per sourcetype.`,
  },
  "settings.index.perst": { wide: () => "Index per sourcetype: chosen here, or the one you clicked in", panel: () => "Index per sourcetype" },
  "discover.resourceId": {
    wide: () => "/subscriptions/…/resourceGroups/…/providers/Microsoft.OperationalInsights/workspaces/<name>",
    panel: () => "workspace resource id",
  },
  "discover.imported": {
    wide: ({ when, rows }) => `imported ${when} · ${rows} rows`,
    panel: ({ rows }) => `imported · ${rows} rows`,
  },
  "discover.stale": {
    wide: () => "stale: the query changed since this was imported",
    panel: () => "stale",
  },
  "discover.recordTypesBy": {
    wide: ({ column }) => `record types by ${column}`,
    panel: ({ column }) => `types by ${column}`,
  },
  "discover.openPortal": { wide: () => "Open in portal ↗", panel: () => "Open ↗" },
  "discover.copyKql": { wide: () => "copy KQL", panel: () => "copy" },
  "discover.copyAll": { wide: () => "Copy all recipe queries", panel: () => "Copy all queries" },
  "discover.indexPlaceholder": { wide: () => "index (default: *)", panel: () => "index (*)" },
  "discover.skipFresh": {
    wide: () => " skip sourcetypes profiled in the last 7 days",
    panel: () => " skip those profiled this week",
  },
  "start.line": {
    wide: () => `Type a ${TERMS.sourcetype}, a ${TERMS.field}, a value, or paste one: a hash, an IP, a user.`,
    panel: () => `A ${TERMS.sourcetype}, a ${TERMS.field}, a hash or an IP.`,
  },
  "start.line.fdr": {
    wide: () => "Type a sourcetype, a field, a value, or take one of the guided workflows below.",
    panel: () => "A sourcetype, a field, or a value.",
  },
  "card.host": { wide: () => "A hostname or an aid, and you want to know what ran on it.", panel: () => "A hostname or an aid: what ran on it." },
  "card.pid": { wide: () => "A PID from a ticket, a dump, ps or Task Manager.", panel: () => "A PID from a ticket, a dump or ps." },
  "card.detection": { wide: () => "A detection summary event: a different sourcetype, renamed handles.", panel: () => "A detection summary event." },
  "card.ioc": { wide: () => "A hash, an IP, a domain, a filename.", panel: () => "A hash, IP, domain or filename." },
};

export function copy(key, parts = {}) {
  const line = LINES[key];
  if (!line) throw new Error(`no copy for ${key}`);
  const fn = pick(line);
  return fn(parts);
}

export function hasCopy(key) {
  return key in LINES;
}

export default copy;
