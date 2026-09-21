// One shape for a click's context on every host. context.js (Splunk) and
// sentinel-context.js (Sentinel) each read their own DOM and answer the
// same keys; this module picks the reader for the platform and adds what
// the bands read off the row through it: the verdict and alert fields,
// the event's summary line, and searchNow for the Hold row.
//
//   SHAPE                            the keys every platform's context carries
//   clickContext(platform, el, { discriminators, known, doc, scope, forcedTable, infer, runbooks, readEditor }) → {
//     container       the sourcetype or table, string | null
//     scope           the index (Splunk) or the workspace name (Sentinel), string | null
//     discriminator   { field, value } | null, the record type on this container
//     basis           { container: "row" | "search" | "query" | "page" | "column" | "user" | null,
//                       scope: "row" | "search" | "workspace" | null }
//     candidates      the containers in reach when none is certain (a mixed page, a query naming several)
//     inferred        what infer() answered on Sentinel when the column names several tables, else null
//     eventFields     the row's sibling fields a verdict reads (verdictFields), plus the alert fields when runbooks is on
//     alertRow        the alert fields alone, the container under the platform's key, for the runbook band
//     event           { id, time, summary }, the row's event as the notebook keeps it
//     search          { text, sid } | null, the search the row came from as the page shows it
//     searchNow()     async, the search as of a Hold click (the editor first on Splunk)
//     read(name)      the row's value for another field, or null
//   }
//   conform(ctx)                     the same object with every SHAPE key present, for a caller's own reader
//
// DOM-reading through the platform module only; never writes, never fetches.

import * as splunk from "./context.js";
import * as sentinel from "./sentinel-context.js";
import { verdictFields, alertFields } from "./bands/verdict.js";
import { eventSummary } from "./bands/hold-and-benign.js";

export const SHAPE = Object.freeze(["container", "scope", "discriminator", "basis", "candidates", "inferred", "eventFields", "alertRow", "event", "search", "searchNow", "read"]);

// The alert fields carry the container under the platform's own key: a
// Splunk row's sourcetype, a Sentinel row's Type.
const CONTAINER_KEY = { splunk: "sourcetype", sentinel: "Type" };

export function conform(ctx) {
  const out = { ...ctx };
  for (const k of SHAPE) if (!(k in out)) out[k] = k === "read" ? () => null : k === "searchNow" ? async () => out.search : k === "candidates" ? [] : k === "eventFields" || k === "alertRow" ? {} : k === "basis" ? { container: null, scope: null } : k === "event" ? { id: null, time: "", summary: "" } : null;
  return out;
}

export function clickContext(platform, el, { runbooks = false, readEditor = null, ...opts } = {}) {
  const base = platform === "sentinel" ? sentinel.clickContext(el, opts) : splunk.clickContext(el, opts);
  const read = base.read || (() => null);
  const eventFields = verdictFields(read);
  const alertRow = runbooks ? alertFields(read) : {};
  if (base.container && Object.keys(alertRow).length) alertRow[CONTAINER_KEY[platform] || "sourcetype"] = base.container;
  Object.assign(eventFields, alertRow);
  const ev = base.event || { id: null, time: "" };
  const event = { id: ev.id || null, time: ev.time || "", summary: eventSummary({ container: base.container, discriminator: base.discriminator ? base.discriminator.value : null, time: ev.time || "" }) };
  const searchNow = platform === "sentinel" ? async () => base.search : splunk.searchNow(opts.doc, readEditor);
  return conform({ ...base, platform, read, eventFields, alertRow, event, searchNow });
}

export default { SHAPE, clickContext, conform };
