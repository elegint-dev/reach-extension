// selection: a SIEM click landing in the panel. The worker relays the
// click (background.js reach:selection) and this is the one place it is
// turned into a route. A click holds nothing: the value rides as the
// field route's ?value= parameter and as this tab's last event
// (last-event.js). The held stores (investigation.js, the notebook's
// pins, pinned.js) are written only by Hold, Attach and the Holding add
// form, never here. The index the event sits in is scope, learned for
// the event's sourcetype (scope.js); a wildcard is the search string's
// scope, not an index.
//
//   land(sel) → { platform, route: "field", params, hop } | null
//     params: { name, st?, on?, value? } for router.build("field", params)
//     hop: hopKey(sel)
//   hopKey(sel) → string   the row the click was in, for the trail
//
// The trail records hops, not clicks (navstack.js): clicks in one event or
// result row update the current chip, and only a click in another row, a
// pivot's results or a page the panel navigated to itself adds one. The
// hop key names the row: platform, container, record type, the search the
// row came from and the row's identity (the event id when the page shows
// one, else the row's time and sibling fields; a row with neither is the
// search itself, so clicks on it share one chip).

import * as scope from "./scope.js";
import * as lastEvent from "./last-event.js";

export function land(sel) {
  if (!sel || !sel.name) return null;
  const platform = sel.platform === "sentinel" ? "sentinel" : "splunk";
  const value = sel.kind === "value" && sel.value ? String(sel.value) : "";
  if (sel.index && sel.sourcetype) scope.learn(sel.sourcetype, sel.index);
  lastEvent.remember({
    platform,
    container: sel.sourcetype,
    fields: sel.event || {},
    provenance: sel.provenance || null,
    clicked: value ? { field: sel.name, value } : null,
  });
  const params = { name: sel.name };
  if (sel.sourcetype) params.st = sel.sourcetype;
  if (sel.discriminator && sel.discriminator.value) params.on = sel.discriminator.value;
  if (value) params.value = value;
  return { platform, route: "field", params, hop: hopKey(sel) };
}

export function hopKey(sel) {
  const platform = sel && sel.platform === "sentinel" ? "sentinel" : "splunk";
  const container = (sel && sel.sourcetype) || "";
  const type = sel && sel.discriminator && sel.discriminator.value ? String(sel.discriminator.value) : "";
  const prov = (sel && sel.provenance) || {};
  const search = prov.search && prov.search.text ? String(prov.search.text) : "";
  const ev = prov.event || {};
  let row = "";
  if (ev.id) row = `id:${ev.id}`;
  else {
    const fields = Object.entries((sel && sel.event) || {})
      .filter(([, v]) => typeof v === "string" && v)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${k}=${v}`);
    if (ev.time || fields.length) row = `row:${ev.time || ""};${fields.join(";")}`;
  }
  return [platform, container, type, digest(search), digest(row)].join("|");
}

// FNV-1a, 32 bits, as hex: the search text and the row's fields can run to
// kilobytes and the key sits on every trail entry in sessionStorage.
function digest(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export default { land, hopKey };
