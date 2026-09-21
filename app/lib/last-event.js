// The last clicked row's sibling fields, for the panel: a selection
// (background.js reach:selection) carries the few columns a known-good
// verdict reads (popup-ui.js verdictFields), and the value page asks for
// them by container. The same selection carries where the click was (the
// event's id and time, the search, the scope), which the value page's Hold
// puts on the notebook pin, and the field and value the click was on,
// which the field page falls back to when its route names no value. This
// tab's sessionStorage, so a reload keeps the row and another tab never
// sees it. Not a held value: the fields are evidence about one event and
// the clicked value is where the analyst is, not a fact they are holding
// (investigation.js); nothing here is written by Hold or read as held.
//
//   remember({ platform, container, fields, provenance, clicked })
//   recall(container) → fields | null    null when the last row was on another container
//   provenance(container) → { event, search, scope } | null   the same rule
//   clicked(container) → { field, value } | null                the same rule
//   clear()

const KEY = "reach.lastEvent";

function storage() {
  try {
    return typeof sessionStorage !== "undefined" ? sessionStorage : null;
  } catch {
    return null;
  }
}

export function remember({ platform, container, fields, provenance = null, clicked = null }) {
  const s = storage();
  if (!s) return;
  const clean = {};
  for (const [k, v] of Object.entries(fields || {})) if (typeof v === "string" && v) clean[k] = v;
  const prov = provenance && typeof provenance === "object" ? provenance : null;
  const on = clicked && typeof clicked === "object" && clicked.field && clicked.value !== undefined && clicked.value !== null && clicked.value !== "" ? { field: String(clicked.field), value: String(clicked.value) } : null;
  try {
    if (!Object.keys(clean).length && !prov && !on) s.removeItem(KEY);
    else s.setItem(KEY, JSON.stringify({ platform: platform || null, container: container || null, fields: clean, provenance: prov, clicked: on, at: Date.now() }));
  } catch {
    /* storage blocked: the verdict waits for the next click */
  }
}

function read(container) {
  const s = storage();
  if (!s) return null;
  try {
    const raw = s.getItem(KEY);
    if (!raw) return null;
    const rec = JSON.parse(raw);
    if (!rec || typeof rec !== "object") return null;
    if (container && rec.container && rec.container !== container) return null;
    return rec;
  } catch {
    return null;
  }
}

export function recall(container) {
  const rec = read(container);
  return rec && rec.fields && Object.keys(rec.fields).length ? rec.fields : null;
}

export function provenance(container) {
  const rec = read(container);
  return rec && rec.provenance ? rec.provenance : null;
}

export function clicked(container) {
  const rec = read(container);
  return rec && rec.clicked && rec.clicked.field ? { field: rec.clicked.field, value: rec.clicked.value } : null;
}

export function clear() {
  const s = storage();
  if (!s) return;
  try {
    s.removeItem(KEY);
  } catch {
    /* nothing to clear */
  }
}

export default { remember, recall, provenance, clicked, clear };
