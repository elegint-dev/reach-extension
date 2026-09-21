// Which event did the click land in? Splunk renders an event's default fields
// (host, source, sourcetype, and index when it is a selected field) as the
// same <a class="f-v" data-field-name="…"> links the value popup is bound to,
// inside the same event container. Reading them is a free, local DOM lookup:
// no network, no guessing. This module is the one place that question is
// answered, for both popups.
//
//   rowEvent(container) → { id, time }   the row's event id when the page shows
//                                        one (_cd, _serial) and its time cell's text
//   pageSearch(doc) → { text, sid }     the search the page ran: the URL's q=
//                                        as it was run, else the bar's rendered
//                                        text (searchString); the job's sid
//   contextFor(el, { discriminators }) → {
//     sourcetype, index, source, host,   string | null: from the row, else from
//                                        the search string, else null
//     discriminator: { field, value } | null   e.g. event_simpleName=ProcessRollup2
//     basis: { sourcetype: "row" | "search" | null, index: … }
//     container: Element                 the event container the click was in
//   }
//   clickContext(el, { discriminators, doc }) → the click-context.js shape:
//     { container, scope, discriminator, basis, candidates, inferred, event, search, read, row }
//     container is the sourcetype, scope the index; a null el is the page
//     (the sidebar's field-info popdown): one sourcetype on the page is
//     the container, several are candidates, read() answers nothing.
//   searchNow(doc, readEditor) → async () => { text, sid }
//     the search as of a Hold click: the editor's text through readEditor
//     (the editor bridge) first, the page's string when it has none.
//
// `discriminators` maps a sourcetype to the field that names its record type
// (FDR: event_simpleName; CloudTrail: eventName). Only consulted once the
// sourcetype is known. A discriminator is meaningless without one.
//
// Plain ES module. DOM-reading only; never writes, never fetches.

// An event in Splunk's events viewer, list or table layout. The outermost
// match wins when they nest (a <tr> inside the row div), so the default-field
// links at the bottom of the event are always inside the container even when
// the clicked value sits in a nested table.
export const EVENT_SELECTOR = ".shared-eventsviewer-list-body-row, .shared-eventsviewer-table-body-row, tr";

export function eventContainerFor(el) {
  if (!el || !el.closest) return null;
  let node = el.closest(EVENT_SELECTOR);
  // Prefer the events-viewer row over a bare <tr> nested inside it.
  const outer = node && node.closest(".shared-eventsviewer-list-body-row, .shared-eventsviewer-table-body-row");
  return outer || node;
}

// Only VALUE links (.f-v). The sidebar's field list also carries
// data-field-name on its field-NAME links, whose text is the name. Reading
// one of those as a value would report a sourcetype called "sourcetype".
export function fieldValueIn(container, fieldName) {
  if (!container || !container.querySelector) return null;
  const el = container.querySelector(`.f-v[data-field-name="${CSS.escape(fieldName)}"]`);
  if (!el) return null;
  const v = (el.textContent || el.title || "").trim();
  return v || null;
}

// index=… / sourcetype=… from the page's own search string: the textarea in
// the search bar. A weaker basis than the row (a search can cover several
// sourcetypes), so it only ever fills a gap the row left.
const TERM_RE = { index: /\bindex\s*=\s*"?([A-Za-z0-9_\-*]+)"?/i, sourcetype: /\bsourcetype\s*=\s*"?([A-Za-z0-9_:\-.*]+)"?/i };

// The search string, wherever this Splunk keeps it: a plain textarea (older
// Splunk Web), the ACE editor's rendered lines (Splunk 9/10: its hidden
// textarea holds only control characters), and the page URL's q= parameter.
export function searchString(doc = document) {
  const parts = [];
  const bar = doc.querySelector("textarea.search-field, [data-test='search-bar'] textarea:not(.ace_text-input), #search-bar textarea:not(.ace_text-input)");
  if (bar && bar.value && !/[\u0000-\u0008]/.test(bar.value)) parts.push(String(bar.value));
  const lines = doc.querySelectorAll(".search-bar .ace_line, .ace_editor .ace_line");
  if (lines.length) parts.push(Array.from(lines, (l) => l.textContent).join("\n"));
  try {
    const loc = doc.defaultView ? doc.defaultView.location : typeof location !== "undefined" ? location : null;
    const q = loc && new URLSearchParams(loc.search).get("q");
    if (q) parts.push(q);
  } catch {
    /* no URL to read */
  }
  return parts.join("\n");
}

export function searchStringTerm(name, doc = document) {
  const text = searchString(doc);
  const m = TERM_RE[name] && TERM_RE[name].exec(text);
  const v = m ? m[1] : null;
  return v && !v.includes("*") ? v : null;
}

// Splunk's own rendered time cell splits the date and the time across
// sibling <span>s with a <br> between them ("formated-time"); plain
// textContent runs them together with no separator ("9/17/268:58:59 PM").
// Its data-time-iso attribute, when present, is the exact instant and
// needs no locale parsing; without it, join the cell's element children's
// text with a space instead of concatenating them raw.
function cellTime(cell) {
  if (!cell) return "";
  const iso = cell.getAttribute ? cell.getAttribute("data-time-iso") : null;
  if (iso) return iso;
  const kids = cell.children ? Array.from(cell.children) : [];
  if (kids.length) {
    const joined = kids.map((c) => (c.textContent || "").trim()).filter(Boolean).join(" ");
    if (joined) return joined;
  }
  return (cell.textContent || "").trim();
}

// Where a click was, as a selection carries it (provenance): the row's
// event id when the page shows one and its time cell's time (an ISO
// string when the cell carries one, else its text, space-joined), and the
// search the page ran, the URL's q= as it was run before the bar's text.
export function rowEvent(container) {
  const id = fieldValueIn(container, "_cd") || fieldValueIn(container, "_serial") || null;
  const cell = container && container.querySelector ? container.querySelector("td.time, .time, [data-test='time'], .formated-time") : null;
  const time = cellTime(cell);
  return { id, time };
}

export function pageSearch(doc = document) {
  let q = "";
  let sid = "";
  try {
    const loc = doc.defaultView ? doc.defaultView.location : typeof location !== "undefined" ? location : null;
    const p = new URLSearchParams(loc ? loc.search : "");
    q = p.get("q") || "";
    sid = p.get("sid") || "";
  } catch {
    /* no URL to read */
  }
  return { text: q || searchString(doc), sid };
}

// The distinct sourcetypes rendered anywhere on the page, for a field-level
// surface (Splunk's field-info popdown summarises a field across the whole
// result set, so there is no one row). One value means the results are
// single-sourcetype and the field can be scoped to it; several means the
// caller has to say "ambiguous" and list them.
export function pageSourcetypes(doc = document) {
  const seen = new Set();
  for (const el of doc.querySelectorAll('.f-v[data-field-name="sourcetype"]')) {
    const v = (el.textContent || el.title || "").trim();
    if (v) seen.add(v);
  }
  if (!seen.size) {
    const fromSearch = searchStringTerm("sourcetype", doc);
    if (fromSearch) seen.add(fromSearch);
  }
  return Array.from(seen).sort();
}

export function contextFor(el, { discriminators = {}, doc = document } = {}) {
  const container = eventContainerFor(el) || (doc && doc.body) || null;
  const basis = { sourcetype: null, index: null };
  const pick = (name) => {
    const fromRow = fieldValueIn(container, name);
    if (fromRow) {
      if (name in basis) basis[name] = "row";
      return fromRow;
    }
    if (name in basis) {
      const fromSearch = searchStringTerm(name, doc);
      if (fromSearch) {
        basis[name] = "search";
        return fromSearch;
      }
    }
    return null;
  };
  const sourcetype = pick("sourcetype");
  const index = pick("index");
  const source = pick("source");
  const host = pick("host");
  let discriminator = null;
  const discField = sourcetype ? discriminators[sourcetype] : null;
  if (discField) {
    const value = fieldValueIn(container, discField);
    if (value) discriminator = { field: discField, value };
  }
  return { sourcetype, index, source, host, discriminator, basis, container };
}

// The click as click-context.js hands it to the section: the sourcetype
// and index, where each came from, the row's event and the page's search,
// and read(name) for the row's other fields. Off the page (no element)
// the reader is the field-info popdown's: page-wide, no row to read.
export function clickContext(el, { discriminators = {}, doc = document } = {}) {
  if (!el) {
    const onPage = pageSourcetypes(doc);
    return {
      container: onPage.length === 1 ? onPage[0] : null,
      scope: null,
      discriminator: null,
      basis: { container: onPage.length === 1 ? "page" : null, scope: null },
      candidates: onPage,
      inferred: null,
      event: { id: null, time: "" },
      search: pageSearch(doc),
      read: () => null,
      row: null,
    };
  }
  const c = contextFor(el, { discriminators, doc });
  const row = c.container;
  return {
    container: c.sourcetype,
    scope: c.index,
    discriminator: c.discriminator,
    basis: { container: c.basis.sourcetype, scope: c.basis.index },
    candidates: c.sourcetype ? [c.sourcetype] : [],
    inferred: null,
    event: rowEvent(row),
    search: pageSearch(doc),
    read: (name) => fieldValueIn(row, name),
    row,
  };
}

// Asked on a Hold click, never at render: the editor's own text through
// readEditor (which injects a page script) first, the page's string when
// the bridge has no editor.
export function searchNow(doc = document, readEditor = null) {
  return async () => {
    const page = pageSearch(doc);
    if (!readEditor) return page;
    try {
      const r = await readEditor();
      if (r && r.ok && r.text) return { text: r.text, sid: page.sid };
    } catch {
      /* the page's string stands */
    }
    return page;
  };
}

export default { contextFor, clickContext, searchNow, eventContainerFor, fieldValueIn, searchString, searchStringTerm, rowEvent, pageSearch, pageSourcetypes, EVENT_SELECTOR };
