// Which cell, which column, which table? The Logs blade's results grid is
// ag-Grid, so this keys on ARIA (role=gridcell/row/columnheader,
// aria-colindex, aria-rowindex) and on ag-Grid's stable structural classes
// (.ag-root, ag-row-level-N), never on the blade's own hashed React class
// names, with geometry (a header whose x-range contains the cell) as the
// last resort. This is the Sentinel counterpart of context.js.
//
//   cellAt(el)                 → { cell, row, grid, kind: "grid"|"detail"|"header"|null }
//   columnOf(info)             → { column, path, header } | null
//        column  the table column (top-level)
//        path    the full dotted path when the click was on a nested leaf
//                (UserIdentity.type), else the column
//   valueOf(info)              → the clicked cell's text
//   tableOf(info, doc)         → { table, basis: "row"|"query"|null, candidates }
//   queryText(doc)             → the Monaco editor's visible text, "" if none
//   clickContext(el, { discriminators, known, doc, scope, forcedTable, infer }) → the click-context.js shape:
//     { container, scope, discriminator, basis, candidates, inferred, event, search, read, row, info, column, kind, value }
//        container  the table: the row's Type, else the query's one table,
//                   else forcedTable (the picker), else infer(column,
//                   candidates)'s one table (basis "column"); inferred keeps
//                   what infer answered when it named several
//        scope      the caller's (the workspace name), a config fact
//        kind       "value" for a cell, "field" for a column header
//        read(name) the row's other columns; nothing on a header click
//
// DOM-reading only; never writes, never fetches. Plain ES module.

import { tablesIn } from "./kql.js";

// The Logs blade renders results with ag-Grid (verified live, 2026-09-17):
// the results grid, and (under an expanded row) a second, nested ag-Grid
// of key/value rows, tree-indented for the leaves of a dynamic column
// (ag-row-level-1 under UserIdentity). Rows are absolutely positioned, so
// DOM order is not row order; aria-rowindex is.
const HEADER_SEL = '[role="columnheader"], th';
const CELL_SEL = '[role="gridcell"], [role="cell"], td';
const ROW_SEL = '[role="row"], tr';
const GRID_SEL = '.ag-root, [role="grid"], [role="treegrid"], [role="table"], table';
const NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]*(\s\[UTC\])?$/;

export function text(el) {
  return el ? String(el.textContent || "").replace(/\s+/g, " ").trim() : "";
}

export function headerName(el) {
  // "TimeGenerated [UTC]" → TimeGenerated; a sort glyph or menu inside the
  // header contributes no letters worth keeping.
  const t = text(el).replace(/\s*\[UTC\]\s*$/, "");
  const m = /^([A-Za-z_][A-Za-z0-9_.]*)/.exec(t);
  return m ? m[1] : t;
}

function rect(el) {
  return el && el.getBoundingClientRect ? el.getBoundingClientRect() : null;
}

function cellsOf(row) {
  return row ? Array.from(row.querySelectorAll(CELL_SEL)).filter((c) => c.closest(ROW_SEL) === row) : [];
}

// The detail tree under an expanded row renders one key/value pair per
// row: a name cell, then a value cell, indented by nesting depth. A row is
// a detail row when it has a name-shaped first cell and a value beside it
// and no aria-colindex worth trusting.
function looksLikeDetailRow(row) {
  const cells = cellsOf(row).filter((c) => text(c) !== "");
  if (cells.length !== 2) return false;
  return NAME_RE.test(text(cells[0]));
}

// A grid nested inside another grid's row is the detail tree.
function isNestedGrid(grid) {
  const parent = grid && grid.parentElement ? grid.parentElement.closest(GRID_SEL) : null;
  return Boolean(parent);
}

export function cellAt(el) {
  if (!el || !el.closest) return { cell: null, row: null, grid: null, kind: null };
  const header = el.closest(HEADER_SEL);
  if (header) return { cell: header, row: header.closest(ROW_SEL), grid: header.closest(GRID_SEL), kind: "header", target: el };
  let cell = el.closest(CELL_SEL);
  const row = cell ? cell.closest(ROW_SEL) : el.closest(ROW_SEL);
  if (!cell && row) cell = el; // no cell role: the element itself
  if (!cell) return { cell: null, row: null, grid: null, kind: null };
  const grid = (row || cell).closest(GRID_SEL);
  const kind = row && (isNestedGrid(grid) || looksLikeDetailRow(row)) ? "detail" : "grid";
  return { cell, row, grid, kind, target: el };
}

export function valueOf(info) {
  if (!info || !info.cell) return "";
  // Prefer the innermost element the user actually clicked when it holds
  // the same text (a leaf span inside a cell); the cell otherwise.
  const t = info.target && info.target !== info.cell ? text(info.target) : "";
  return t && text(info.cell).includes(t) ? t : text(info.cell);
}

function headersOf(grid, doc) {
  const scope = grid || doc;
  return scope ? Array.from(scope.querySelectorAll(HEADER_SEL)).filter((h) => headerName(h)) : [];
}

function headerByIndex(grid, doc, idx) {
  if (!idx) return null;
  for (const h of headersOf(grid, doc)) if (h.getAttribute("aria-colindex") === String(idx)) return h;
  return null;
}

function headerByGeometry(grid, doc, cell) {
  const r = rect(cell);
  if (!r) return null;
  const x = r.left + Math.min(r.width, 24) / 2; // the cell's left edge: columns are left-aligned
  let best = null;
  for (const h of headersOf(grid, doc)) {
    const hr = rect(h);
    if (!hr || hr.width === 0) continue;
    if (x >= hr.left - 1 && x <= hr.right + 1) {
      best = h;
      break;
    }
  }
  return best;
}

function keyOf(row) {
  const cells = cellsOf(row).filter((c) => text(c) !== "");
  return cells.length ? text(cells[0]).replace(/\s*\[UTC\]\s*$/, "") : "";
}

function valueCellOf(row) {
  const cells = cellsOf(row).filter((c) => text(c) !== "");
  return cells.length > 1 ? cells[1] : null;
}

// Tree depth of a detail row. ag-Grid marks the indent on the key cell's
// wrapper (ag-row-group-indent-N); verified live: the leaves of a dynamic
// value sit in the same grid as their parent, every row ag-row-level-0.
// So the cell's class comes first, then the key cell's left offset relative
// to the grid's least-indented key cell.
const INDENT_PX = 24;
function levelOf(row, grid) {
  const cells = cellsOf(row).filter((c) => text(c) !== "");
  const key = cells[0];
  if (key) {
    const el = key.querySelector('[class*="ag-row-group-indent-"]') || key;
    const m = /\bag-row-group-indent-(\d+)\b/.exec(typeof el.className === "string" ? el.className : "");
    if (m) return Number(m[1]);
  }
  const m = /\bag-row-level-(\d+)\b/.exec(typeof row.className === "string" ? row.className : "");
  if (m && Number(m[1]) > 0) return Number(m[1]);
  const r = rect(key);
  if (!r) return 0;
  const base = grid ? minKeyLeft(grid) : 0;
  return Math.max(0, Math.round((r.left - base) / INDENT_PX));
}

const minLeftMemo = new WeakMap();
function minKeyLeft(grid) {
  if (minLeftMemo.has(grid)) return minLeftMemo.get(grid);
  let min = Infinity;
  for (const r of grid.querySelectorAll(ROW_SEL)) {
    if (r.closest(GRID_SEL) !== grid) continue;
    const k = cellsOf(r).filter((c) => text(c) !== "")[0];
    const kr = rect(k);
    if (kr && kr.left < min) min = kr.left;
  }
  const out = Number.isFinite(min) ? min : 0;
  minLeftMemo.set(grid, out);
  setTimeout(() => minLeftMemo.delete(grid), 500); // per click, not per page
  return out;
}

function rowIndexOf(row) {
  const v = row.getAttribute && row.getAttribute("aria-rowindex");
  return v ? Number(v) : Number.MAX_SAFE_INTEGER;
}

// The detail grid's rows in display order (aria-rowindex), not DOM order.
function detailRows(grid) {
  return Array.from(grid ? grid.querySelectorAll(ROW_SEL) : [])
    .filter((r) => r.closest(GRID_SEL) === grid && keyOf(r))
    .sort((a, b) => rowIndexOf(a) - rowIndexOf(b));
}

// The grid that holds a nested grid's row: the parent grid, and the row
// in it the nested grid hangs under (UserIdentity's row holds the grid of
// its leaves). Verified live: master grid → detail grid of key/value rows
// → one more grid per expanded dynamic value.
function parentOf(grid) {
  const holder = grid && grid.parentElement ? grid.parentElement.closest(ROW_SEL) : null;
  const parent = holder ? holder.closest(GRID_SEL) : null;
  if (!parent || parent === grid) return null;
  // ag-Grid master/detail: the nested grid sits in its own full-width
  // details row, keyless; the key it belongs to is the nearest keyed row
  // above it in display order (the one whose chevron was opened).
  let row = holder;
  if (!keyOf(holder)) {
    const idx = rowIndexOf(holder);
    let best = null;
    for (const r of parent.querySelectorAll(ROW_SEL)) {
      if (r.closest(GRID_SEL) !== parent || !keyOf(r)) continue;
      const i = rowIndexOf(r);
      if (i < idx && (!best || i > rowIndexOf(best))) best = r;
    }
    row = best || holder;
  }
  return { grid: parent, row };
}

// The detail grids from the one the click landed in up to (not including)
// the master grid, innermost first, each with the row it hangs under.
function detailChain(info) {
  const out = [];
  let grid = info.grid;
  let guard = 0;
  while (grid && guard++ < 8) {
    const up = parentOf(grid);
    if (!up) break;
    out.push({ grid, row: up.row });
    grid = up.grid;
  }
  return out;
}

// The nesting path of a detail row: within its grid, every row above it
// (in display order) with a smaller level is an ancestor key; then each
// enclosing grid's own row is the key it hangs under (UserIdentity →
// userName).
function detailPath(info) {
  const row = info.row;
  const parts = [keyOf(row)];
  const rows = detailRows(info.grid);
  const at = rows.indexOf(row);
  if (at >= 0) {
    let level = levelOf(row, info.grid);
    for (let i = at - 1; i >= 0 && level > 0; i--) {
      const l = levelOf(rows[i], info.grid);
      if (l < level) {
        parts.unshift(keyOf(rows[i]));
        level = l;
      }
    }
  }
  const chain = detailChain(info);
  // chain[0] is the click's own grid; its row is the key one level up.
  for (let i = 0; i < chain.length - 1; i++) {
    const k = keyOf(chain[i].row);
    if (k) parts.unshift(k);
  }
  return parts;
}

export function columnOf(info, doc = typeof document !== "undefined" ? document : null) {
  if (!info || !info.cell) return null;
  if (info.kind === "header") {
    const name = headerName(info.cell);
    return name ? { column: name, path: name, header: info.cell } : null;
  }
  if (info.kind === "detail") {
    const parts = detailPath(info);
    if (!parts.length || !parts[0]) return null;
    return { column: parts[0], path: parts.join("."), header: null };
  }
  const idx = info.cell.getAttribute && info.cell.getAttribute("aria-colindex");
  const header = headerByIndex(info.grid, doc, idx) || headerByGeometry(info.grid, doc, info.cell);
  if (!header) return null;
  const name = headerName(header);
  return name ? { column: name, path: name, header } : null;
}

// A named column's value for the row the click belongs to. In the detail
// tree every column is a top-level key/value row, so the answer is read
// straight off it (Type, Aid, …); in the results grid it is the cell under
// the header of that name.
export function fieldValueIn(info, name, doc = typeof document !== "undefined" ? document : null) {
  if (!info || !info.row) return null;
  if (info.kind === "detail") {
    // The outermost detail grid lists every column of the row; an inner
    // grid lists the leaves of one dynamic value. Look from the outside in.
    const chain = detailChain(info);
    const grids = chain.length ? chain.map((c) => c.grid).reverse() : [info.grid];
    for (const g of grids) {
      for (const r of detailRows(g)) {
        if (levelOf(r, g) === 0 && keyOf(r) === name) {
          const v = valueCellOf(r);
          return v ? text(v) || null : null;
        }
      }
    }
    return null;
  }
  const row = info.row;
  const headers = headersOf(info.grid, doc);
  const h = headers.find((x) => headerName(x) === name);
  if (!h) return null;
  const idx = h.getAttribute("aria-colindex");
  const cells = cellsOf(row);
  let cell = idx ? cells.find((c) => c.getAttribute("aria-colindex") === idx) : null;
  if (!cell) {
    const hr = rect(h);
    cell = cells.find((c) => {
      const r = rect(c);
      return r && hr && r.left >= hr.left - 1 && r.left <= hr.right;
    }) || null;
  }
  return cell ? text(cell) || null : null;
}

// The query text off a visible Monaco editor (.view-line spans; NBSP for
// indentation). Simple mode keeps a hidden Monaco whose one rendered line
// is a fragment of the query, which is worse than nothing. So only an
// editor with real size counts.
export function queryText(doc = typeof document !== "undefined" ? document : null) {
  if (!doc) return "";
  for (const editor of doc.querySelectorAll(".monaco-editor")) {
    const r = rect(editor);
    if (!r || r.width < 120 || r.height < 20) continue;
    const lines = editor.querySelectorAll(".view-lines .view-line");
    if (!lines.length) continue;
    return Array.from(lines, (l) => String(l.textContent || "").replace(/\u00a0/g, " ")).join("\n");
  }
  return "";
}

// The distinct Type values of the rows on screen, for a header click,
// which has no row of its own.
export function pageTables(info, doc = typeof document !== "undefined" ? document : null) {
  const grid = info && info.grid;
  const headers = headersOf(grid, doc);
  const h = headers.find((x) => headerName(x) === "Type");
  if (!h) return [];
  const idx = h.getAttribute("aria-colindex");
  const seen = new Set();
  for (const row of grid ? grid.querySelectorAll(ROW_SEL) : []) {
    if (row.closest(GRID_SEL) !== grid) continue;
    const cell = idx ? cellsOf(row).find((c) => c.getAttribute("aria-colindex") === idx) : null;
    const v = cell ? text(cell) : "";
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) seen.add(v);
  }
  return Array.from(seen);
}

export function tableOf(info, doc = typeof document !== "undefined" ? document : null, { known = [] } = {}) {
  const fromRow = info && info.kind !== "header" ? fieldValueIn(info, "Type", doc) : null;
  if (fromRow && /^[A-Za-z_][A-Za-z0-9_]*$/.test(fromRow)) return { table: fromRow, basis: "row", candidates: [fromRow] };
  if (info && info.kind === "header") {
    const onPage = pageTables(info, doc);
    if (onPage.length === 1) return { table: onPage[0], basis: "page", candidates: onPage };
    if (onPage.length > 1) return { table: null, basis: null, candidates: onPage };
  }
  const candidates = tablesIn(queryText(doc)).filter((t) => t !== "S" && t !== "T");
  if (candidates.length === 1) return { table: candidates[0], basis: "query", candidates };
  if (candidates.length > 1) {
    const hit = candidates.find((c) => known.includes(c));
    return { table: hit || null, basis: hit ? "query" : null, candidates };
  }
  return { table: null, basis: null, candidates: [] };
}

// The click as click-context.js hands it to the section. The column is
// read here as well (the cell under which header, or the detail row's
// dotted path), since the table and the column are one DOM walk.
export function clickContext(el, { discriminators = {}, known = [], doc = typeof document !== "undefined" ? document : null, scope = null, forcedTable = null, infer = null } = {}) {
  const info = cellAt(el);
  const column = info.cell ? columnOf(info, doc) : null;
  const header = info.kind === "header";
  let found = forcedTable ? { table: forcedTable, basis: "user", candidates: [forcedTable] } : tableOf(info, doc, { known });
  let inferred = null;
  if (!found.table && column && infer) {
    inferred = infer(column.path, found.candidates) || (column.path !== column.column ? infer(column.column, found.candidates) : null);
    if (inferred && inferred.sourcetype) found = { table: inferred.sourcetype, basis: "column", candidates: [inferred.sourcetype] };
  }
  const read = (name) => (header || !info.row ? null : fieldValueIn(info, name, doc));
  const container = found.table;
  const discField = container ? discriminators[container] : null;
  const discValue = discField ? read(discField) : null;
  const text = queryText(doc);
  return {
    container,
    scope,
    discriminator: discField && discValue ? { field: discField, value: discValue } : null,
    basis: { container: found.basis, scope: scope ? "workspace" : null },
    candidates: found.candidates,
    inferred,
    event: { id: read("_ItemId"), time: read("TimeGenerated") || "" },
    search: text ? { text, sid: "" } : null,
    read,
    row: info.row,
    info,
    column,
    kind: header ? "field" : "value",
    value: header ? "" : valueOf(info),
  };
}

export default { cellAt, columnOf, valueOf, tableOf, pageTables, fieldValueIn, queryText, headerName, text, clickContext };
