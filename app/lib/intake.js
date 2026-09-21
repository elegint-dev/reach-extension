// Intake: what the user brings back from the portal, turned into rows.
// docs/SENTINEL.md §5.1. Three shapes are accepted:
//
//   1. the envelope: the one JSON string a Reach query folds its result
//      into, pasted raw (Copy value on the cell) or inside the one-row CSV
//      the blade exports (Export → CSV); the `reach` column is found and
//      un-quoted
//   2. a plain CSV export of an un-enveloped result (plan B): every row,
//      every column, no identity; the caller has to say which step it was
//   3. a JSON array of row objects, the same as 2 without the CSV
//
//   parse(text) → { kind: "envelope", step, env, params, gen, q, rows, meta }
//              | { kind: "table", columns, rows }
//   throws IntakeError(code, message)
//
// Pure functions over strings. No DOM, no store.

export class IntakeError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "IntakeError";
    this.code = code;
  }
}

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_COLUMN = "reach";

// ---------------------------------------------------------------------------
// CSV, RFC 4180: quoted fields, doubled quotes, newlines inside quotes, CRLF.
// Excel's UTF-8 BOM is stripped. Returns rows of strings; ragged rows are
// kept as they are (the caller decides).

export function parseCsv(text) {
  const s = String(text || "").replace(/^﻿/, "");
  const rows = [];
  let row = [];
  let cell = "";
  let inQ = false;
  let i = 0;
  const n = s.length;
  const sep = detectSeparator(s);
  while (i < n) {
    const ch = s[i];
    if (inQ) {
      if (ch === '"') {
        if (s[i + 1] === '"') { cell += '"'; i += 2; continue; }
        inQ = false;
        i++;
        continue;
      }
      cell += ch;
      i++;
      continue;
    }
    if (ch === '"') { inQ = true; i++; continue; }
    if (ch === sep) { row.push(cell); cell = ""; i++; continue; }
    if (ch === "\r") { i++; continue; }
    if (ch === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; i++; continue; }
    cell += ch;
    i++;
  }
  if (inQ) throw new IntakeError("csv_unterminated", "the CSV ends inside a quoted field");
  if (cell !== "" || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => !(r.length === 1 && r[0] === ""));
}

// Comma unless the header line has more tabs or semicolons: Excel in some
// locales writes ; and a "copy all" from a grid writes tabs.
function detectSeparator(s) {
  const head = s.split(/\r?\n/, 1)[0] || "";
  const stripped = head.replace(/"(?:[^"]|"")*"/g, "");
  const counts = { ",": 0, "\t": 0, ";": 0 };
  for (const ch of stripped) if (ch in counts) counts[ch]++;
  if (counts["\t"] > counts[","] && counts["\t"] >= counts[";"]) return "\t";
  if (counts[";"] > counts[","] && counts[";"] > counts["\t"]) return ";";
  return ",";
}

// ---------------------------------------------------------------------------
// Envelope

function readEnvelope(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw new IntakeError("not_envelope", "not a Reach envelope");
  const meta = obj.meta && typeof obj.meta === "object" ? obj.meta : null;
  if (!meta || !Array.isArray(obj.rows)) throw new IntakeError("not_envelope", "not a Reach envelope (no meta/rows)");
  if (Number(meta.v) !== ENVELOPE_VERSION) throw new IntakeError("envelope_version", `envelope version ${String(meta.v)}: this Reach reads version ${ENVELOPE_VERSION}`);
  if (!meta.step || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(meta.step))) throw new IntakeError("envelope_step", "envelope names no step");
  const params = obj.params && typeof obj.params === "object" && !Array.isArray(obj.params) ? obj.params : {};
  const rows = obj.rows.filter((r) => r && typeof r === "object" && !Array.isArray(r));
  return {
    kind: "envelope",
    step: String(meta.step),
    env: meta.env == null ? "" : String(meta.env),
    gen: meta.gen == null ? null : String(meta.gen),
    q: meta.q == null ? null : String(meta.q),
    params: { ...params },
    rows,
    meta: { ...meta },
  };
}

function tryJson(text) {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (err) {
    return { ok: false, error: err };
  }
}

// A CSV whose header has the envelope column: the cell holds the JSON.
function envelopeFromCsv(rows) {
  if (!rows.length) return null;
  const header = rows[0].map((h) => String(h).trim().toLowerCase());
  const at = header.indexOf(ENVELOPE_COLUMN);
  if (at < 0) return null;
  const data = rows.slice(1).filter((r) => r.some((c) => String(c).trim() !== ""));
  if (!data.length) throw new IntakeError("envelope_empty", "the export has the reach column but no row under it");
  if (data.length > 1) throw new IntakeError("envelope_rows", `the export has ${data.length} rows; an envelope result has exactly one`);
  const cell = data[0][at];
  const parsed = tryJson(cell);
  if (!parsed.ok) throw new IntakeError("envelope_json", `the reach cell is not valid JSON (${parsed.error.message}); if the file was opened in Excel first, export again and drop the file directly`);
  return readEnvelope(parsed.value);
}

function tableFromRows(rows) {
  if (rows.length < 2) throw new IntakeError("csv_empty", "the CSV has a header but no rows");
  const columns = rows[0].map((h) => String(h).trim());
  const out = [];
  for (const r of rows.slice(1)) {
    const o = {};
    columns.forEach((c, i) => { o[c] = r[i] === undefined ? "" : r[i]; });
    out.push(o);
  }
  return { kind: "table", columns, rows: out };
}

export function parse(text) {
  const s = String(text || "").replace(/^﻿/, "").trim();
  if (!s) throw new IntakeError("empty", "nothing to import");
  if (s[0] === "{" || s[0] === "[") {
    const parsed = tryJson(s);
    if (parsed.ok) {
      if (Array.isArray(parsed.value)) {
        const rows = parsed.value.filter((r) => r && typeof r === "object" && !Array.isArray(r));
        if (!rows.length) throw new IntakeError("json_rows", "a JSON array with no row objects");
        const columns = [];
        for (const r of rows) for (const k of Object.keys(r)) if (!columns.includes(k)) columns.push(k);
        return { kind: "table", columns, rows };
      }
      return readEnvelope(parsed.value);
    }
    // A cell copied out of the grid is sometimes wrapped in one extra set of
    // quotes with the inner ones doubled (CSV quoting without the CSV).
    if (s[0] === '"' || parsed.error) {
      const unq = tryJson(s.replace(/^"|"$/g, "").replace(/""/g, '"'));
      if (unq.ok && unq.value && typeof unq.value === "object") return readEnvelope(unq.value);
    }
    throw new IntakeError("json", `not valid JSON: ${parsed.error.message}`);
  }
  if (s[0] === '"') {
    const unq = tryJson(s.replace(/^"|"$/g, "").replace(/""/g, '"'));
    if (unq.ok && unq.value && typeof unq.value === "object" && !Array.isArray(unq.value)) return readEnvelope(unq.value);
  }
  const rows = parseCsv(s);
  const env = envelopeFromCsv(rows);
  if (env) return env;
  return tableFromRows(rows);
}

export default { parse, parseCsv, IntakeError, ENVELOPE_VERSION, ENVELOPE_COLUMN };
