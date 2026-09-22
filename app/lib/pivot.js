// Generic query renderer for pack edges and pack queries. A pack edge (or a
// query) carries its SPL as data (a list of lines) and this module turns it
// into a search for a set of bound parameters. It is the only place a query
// a user sees is rendered, on both platforms.
//
// The template language is deliberately tiny, so a pack stays data and a
// mistake in one cannot become a different search:
//
//   $name$          the parameter, quoted as an SPL string literal
//   $name:time$     a time modifier (-24h, now, @d, epoch) unquoted when it
//                   looks like one, an ISO stamp as %m/%d/%Y:%H:%M:%S (epoch
//                   seconds when it carries a zone), quoted otherwise
//   $name:qtime$    the same modifier as a quoted string literal: a macro
//                   argument
//   $name:list$     the parameter as a quoted, comma-separated list for an
//                   IN (...) term; the value must be a non-empty array
//                   (PivotError bad_list otherwise: a scalar in a list slot
//                   is a caller's mistake, never silently one-element)
//   $name:field$    the parameter as a field name: an identifier, written
//                   bare (PivotError bad_identifier otherwise); the one
//                   token that lets a caller name a column
//   $name:prefixes$ the parameter, a non-empty list of path prefixes, as a
//                   starts-with-any match: SPL a quoted glob list for an
//                   IN (...) term ("/usr/bin/*", ...), KQL an anchored
//                   verbatim regex literal for matches regex
//   $index$         index=<param index>   (index is a parameter like any other;
//                   a template's index_macro names the macro written when it
//                   is unbound, which then is not a missing parameter)
//   $sourcetype$    sourcetype=<the edge's dst sourcetype>
//
// A line is either a string, rendered always, or { clause, needs: [],
// unless: [] }, rendered only when every `needs` parameter is bound and no
// `unless` parameter is. That is the only conditional. Unbound $name$ in an
// always-line renders as "$name$" ($name$ for a time or field token) and is
// reported in `missing`, so a caller can ask for it; a template's `required`
// list adds parameters a shape needs even if no line mentions them.
//
// A template may also carry:
//
//   guard: { all: [], code, message }   every named parameter must be bound
//                   before anything renders (a placeholder is not enough);
//                   otherwise PivotError(code) naming the unbound ones
//   macro: { lines: [] }   the same search as a macro call, rendered by
//                   generate(edge, params, { form: "macro" }); PivotError
//                   no_macro when there is none, or when a parameter bound
//                   in the inline lines has no token in the macro lines
//                   (index and sourcetype are the macro's own business, and
//                   latest bound to now is the macro's implicit upper bound)
//
// Hazards on an edge or query are pack hazard ids, hazard objects, or
// either with needs / unless gates read against the bound parameters.
//
// No raw substitution, no nesting: a field name in a template is the pack
// author's, or a validated identifier a caller passes to a :field token.
//
//   generate(edge, params, { pack, form }) → { spl, hazards, missing, asserted, form, kind, sourcetype, lang }
//   throws PivotError(code) for a malformed template, a failed guard, a
//   missing macro or a lint failure
//
// An edge carries either `spl` (Splunk) or `kql` (Sentinel) with the same
// { required, lines } shape and the same tokens. In a KQL template:
//
//   $name$          the parameter as a KQL string literal ("…", backslash-escaped)
//   $name:time$     ago(24h) / now() / datetime(…) from -24h, now, an ISO stamp
//   $name:list$     the parameter as a quoted, comma-separated list for in (...)
//   $name:field$    the parameter as a column reference (kql.column)
//   $name:prefixes$ an anchored regex literal, @"^(?:a|b)", every prefix escaped
//   $table$         the edge's dst table name, validated as an identifier
//
// `spl` in the result is the rendered text whichever the language. The
// popups and the drawer read that one key; `lang` says which it is.

import { quote, quoteList, timeModifier } from "./spl.js";
import * as kql from "./kql.js";
import { LANG } from "./lang.js";

export class PivotError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "PivotError";
    this.code = code;
  }
}

// The one placeholder shape and the one bound-ness test: every emitter
// that fills a pack template (SPL, KQL, the FDR bundle's own kinds in
// fdr-queries.js) shares this, so "is this $name$ still open" never
// drifts into a second regex.
export const PLACEHOLDER_RE = /^\$[A-Za-z_][A-Za-z0-9_]*(?::time|:qtime|:list|:field|:prefixes)?\$$/;
const SAFE_INDEX_RE = /^[A-Za-z0-9_\-*]+$/;
const SAFE_SOURCETYPE_RE = /^[A-Za-z0-9_:\-.*]+$/;
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const MACRO_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

// A real value, not empty and not a leftover $name$ token: the one test
// every caller shares, so "still a placeholder" is decided once.
export function isBound(v) {
  if (v === undefined || v === null) return false;
  if (Array.isArray(v)) return v.some(isBound); // blank entries are skipped at render
  const s = String(v).trim();
  return s !== "" && !PLACEHOLDER_RE.test(s);
}

// A list slot takes a non-empty array and nothing else; an array in a
// scalar slot is refused too, so a caller cannot smuggle a list through
// quote() as one comma-joined string. Blank entries are dropped.
function listValue(v, name, quoteAll) {
  if (!Array.isArray(v)) throw new PivotError("bad_list", `$${name}:list$ takes a list of values, not ${typeof v === "string" ? "a string" : typeof v}`);
  return quoteAll(v.filter(isBound));
}

function scalarValue(v, name, quoteOne) {
  if (Array.isArray(v)) throw new PivotError("bad_list", `$${name}$ takes one value; write $${name}:list$ for a list`);
  return quoteOne(v);
}

function fieldValue(v, name) {
  const s = String(scalarValue(v, name, String));
  if (!IDENT_RE.test(s)) throw new PivotError("bad_identifier", `${name} is not a valid identifier: ${s}`);
  return s;
}

// SPL: each prefix quoted with a trailing wildcard, for IN (...).
function splPrefixes(v, name) {
  return listValue(v, name, (values) => quoteList(values.map((p) => `${p}*`)));
}

// KQL: one anchored alternation in a verbatim string, so a backslash in a
// prefix stays a backslash and every regex metacharacter is escaped.
function kqlPrefixes(v, name) {
  return listValue(v, name, (values) => {
    if (!values.length) throw new PivotError("bad_list", `$${name}:prefixes$ needs at least one prefix`);
    const escaped = values.map((p) => String(p).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/"/g, '""'));
    return `@"^(?:${escaped.join("|")})"`;
  });
}

function indexTerm(v) {
  const s = String(v).trim();
  return `index=${SAFE_INDEX_RE.test(s) ? s : quote(s)}`;
}

function sourcetypeTerm(st) {
  return `sourcetype=${SAFE_SOURCETYPE_RE.test(st) ? st : quote(st)}`;
}

function dstSourcetype(edge) {
  return edge.dst && edge.dst.sourcetype ? edge.dst.sourcetype : edge.src.sourcetype;
}

// Every $…$ token in a line, in order.
const TOKEN_RE = /\$([A-Za-z_][A-Za-z0-9_]*)(?::(time|qtime|list|field|prefixes))?\$/g;

function placeholder(name, kind) {
  return kind === "time" || kind === "field" ? `$${name}$` : `"$${name}$"`;
}

function renderLine(text, params, edge, missing, template) {
  return text.replace(TOKEN_RE, (_, name, kind) => {
    if (name === "sourcetype" && !kind) return sourcetypeTerm(dstSourcetype(edge));
    if (name === "index" && !kind) {
      if (isBound(params.index)) return indexTerm(params.index);
      if (template.index_macro) return `index=\`${template.index_macro}\``;
      if (!missing.includes("index")) missing.push("index");
      return "index=$index$";
    }
    const v = params[name];
    if (!isBound(v)) {
      if (!missing.includes(name)) missing.push(name);
      return placeholder(name, kind);
    }
    if (kind === "time") return timeModifier(v);
    if (kind === "qtime") return quote(timeModifier(v).replace(/^"|"$/g, ""));
    if (kind === "list") return listValue(v, name, quoteList);
    if (kind === "field") return fieldValue(v, name);
    if (kind === "prefixes") return splPrefixes(v, name);
    return scalarValue(v, name, quote);
  });
}

function renderKqlLine(text, params, edge, missing) {
  return text.replace(TOKEN_RE, (_, name, kind) => {
    if (name === "table" && !kind) return kql.table(dstSourcetype(edge));
    if (kind === "qtime") throw new PivotError("bad_template", "a KQL template has no $name:qtime$ token");
    const v = params[name];
    if (!isBound(v)) {
      if (!missing.includes(name)) missing.push(name);
      return placeholder(name, kind);
    }
    if (kind === "time") {
      try {
        return kql.timeLiteral(v);
      } catch (err) {
        throw new PivotError("bad_time", err.message);
      }
    }
    if (kind === "list") return listValue(v, name, kql.quoteList);
    if (kind === "field") return kql.column(fieldValue(v, name));
    if (kind === "prefixes") return kqlPrefixes(v, name);
    return scalarValue(v, name, kql.quote);
  });
}

// { clause, needs, unless } for any line; a string is an always-line.
function lineGate(line) {
  if (typeof line === "string") return { clause: line, needs: [], unless: [] };
  const ok = line && typeof line.clause === "string" && (Array.isArray(line.needs) || Array.isArray(line.unless)) && (line.needs === undefined || Array.isArray(line.needs)) && (line.unless === undefined || Array.isArray(line.unless));
  if (!ok) throw new PivotError("bad_template", "a template line is a string or { clause, needs: [], unless: [] }");
  return { clause: line.clause, needs: line.needs || [], unless: line.unless || [] };
}

function gateOpen(gate, params) {
  return gate.needs.every((n) => isBound(params[n])) && !gate.unless.some((n) => isBound(params[n]));
}

function tokenNames(lines) {
  const names = new Set();
  for (const line of lines || []) {
    const text = typeof line === "string" ? line : (line && line.clause) || "";
    for (const m of text.matchAll(TOKEN_RE)) names.add(m[1]);
  }
  return names;
}

export function templateOf(edge) {
  if (edge && edge.kql && Array.isArray(edge.kql.lines)) return { lang: "kql", template: edge.kql };
  if (edge && edge.spl && Array.isArray(edge.spl.lines)) return { lang: "spl", template: edge.spl };
  return null;
}

// The macro lines when they can carry every bound inline parameter, else
// PivotError no_macro. `latest` at now is the macro's implicit upper bound;
// index and sourcetype are inside the macro.
function macroLines(template, params) {
  const macro = template.macro;
  if (!macro || !Array.isArray(macro.lines) || !macro.lines.length) throw new PivotError("no_macro", "this search has no macro form");
  const inline = tokenNames(template.lines);
  const carried = tokenNames(macro.lines);
  const bound = (n) => isBound(params[n]) && !(n === "latest" && String(params[n]).trim().toLowerCase() === "now");
  const dropped = [...inline].filter((n) => n !== "index" && n !== "sourcetype" && bound(n) && !carried.has(n));
  if (dropped.length) throw new PivotError("no_macro", `the macro cannot carry ${dropped.join(", ")}; use the inline form`);
  return macro.lines;
}

// A hazard entry (id, object, or either with needs / unless gates) as the
// { level, text } the drawer shows, or null when the pack knows no such id
// or the gate is shut.
function hazardEntry(ref, params, pack) {
  const hz = (pack && pack.hazards) || {};
  if (ref && typeof ref === "object") {
    const gate = { needs: ref.needs || [], unless: ref.unless || [] };
    if (!gateOpen(gate, params)) return null;
    const h = ref.ref !== undefined ? hz[ref.ref] : ref;
    return h && h.text ? { level: h.level || ref.level || "note", text: h.text } : null;
  }
  const h = typeof ref === "string" ? hz[ref] : null;
  return h && h.text ? { level: h.level || "note", text: h.text } : null;
}

export function generate(edge, params = {}, { pack, form = "inline" } = {}) {
  const t = edge && typeof edge === "object" ? templateOf(edge) : null;
  if (!t) throw new PivotError("bad_edge", "edge needs spl.lines or kql.lines");
  const { lang, template } = t;
  const p = params || {};
  if (template.guard) {
    const g = template.guard;
    const unbound = (g.all || []).filter((n) => !isBound(p[n]));
    if (unbound.length) throw new PivotError(g.code || "guard", `${g.message || "this search needs every scoping parameter bound"} Unbound: ${unbound.join(", ")}.`);
  }
  const macroForm = form === "macro";
  if (macroForm && lang === "kql") throw new PivotError("no_macro", "a KQL search has no macro form");
  const lines = macroForm ? macroLines(template, p) : template.lines;
  const missing = [];
  const out = [];
  for (const line of lines) {
    const gate = lineGate(line);
    if (!gateOpen(gate, p)) continue; // optional clause, param unbound (or bound, for unless): dropped
    const rendered = lang === "kql" ? renderKqlLine(gate.clause, p, edge, missing) : renderLine(gate.clause, p, edge, missing, template);
    if (rendered.trim()) out.push(rendered);
  }
  // `required` also fixes the order a caller asks for them in; tokens no
  // list names follow in the order the lines meet them.
  const required = macroForm ? [] : template.required || [];
  for (const name of required) if (!isBound(p[name]) && !missing.includes(name)) missing.push(name);
  const ordered = [...required.filter((n) => missing.includes(n)), ...missing.filter((n) => !required.includes(n))];

  const hazards = [];
  for (const ref of edge.hazards || []) {
    const h = hazardEntry(ref, p, pack);
    if (h && !hazards.some((x) => x.text === h.text)) hazards.push(h);
  }
  if (edge.basis === "asserted" || edge.basis === "proposed") {
    hazards.unshift({ level: "asserted", text: `${(edge.note || edge.label || "").trim()} ${edge.basis === "proposed" ? "Proposed by discovery, not confirmed." : "Asserted from the data model, not corpus-validated."}`.trim() });
  }

  const text = out.join("\n");
  const verdict = LANG[lang].lint(text, { commands: (pack && pack.commands) || [], macros: (pack && pack.macros) || [] });
  if (!verdict.ok) {
    const err = new PivotError("lint", `generated ${lang.toUpperCase()} failed lint: ${verdict.violations.join("; ")}`);
    err.violations = verdict.violations;
    throw err;
  }
  for (const w of verdict.warnings || []) hazards.push({ level: "note", text: w });
  return {
    spl: text,
    lang,
    hazards,
    missing: ordered,
    asserted: edge.basis !== "confirmed" && edge.basis !== "validated",
    form: macroForm ? "macro" : "inline",
    kind: "edge",
    sourcetype: dstSourcetype(edge),
  };
}

// Sanity check a pack's edges at load time: every template renders with
// every parameter bound to a dummy value and passes lint; a macro form
// renders with its own parameters bound. Returns [errors].
export function validatePack(pack) {
  const errors = [];
  for (const edge of pack.edges || []) {
    try {
      const t = templateOf(edge) || { lang: "spl", template: {} };
      const template = t.template;
      if (template.index_macro !== undefined && !MACRO_NAME_RE.test(String(template.index_macro))) throw new PivotError("bad_template", `index_macro is not a macro name: ${template.index_macro}`);
      if (template.guard !== undefined && (!template.guard || !Array.isArray(template.guard.all))) throw new PivotError("bad_template", "guard needs all: [param names]");
      if (template.macro !== undefined && (!template.macro || !Array.isArray(template.macro.lines))) throw new PivotError("bad_template", "macro needs lines: []");
      const times = new Set();
      const dummyFor = (names, lists) => {
        const dummy = {};
        for (const n of names) dummy[n] = n === "index" ? "main" : n === "table" ? "" : lists.has(n) ? ["x"] : times.has(n) || /earliest|latest|since|until/.test(n) ? "-24h" : "x";
        return dummy;
      };
      const scan = (lines, names, lists) => {
        for (const line of lines || []) {
          const gate = lineGate(line);
          for (const m of gate.clause.matchAll(TOKEN_RE)) {
            names.add(m[1]);
            if (m[2] === "list" || m[2] === "prefixes") lists.add(m[1]);
            if (m[2] === "time" || m[2] === "qtime") times.add(m[1]);
          }
          for (const n of [...gate.needs, ...gate.unless]) names.add(n);
        }
      };
      const names = new Set([...(t.lang === "spl" ? ["index"] : []), ...(template.required || []), ...((template.guard && template.guard.all) || [])]);
      const lists = new Set();
      scan(template.lines, names, lists);
      generate(edge, dummyFor(names, lists), { pack });
      if (template.macro) {
        // The macro's own tokens, plus the guard's parameters: a guarded
        // latest the macro does not carry sits at now, its implicit bound.
        const macroNames = new Set();
        scan(template.macro.lines, macroNames, lists);
        const dummy = dummyFor(macroNames, lists);
        for (const n of (template.guard && template.guard.all) || []) if (!macroNames.has(n)) dummy[n] = n === "latest" ? "now" : "x";
        generate(edge, dummy, { pack, form: "macro" });
      }
    } catch (err) {
      errors.push(`${edge.id || "(no id)"}: ${err.message}`);
    }
  }
  return errors;
}

export default { generate, validatePack, templateOf, PivotError, PLACEHOLDER_RE, isBound };
