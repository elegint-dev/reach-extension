// Splunk macros.conf definitions for the crowdstrike-falcon pack's macro
// allowlist (cs_index, cs_trace_process, cs_process_table, cs_pid_lookup,
// cs_process_events). Every definition but cs_index is derived from the
// same inline query template fdr-queries.js renders (packs.query's spl),
// by rendering it once with a placeholder bound to each of the macro's
// own arguments and folding the placeholders back into $name$ tokens, so
// the macro and the inline form can never drift apart on the body text.
// cs_index is the one macro the pack cannot supply a body for: its
// definition is the scope index this pivot resolved, or a placeholder the
// analyst edits by hand.
//
//   argsFor(name) → [arg, ...] | null        the macro's own parameters, call order
//   definitionFor(name, { resolvedIndex }) → string | null
//   stanzaName(name) → "name" | "name(N)"    the Search-macros form's Name field
//   uiFields(name, { resolvedIndex }) → { name, args, definition } | null
//   confStanza(name, { resolvedIndex }) → the macros.conf [stanza] text | null
//   macrosConfText(names, { resolvedIndex }) → every named stanza, blank-line separated
//
// No DOM. Read-only against packs/pivot: never throws on an unknown name.

import * as packs from "./packs.js";
import * as pivot from "./pivot.js";

const PACK_ID = "crowdstrike-falcon";

// Which query's own template supplies a macro's body: the query whose
// `macro.lines` calls that name (falcon_queries.py's macro= lines).
const SOURCE_QUERY = Object.freeze({
  cs_trace_process: "cs_trace",
  cs_process_table: "cs_process_table",
  cs_pid_lookup: "cs_pid_lookup",
  cs_process_events: "cs_process_events",
});

// Three placeholders cover every macro's arity (the widest is 3: field,
// value, earliest). Gibberish, so a real value can never collide with one.
const SENTINELS = ["REACHMACROARGONE", "REACHMACROARGTWO", "REACHMACROARGTHREE"];

// The macro call's own argument names, in order, from its one backtick
// line: `` `cs_pid_lookup($aid$, $pid$, $earliest:qtime$)` `` → [aid, pid, earliest].
function parseArgs(line) {
  const m = /\(([^)]*)\)`\s*$/.exec(String(line || "").trim());
  if (!m) return null;
  const inner = m[1].trim();
  if (!inner) return [];
  return inner.split(",").map((tok) => {
    const stripped = tok.trim().replace(/^"|"$/g, "");
    const nm = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(stripped);
    return nm ? nm[1] : null;
  });
}

function macroLine(qid) {
  const q = packs.query(PACK_ID, qid);
  return q && q.spl && q.spl.macro && q.spl.macro.lines && q.spl.macro.lines[0];
}

export function argsFor(name) {
  if (name === "cs_index") return [];
  const qid = SOURCE_QUERY[name];
  if (!qid) return null;
  const line = macroLine(qid);
  if (!line) return null;
  const args = parseArgs(line);
  return args && args.every(Boolean) ? args : null;
}

// The scope index this pivot resolved, else the placeholder text: the only
// line macroDefineHint (field.js) and this module need to agree on.
export function csIndexDefinition(resolvedIndex) {
  return resolvedIndex ? `index=${resolvedIndex}` : "index=<your index>";
}

export function definitionFor(name, { resolvedIndex } = {}) {
  if (name === "cs_index") return csIndexDefinition(resolvedIndex);
  const qid = SOURCE_QUERY[name];
  const args = argsFor(name);
  if (!qid || !args || !args.length) return null;
  const q = packs.query(PACK_ID, qid);
  const pack = packs.pack(PACK_ID);
  if (!q || !pack) return null;
  const params = {};
  args.forEach((a, i) => {
    params[a] = SENTINELS[i];
  });
  // A required-mode query's head always carries a latest clause (it is
  // never conditional the way earliest-only mode is); the macro's own
  // implicit upper bound is "now" (pivot.js: "latest bound to now is the
  // macro's implicit upper bound"). An earliest-only query (cs_trace) has
  // no latest slot at all, so nothing is bound here for it.
  if ((q.spl.required || []).includes("latest")) params.latest = "now";
  let out;
  try {
    out = pivot.generate(q, params, { pack });
  } catch {
    return null;
  }
  let text = out.spl;
  args.forEach((a, i) => {
    text = text.split(SENTINELS[i]).join(`$${a}$`);
  });
  return text;
}

export function stanzaName(name) {
  const args = argsFor(name);
  return args && args.length ? `${name}(${args.length})` : name;
}

export function uiFields(name, opts = {}) {
  const args = argsFor(name);
  const definition = definitionFor(name, opts);
  if (args === null || definition === null) return null;
  return { name: stanzaName(name), args: args.join(", "), definition };
}

function confEscape(definition) {
  // macros.conf's multi-line values continue with a trailing backslash;
  // the Search-macros form's own Definition field takes the raw text.
  return String(definition).split("\n").join(" \\\n");
}

export function confStanza(name, opts = {}) {
  const fields = uiFields(name, opts);
  if (!fields) return null;
  const lines = [`[${fields.name}]`];
  if (fields.args) lines.push(`args = ${fields.args}`);
  lines.push(`definition = ${confEscape(fields.definition)}`);
  lines.push("iseval = 0");
  return lines.join("\n");
}

export function macrosConfText(names, opts = {}) {
  return names
    .map((n) => confStanza(n, opts))
    .filter(Boolean)
    .join("\n\n");
}

export default { argsFor, definitionFor, csIndexDefinition, stanzaName, uiFields, confStanza, macrosConfText };
