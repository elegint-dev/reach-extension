// The efficiency class of a field: what a filter on it costs the platform,
// derived from how the field comes to exist. Every consumer that decides
// whether a term narrows the scan reads it from here: the ladder gates
// TERM() on it, the field page shows it as a chip, the advisor names it in
// a finding.
//
//   classify({ column, platform, provenance, binding, layer, declared, profile, props, derived, resolve }) -> Class
//   classOf(view, { platform, resolve })   -> Class, from a catalogue.fieldOn() view
//   CLASSES, LABELS, ADVICE
//
// Class: { class, label, evidence: [string], advice, source, cite, termable }
//   class     indexed | raw_token | search_time | calculated | lookup_output | pipeline_derived
//             (the same strings ladder.js reads as fieldClass)
//   evidence  one line per fact the class rests on
//   advice    the cheapest filter on this field, one line
//   source    platform | pack | discovery | schema | layer | default   which input decided
//   termable  TERM() can carry a bare value on this class
//
// Inputs, each optional:
//   provenance  discovery.provenance()'s list for the field: [{ kind: alias | calculated |
//               lookup | lookup_key | extracted, from?, regex?, transform?, ... }]
//   binding     the pack binding with its sidecar provenance { kind: indexed | extracted |
//               alias | calculated | lookup | connector }
//   layer       the FDR bundle's layer for the field: raw_fdr | ta_derived | cim
//   declared    Sentinel: the column's declared schema type { type }; a dotted column is a
//               path into a dynamic column
//   props       the sourcetype's props stanza { indexed_extractions?, kv_mode? } when read
//   derived     true when the field exists only after a stage in the search
//   resolve     (name) -> the same inputs for another field on the container, for an
//               alias chain; a chain is followed at most ALIAS_DEPTH steps
//
// Precedence follows Splunk's search-time order (extraction, alias,
// calculated field, lookup): the last writer wins, so a lookup output
// outranks a calculated field, which outranks an alias, which outranks an
// extraction. A pack binding's declared provenance stands in when discovery
// has not run; the platform's own fields are indexed on every install.
//
// Plain ES module. No DOM, no store, no network.

export const CLASSES = Object.freeze(["indexed", "raw_token", "search_time", "calculated", "lookup_output", "pipeline_derived"]);

export const LABELS = Object.freeze({
  indexed: "indexed",
  raw_token: "raw token",
  search_time: "search-time",
  calculated: "calculated",
  lookup_output: "lookup output",
  pipeline_derived: "pipeline-derived",
});

export const ADVICE = Object.freeze({
  spl: {
    indexed: "field=value in the search block: answered from the index alone, no event is read",
    raw_token: "field=value in the search block; the value is a raw token, so TERM(value) can read it from the lexicon whole",
    search_time: "field=value in the search block: the value's own tokens narrow the scan before the field is extracted; avoid a leading wildcard, which cannot use the lexicon",
    calculated: "narrow with an indexed field or a raw token first; a test on this field runs the EVAL on every event the scan returns",
    lookup_output: "narrow with an indexed field or a raw token first, or filter on the lookup's input field; a test on this field runs the lookup on every event the scan returns",
    pipeline_derived: "the field exists only after the stage that derives it: filter on it with | search or | where after that stage, and narrow the search block on something indexed first",
  },
  kql: {
    indexed: "where column == value, or column has value: the column is materialised and the term index answers it",
    raw_token: "where column has value: the term index answers a whole term; contains scans every value",
    search_time: "the column is a path into a dynamic column: parsed on every row, no term index; narrow on a materialised column first and compare with tostring()",
    calculated: "the column is computed on every row; narrow on a materialised column first",
    lookup_output: "the column comes from a lookup joined at query time; narrow on a materialised column first",
    pipeline_derived: "the column exists only after the stage that derives it: put the where after that stage, and narrow on a materialised column before it",
  },
});

export const PLATFORM_FIELDS = Object.freeze({
  spl: ["index", "sourcetype", "source", "host", "splunk_server", "punct", "linecount", "_time", "_indextime"],
  kql: ["TimeGenerated", "Type", "TenantId", "_ResourceId", "SourceSystem", "Computer"],
});

const ALIAS_DEPTH = 4;
const KIND_RANK = { lookup: 4, calculated: 3, alias: 2, extracted: 1 };

function norm(platform) {
  return platform === "kql" || platform === "sentinel" ? "kql" : "spl";
}

function done(cls, platform, evidence, source, extra = {}) {
  const c = CLASSES.includes(cls) ? cls : "search_time";
  return { class: c, label: LABELS[c], evidence, advice: ADVICE[platform][c], source, cite: extra.cite || null, termable: platform === "spl" && (c === "indexed" || c === "raw_token") };
}

// The strongest declaring entry in a discovery provenance list, by
// search-time order.
function strongest(list) {
  let best = null;
  for (const p of list || []) {
    if (!p || !KIND_RANK[p.kind]) continue;
    if (!best || KIND_RANK[p.kind] > KIND_RANK[best.kind]) best = p;
  }
  return best;
}

function fromDiscovery(prov, platform, column, resolve, depth) {
  const p = strongest(prov);
  if (!p) return null;
  const where = p.attribute ? ` (${p.attribute})` : "";
  if (p.kind === "lookup") return done("lookup_output", platform, [`written by the lookup ${p.transform || ""}${where} at search time`.replace("  ", " ")], "discovery");
  if (p.kind === "calculated") return done("calculated", platform, [`computed by an EVAL${where} at search time${p.refs && p.refs.length ? `, from ${p.refs.join(", ")}` : ""}`], "discovery");
  if (p.kind === "alias") {
    const from = p.from;
    const ev = [`an alias of ${from || "another field"}${where}`];
    if (from && from !== column && typeof resolve === "function" && depth < ALIAS_DEPTH) {
      const src = resolve(from);
      if (src) {
        const inner = classify({ ...src, column: from, platform, resolve, _depth: depth + 1 });
        return { ...inner, evidence: [...ev, ...inner.evidence], source: "discovery", advice: inner.advice };
      }
    }
    if (PLATFORM_FIELDS[platform].includes(from)) return done("indexed", platform, [...ev, `${from} is indexed on every install`], "discovery");
    return done("search_time", platform, [...ev, "the source field's own class is not known here"], "discovery");
  }
  // extracted
  const via = p.transform ? `REPORT- transform ${p.transform}` : "an EXTRACT- regex";
  return done("search_time", platform, [`extracted by ${via}${where} at search time: the value's tokens are in the raw event, the field name is not`], "discovery");
}

function fromBinding(binding, platform) {
  const prov = binding && binding.provenance;
  if (!prov || !prov.kind) return null;
  const cite = prov.cite || null;
  const stmt = prov.statement ? `: ${prov.statement}` : "";
  switch (prov.kind) {
    case "indexed": return done("indexed", platform, [`the pack declares it indexed${stmt}`], "pack", { cite });
    case "extracted": return done(platform === "kql" ? "search_time" : "raw_token", platform, [`the pack declares it extracted from the raw event${stmt}`], "pack", { cite });
    case "alias": return done("search_time", platform, [`the pack declares it an alias${stmt}`], "pack", { cite });
    case "calculated": return done("calculated", platform, [`the pack declares it calculated${stmt}`], "pack", { cite });
    case "lookup": return done("lookup_output", platform, [`the pack declares it a lookup output${stmt}`], "pack", { cite });
    case "connector": return done("indexed", platform, [`the pack declares the connector writes it as a column${stmt}`], "pack", { cite });
    default: return null;
  }
}

function fromLayer(layer, platform) {
  if (layer === "raw_fdr" || layer === "L1") return done("raw_token", platform, ["a raw feed field: KV_MODE json reads it out of the event, and its value is a token in _raw"], "layer");
  if (layer === "ta_derived" || layer === "L2") return done("calculated", platform, ["the TA derives it: an EVAL at search time, not a value in the raw event"], "layer");
  if (layer === "cim" || layer === "L3") return done("search_time", platform, ["a CIM name the TA maps at search time (alias or EVAL)"], "layer");
  return null;
}

function fromSchema(declared, column) {
  if (!declared && !column) return null;
  const dotted = typeof column === "string" && column.includes(".");
  const type = declared && declared.type ? String(declared.type).toLowerCase() : null;
  if (dotted || type === "dynamic") {
    return done("search_time", "kql", [dotted ? `${column} is a path into a dynamic column: parsed on every row` : "declared dynamic: parsed on every row"], "schema");
  }
  if (type) return done("indexed", "kql", [`declared ${type}: a materialised column with a term index`], "schema");
  return null;
}

export function classify(input = {}) {
  const platform = norm(input.platform);
  const column = input.column || input.field || input.name || "";
  const depth = input._depth || 0;
  if (input.derived) return done("pipeline_derived", platform, ["derived by a stage in this search"], "default");
  if (PLATFORM_FIELDS[platform].includes(column)) return done("indexed", platform, [`${column} is ${platform === "spl" ? "indexed on every install" : "a materialised column on every table"}`], "platform");
  if (platform === "kql") {
    const s = fromSchema(input.declared, column) || fromBinding(input.binding, platform);
    if (s) return s;
    return done("indexed", platform, ["no schema read yet: a plain column name is taken as materialised"], "default");
  }
  const d = fromDiscovery(input.provenance, platform, column, input.resolve, depth);
  if (d) return d;
  const props = input.props || {};
  if (props.indexed_extractions) return done("indexed", platform, [`INDEXED_EXTRACTIONS = ${props.indexed_extractions} on the sourcetype: fields are written at index time`], "discovery");
  const b = fromBinding(input.binding, platform);
  if (b) return b;
  const l = fromLayer(input.layer, platform);
  if (l) return l;
  const kv = props.kv_mode ? String(props.kv_mode).toLowerCase() : null;
  if (kv && kv !== "none") return done("raw_token", platform, [`KV_MODE = ${kv} on the sourcetype and no stanza declares the field: read out of the raw event`], "discovery");
  if (input.profile) return done("raw_token", platform, ["seen by the profile with no declaring stanza: automatic key=value extraction reads it out of the raw event"], "default");
  return done("search_time", platform, ["no provenance recorded: run Provenance on the sourcetype to learn how it is produced"], "default");
}

// From a catalogue.fieldOn() view, with the container's other fields
// reachable for an alias chain.
export function classOf(view, { platform, resolve, layer, props } = {}) {
  if (!view) return classify({ platform });
  return classify({
    column: view.name,
    platform,
    provenance: view.provenance,
    binding: view.binding,
    declared: view.declared,
    profile: view.profile,
    layer: layer || (view.pack && view.pack.layer) || null,
    props: props || view.props || null,
    resolve: resolve ? (n) => { const v = resolve(n); return v ? { provenance: v.provenance, binding: v.binding, declared: v.declared, profile: v.profile, layer: v.pack && v.pack.layer } : null; } : undefined,
  });
}

export default { classify, classOf, CLASSES, LABELS, ADVICE, PLATFORM_FIELDS };
