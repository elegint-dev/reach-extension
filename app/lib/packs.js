// Packs: curated knowledge for one feed, as data. A pack contributes to the
// catalogue (what fields mean, their roles, decode tables) and to the pivot
// graph (edges with query templates rendered by pivot.js).
//
// A pack is keyed by concept: the feed is described once, and bindings
// say which column carries each concept on each platform (concepts.js is
// the resolver). Every read below takes (sourcetype, field) and answers
// for the platform this page is on (platform.js), so the popups and the
// app see one shape.
//
// Version 2:
//   {
//     "format": "reach-pack", "version": 2, "id", "name", "pack_version", "description", "source",
//     "commands": ["dedup"], "macros": [],           extra lint allowances for this pack's queries
//     "params": { "<name>": { "label", "placeholder", "hint", "from_concept": "<concept id>", "from_field": "<column>",
//                             "platform": { "sentinel": { "hint", "placeholder" } } } },
//                                                    from_concept resolves to the column bound on the container in hand;
//                                                    from_field names a column outright, for an input that is a column
//                                                    under a shorter name where no concept fits (held.js treats the two as
//                                                    one fact); platform.<name> overrides the words for one SIEM
//     "hazards": { "<id>": { "level", "text", "platform": { "sentinel": { "text" } } } },
//                                                    the taxonomy's hazards are also available by id
//     "feed": { "id", "label", "description", "tags": [], "discriminator": "<concept id>" },
//     "concepts": { "<id>": { "label", "type": "<taxonomy type>", "description", "notes", "role", "tags": [],
//                             "sensitivity", "cim", "hazards": ["<id>"],
//                             "decode": { "lookup", "meaning_field", "values": {}, "flags"? },
//                             "format", "shape", "examples": [], "values": {}, "provenance", "cite", "quote" } },
//                                                    the dictionary keys (values.js): what the values look like and mean,
//                                                    with provenance and a citation; a bundled pack keeps them in a
//                                                    sidecar app/packs/<id>.values.json, fetched on demand (values.loadFor)
//     "containers": { "<name>": { "platform": "splunk|sentinel", "kind": "vendor|custom|sample", "description", "tags": [], "note",
//                                 "hazards": ["<id>"] } },           carried by every pivot on this container, compiled or templated
//     "bindings": [ { "platform", "container", "column", "concept": "<id>" | "<pack>/<id>",
//                     "note", "alias_of": "<column>", "basis", "basis_ref", "cim",
//                     "encoding": "json_string",       the column's head is a JSON string, the dotted rest a path into it
//                     "provenance": { "kind": "indexed|extracted|alias|calculated|lookup|connector", "statement", "cite" } } ],
//                                                    how the column comes to carry the concept on that platform (values.js)
//     "edges": [ { "id", "kind", "label", "src": { "concept" }, "dst": { "concept" } | { "type": "<taxonomy type>" },
//                  "basis", "basis_ref", "cardinality", "scope": [], "hazards": [], "note",
//                  "intent": { ... } } ],                 what the pivot means, in concepts (intent.js); compiled per
//                                                    container by compile-spl.js / compile-kql.js where no template exists
//     "templates": [ { "edge": "<id>" | "<pack>/<id>", "container", "label", "hazards": [],
//                      "spl" | "kql": { "required": [], "lines": [] } } ],
//                                                    a query written against one destination container; it wins
//                                                    over the edge's intent on that container
//     "queries": [ { "id", "label", "note", "containers": [sourcetype...], "hazards": [],
//                    "spl" | "kql": { "required": [], "lines": [], "index_macro", "guard", "macro", "containers", "hazards" } } ],
//                                                    a named search that is not a hop between bound columns (a
//                                                    workflow's step, a lookup, an event sample); it runs on any of
//                                                    its containers, which need not be bound by the pack, and is
//                                                    rendered by pivot.generate through query() below; the hazards
//                                                    may carry needs / unless gates (pivot.js). A query written in
//                                                    both languages (a hunt with a KQL twin) carries spl and kql,
//                                                    each naming its own containers and hazards; query() picks
//                                                    this platform's
//     "lists": { "<name>": { "note", "source", "values": [string] } },
//                                                    data a workflow result hands a query as a parameter
//                                                    ("<param>": "@<name>"), generated into the pack by a tool
//     "workflows": [ { "id", "title", "kicker", "when", "lead", "value_link": true,
//                                                    value_link: the page links the bound value to the value page
//                      "entries": [ { "concept", "param" } | { "container", "column", "param" } ],
//                                                    where the popups offer it; the clicked value binds to param. A
//                                                    concept entry lands on every column bound to it on this platform;
//                                                    a column entry names one column on a container the pack declares
//                      "steps": [ { "title", "why", "help", "required", "names": [param], "optional": [param], "gate": true } ],
//                                                    gate: the workflow's gate question is asked under this step
//                      "expect", "disambiguate": [], "troubleshooting": [ { "symptom", "causes": [] } ],
//                      "gate": { "param", "ask", "blocked",        a question the data cannot answer; the analyst's
//                                "choices": [ { "value", "label", "emits": bool,   answer is the param, and a gated result
//                                               "callout": { "kind", "label", "body",   emits its search only for a
//                                                            "link": { "text", "workflow", "carry": {} } } } ] },   choice that emits
//                      "results": [ { "id", "label", "note", "caution",
//                                     "edge": "<edge id>" | "query": "<query id>" | "join": "<fields sidecar edge id>",
//                                                    join: an edge of the pack's fields sidecar (pack-fields.js), rendered
//                                                    by fdr-queries.js once the sidecar is loaded; no pivot before that
//                                     "params": { "<edge param>": "$<workflow param>" | "@<list>" | literal },
//                                     "gate": true, "choices": { "<gate value>": { "query" | "edge" | "join", "params" } },
//                                                    a gated result takes its search from the answer; no answer, no search
//                                     "shape": { "columns": [ { "key", "label", "role": "host" | "value" | "time" | "count", "field" } ] } } ],
//                                                    shape: how a run's rows read (views/workflow.js), for a
//                                                    result the app can run through the discovery relay; a
//                                                    column with a field opens the value page on that field
//                      "hunt": { "schedule": "..." },  a workflow meant to be saved as a scheduled search: the
//                                                    page offers Save as scheduled alert with this wording
//                      "chain": { "workflow": "<id>", "text", "why", "carry": { "<their param>": "$<my param>" } } } ]
//   }
//
// A pack loads on both platforms (its bindings span them). A pack's
// per-field catalogue (the records a vendor's add-on lands, the record
// types, the join graph) is its fields sidecar, app/packs/<id>.fields.json,
// listed in index.json under "fields" and read per container by
// pack-fields.js; load() does not fetch it.
//
//   await load()                     bundled packs from app/packs/index.json (and the taxonomy); the values
//                                    sidecars the index lists are not read here (values.loadFor, per container)
//   list()                           → [{ id, name, pack_version, description, source, sourcetypes, fields, edges, workflows, version, feed }]
//   pack(id)                         → the raw pack
//   sourcetype(st)                   → { packId, description, discriminator, tags, feed } | null
//   field(st, name)                  → { packId, description, notes, role, tags, sensitivity, cim, concept?, binding?, hazards?,
//                                        dictionary?, bindingProvenance? } | null
//                                    dictionary: values.dictionary(), once the sidecar is loaded; bindingProvenance:
//                                    the binding's provenance, from the pack or the sidecar
//   fieldsOn(st)                     → [names]
//   decode(st, name)                 → { lookup, meaning_field, values, packId } | null
//   edgesFrom(st, name) / edgesTo(st, name) / edgesOn(st) → [edge with packId], edges resolved for this platform;
//                                    a view compiled from intent carries compiled: true beside its spl | kql
//   edge(packId, id)                 → one resolved edge (the first this platform can render) | null
//   query(packId, id, { container }) → a pack query shaped for pivot.generate, on one of its containers
//                                    (the first by default) | null
//   discriminators()                 → { st: field }
//   paramMeta(packId, name, container?) / params(packId, container?)   from_concept resolved to from_field
//   lintOptions(packId)              → { commands, macros }
//   fieldParams()                    → [{ name, column }] every pack input named as a column (from_field)
//   workflows()                      → [workflow with packId and resolved entries], every pack
//   workflow(id)                     → workflow with packId | null
//   replace(pack)                    validate, set or replace the pack in the Map, rebuild the resolver
//   remove(id)                       drop a pack and rebuild the resolver
//   generation()                     → counter moved by register, replace, remove and _reset; memos compare on it
//
// The learned pack (learned.js, id "learned": the user's own bindings,
// no concepts) is registered through replace() after every change to the
// user layer. It is re-indexed last whatever its slot in the Map, so a
// bundled pack binding the same triple wins in concepts.resolve(), and
// list() leaves it out: it is not a feed.
//
// No DOM. Safe from a content script.

import { validatePack } from "./pivot.js";
import { PLATFORM } from "./platform.js";
import * as concepts from "./concepts.js";
import * as taxonomy from "./taxonomy.js";
import * as intent from "./intent.js";
import * as compileSpl from "./compile-spl.js";
import * as compileKql from "./compile-kql.js";
import { LEARNED_ID } from "./learned.js";
import * as values from "./values.js";

export const FORMAT = "reach-pack";
export const VERSION = 2;

const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);
const PLATFORMS = ["splunk", "sentinel"];
const packs = new Map(); // id → pack
let loaded = false;
let edgeMemo = null; // resolved edges for this platform, rebuilt after register()
let gen = 0; // bumped by register(), replace(), remove() and _reset(): a memo over the resolver compares on it

function fileUrl(name) {
  return new URL(`../packs/${name}`, import.meta.url).href;
}

async function getJson(name) {
  const res = await fetch(fileUrl(name));
  if (!res.ok) throw new Error(`app/packs/${name}: HTTP ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Validation

function commonChecks(pack, errors) {
  if (pack.format !== FORMAT) errors.push(`format must be ${FORMAT}`);
  if (pack.version !== VERSION) errors.push(`version must be ${VERSION}`);
  if (!pack.id || !/^[a-z0-9][a-z0-9-]*$/.test(pack.id)) errors.push("id must be lowercase letters, digits and dashes");
  if (!pack.name) errors.push("name is required");
  if (pack.platform !== undefined && !PLATFORMS.includes(pack.platform)) errors.push("platform must be splunk or sentinel");
}

function objOfFactory(errors) {
  return (v, what) => {
    if (v === undefined) return true;
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      errors.push(`${what} must be an object`);
      return false;
    }
    for (const k of Object.keys(v)) if (UNSAFE.has(k)) errors.push(`${what}: unsafe key "${k}"`);
    return true;
  };
}

function namesOfFactory(errors) {
  return (v, what) => {
    if (v === undefined) return;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string" || !x)) errors.push(`${what} must be an array of names`);
  };
}

function checkCim(cim, what, errors, objOf, namesOf) {
  if (cim === undefined || !objOf(cim, what)) return;
  namesOf(cim.data_models, `${what}.data_models`);
  namesOf(cim.from, `${what}.from`);
  namesOf(cim.targets, `${what}.targets`);
  if (!cim.data_models && !cim.targets) errors.push(`${what} needs data_models or targets`);
}

function checkWorkflows(pack, errors, edgeIds, queryIds, entryCheck) {
  const namesOf = namesOfFactory(errors);
  if (pack.workflows !== undefined && !Array.isArray(pack.workflows)) errors.push("workflows must be an array");
  const wids = new Set();
  const list = Array.isArray(pack.workflows) ? pack.workflows : [];
  for (const w of list) {
    if (!w || typeof w !== "object") { errors.push("workflow must be an object"); continue; }
    if (!w.id || !/^[a-z0-9][a-z0-9_-]*$/.test(w.id)) errors.push(`workflow ${w.id || "?"}: id must be lowercase letters, digits, dashes, underscores`);
    else if (wids.has(w.id)) errors.push(`duplicate workflow id ${w.id}`);
    wids.add(w.id);
    if (!w.title) errors.push(`workflow ${w.id}: title is required`);
    if (!Array.isArray(w.steps) || !w.steps.length) errors.push(`workflow ${w.id}: steps must be a non-empty array`);
    for (const st of Array.isArray(w.steps) ? w.steps : []) {
      if (!st || typeof st !== "object" || !st.title) { errors.push(`workflow ${w.id}: every step needs a title`); continue; }
      namesOf(st.names, `workflow ${w.id}: step "${st.title}" names`);
      namesOf(st.optional, `workflow ${w.id}: step "${st.title}" optional`);
      for (const n of st.names || []) if (!(pack.params && pack.params[n])) errors.push(`workflow ${w.id}: step param ${n} is not declared in params`);
    }
    if (!Array.isArray(w.results) || !w.results.length) errors.push(`workflow ${w.id}: results must be a non-empty array`);
    const gateValues = new Set(w.gate && Array.isArray(w.gate.choices) ? w.gate.choices.map((c) => c && c.value) : []);
    // What a result (or one of a gated result's choices) runs: one of an
    // edge, a query or a sidecar join.
    const checkTarget = (t, where) => {
      const named = ["edge", "query", "join"].filter((k) => t[k] !== undefined);
      if (named.length > 1) errors.push(`${where} names more than one of edge, query and join`);
      else if (t.query !== undefined) { if (!queryIds.has(t.query)) errors.push(`${where} names unknown query ${t.query}`); }
      else if (t.join !== undefined) { if (typeof t.join !== "string" || !t.join) errors.push(`${where} join must be an edge id of the fields sidecar`); }
      else if (!t.edge || !edgeIds.has(t.edge)) errors.push(`${where} names unknown edge ${t.edge}`);
      if (t.params !== undefined && (!t.params || typeof t.params !== "object" || Array.isArray(t.params))) errors.push(`${where} params must be an object`);
      for (const v of Object.values(t.params || {})) {
        if (typeof v === "string" && v.startsWith("@") && !(pack.lists && Object.prototype.hasOwnProperty.call(pack.lists, v.slice(1)) && !UNSAFE.has(v.slice(1)))) errors.push(`${where} names unknown list ${v}`);
      }
    };
    const rids = new Set();
    for (const r of Array.isArray(w.results) ? w.results : []) {
      if (!r || typeof r !== "object" || !r.id) { errors.push(`workflow ${w.id}: every result needs an id`); continue; }
      if (rids.has(r.id)) errors.push(`workflow ${w.id}: duplicate result id ${r.id}`);
      rids.add(r.id);
      const where = `workflow ${w.id}: result ${r.id}`;
      if (r.gate === true) {
        if (!w.gate) errors.push(`${where} is gated but the workflow has no gate`);
        if (!r.choices || typeof r.choices !== "object" || Array.isArray(r.choices) || !Object.keys(r.choices).length) errors.push(`${where} needs choices keyed by the gate's values`);
        else for (const [value, t] of Object.entries(r.choices)) {
          if (UNSAFE.has(value) || !gateValues.has(value)) errors.push(`${where} choice ${value} is not a value of the gate`);
          else if (!t || typeof t !== "object") errors.push(`${where} choice ${value} must be an object`);
          else checkTarget(t, `${where} choice ${value}`);
        }
      } else checkTarget(r, where);
      if (r.caution !== undefined && (typeof r.caution !== "string" || !r.caution)) errors.push(`${where} caution must be a non-empty string`);
      if (r.shape !== undefined && (!r.shape || !Array.isArray(r.shape.columns) || !r.shape.columns.length || r.shape.columns.some((c) => !c || typeof c.key !== "string" || !c.key || (c.field !== undefined && typeof c.field !== "string")))) errors.push(`${where} shape needs columns with a key (and a field name where a cell opens the value page)`);
    }
    if (w.gate !== undefined) {
      const g = w.gate;
      const where = `workflow ${w.id}: gate`;
      if (!g || typeof g !== "object" || Array.isArray(g)) errors.push(`${where} must be an object`);
      else {
        if (typeof g.param !== "string" || !g.param || UNSAFE.has(g.param)) errors.push(`${where} needs a param`);
        if (typeof g.ask !== "string" || !g.ask) errors.push(`${where} needs an ask`);
        if (typeof g.blocked !== "string" || !g.blocked) errors.push(`${where} needs the blocked wording`);
        if (!Array.isArray(g.choices) || !g.choices.length) errors.push(`${where} needs choices`);
        for (const c of Array.isArray(g.choices) ? g.choices : []) {
          if (!c || typeof c !== "object" || typeof c.value !== "string" || !c.value || typeof c.label !== "string" || !c.label) { errors.push(`${where}: every choice needs a value and a label`); continue; }
          if (typeof c.emits !== "boolean") errors.push(`${where}: choice ${c.value} needs emits true or false`);
          if (!c.callout || typeof c.callout !== "object" || !c.callout.kind || !c.callout.label || !c.callout.body) errors.push(`${where}: choice ${c.value} needs a callout with kind, label and body`);
          const link = c.callout && c.callout.link;
          if (link !== undefined && (!link || typeof link !== "object" || !link.text || typeof link.workflow !== "string" || (link.carry !== undefined && (!link.carry || typeof link.carry !== "object")))) errors.push(`${where}: choice ${c.value} link needs text and a workflow`);
        }
        if (!(Array.isArray(w.steps) && w.steps.some((st) => st && st.gate === true))) errors.push(`${where} is asked under no step (a step needs gate: true)`);
      }
    } else if (Array.isArray(w.steps) && w.steps.some((st) => st && st.gate === true)) errors.push(`workflow ${w.id}: a step asks a gate the workflow does not have`);
    if (w.value_link !== undefined && w.value_link !== true) errors.push(`workflow ${w.id}: value_link is true or absent`);
    for (const e of Array.isArray(w.entries) ? w.entries : []) entryCheck(w, e);
    if (w.chain && (!w.chain.workflow || typeof w.chain.workflow !== "string")) errors.push(`workflow ${w.id}: chain needs a workflow id`);
  }
  for (const w of list) {
    if (w && w.chain && w.chain.workflow && !wids.has(w.chain.workflow)) errors.push(`workflow ${w.id}: chain names unknown workflow ${w.chain.workflow}`);
    for (const c of w && w.gate && Array.isArray(w.gate.choices) ? w.gate.choices : []) {
      const link = c && c.callout && c.callout.link;
      if (link && typeof link.workflow === "string" && !wids.has(link.workflow)) errors.push(`workflow ${w.id}: gate choice ${c.value} links unknown workflow ${link.workflow}`);
    }
  }
}

const CONCEPT_ID_RE = /^[a-z][a-z0-9_]*$/;
const QUALIFIED_RE = /^[a-z0-9][a-z0-9-]*\/[a-z][a-z0-9_]*$/;

function hazardKnown(pack, id) {
  return Boolean((pack.hazards && Object.prototype.hasOwnProperty.call(pack.hazards, id)) || taxonomy.hazard(id));
}

function conceptRefOk(pack, ref) {
  if (typeof ref !== "string" || !ref) return false;
  if (ref.includes("/")) return QUALIFIED_RE.test(ref); // another pack's concept: checked when read
  return Boolean(pack.concepts && Object.prototype.hasOwnProperty.call(pack.concepts, ref));
}

function validatePackShape(pack) {
  const errors = [];
  commonChecks(pack, errors);
  const objOf = objOfFactory(errors);
  const namesOf = namesOfFactory(errors);
  objOf(pack.hazards, "hazards");
  objOf(pack.params, "params");
  if (!objOf(pack.feed, "feed") || !pack.feed) errors.push("feed is required");
  if (!objOf(pack.concepts, "concepts") || !pack.concepts) errors.push("concepts is required");
  const conceptIds = new Set(Object.keys(pack.concepts || {}));
  for (const [id, rec] of Object.entries(pack.concepts || {})) {
    if (!CONCEPT_ID_RE.test(id)) errors.push(`concept "${id}": id must be lowercase letters, digits, underscores`);
    if (!objOf(rec, `concepts.${id}`)) continue;
    if (rec.type !== undefined && !taxonomy.type(rec.type)) errors.push(`concept ${id}: unknown type ${rec.type}`);
    namesOf(rec.tags, `concepts.${id}.tags`);
    namesOf(rec.hazards, `concepts.${id}.hazards`);
    for (const h of rec.hazards || []) if (typeof h === "string" && !hazardKnown(pack, h)) errors.push(`concept ${id}: unknown hazard ${h}`);
    checkCim(rec.cim, `concepts.${id}.cim`, errors, objOf, namesOf);
    if (rec.decode !== undefined && objOf(rec.decode, `concepts.${id}.decode`)) {
      const hasValues = rec.decode.values && typeof rec.decode.values === "object";
      const hasFlags = rec.decode.flags !== undefined;
      if (!hasValues && !hasFlags) errors.push(`concepts.${id}.decode.values must be an object`);
      else if (rec.decode.values !== undefined && !hasValues) errors.push(`concepts.${id}.decode.values must be an object`);
      if (hasFlags) {
        if (rec.type !== "bitmask") errors.push(`concepts.${id}.decode.flags: only a bitmask concept carries flags`);
        errors.push(...values.validateFlags(rec.decode.flags, `concepts.${id}.decode.flags`));
      }
    }
    const entry = values.pickEntry(rec);
    if (entry) errors.push(...values.validateEntry(entry, `concepts.${id}`));
  }
  if (pack.feed && pack.feed.discriminator !== undefined && !conceptIds.has(pack.feed.discriminator)) errors.push(`feed.discriminator names unknown concept ${pack.feed.discriminator}`);
  if (objOf(pack.containers, "containers") && pack.containers) {
    for (const [name, rec] of Object.entries(pack.containers)) {
      if (!objOf(rec, `containers.${name}`)) continue;
      if (!PLATFORMS.includes(rec.platform)) errors.push(`containers.${name}: platform must be splunk or sentinel`);
      if (rec.kind !== undefined && !["vendor", "custom", "sample"].includes(rec.kind)) errors.push(`containers.${name}: kind must be vendor, custom or sample`);
      namesOf(rec.hazards, `containers.${name}.hazards`);
      for (const h of rec.hazards || []) if (typeof h === "string" && !hazardKnown(pack, h)) errors.push(`containers.${name}: unknown hazard ${h}`);
    }
  }
  if (!Array.isArray(pack.bindings)) errors.push("bindings must be an array");
  const seenBindings = new Set();
  for (const b of Array.isArray(pack.bindings) ? pack.bindings : []) {
    if (!b || typeof b !== "object") { errors.push("binding must be an object"); continue; }
    const where = `binding ${b.platform || "?"}:${b.container || "?"}/${b.column || "?"}`;
    if (!PLATFORMS.includes(b.platform)) errors.push(`${where}: platform must be splunk or sentinel`);
    if (!b.container || typeof b.container !== "string" || UNSAFE.has(b.container)) errors.push(`${where}: container is required`);
    if (!b.column || typeof b.column !== "string" || UNSAFE.has(b.column)) errors.push(`${where}: column is required`);
    if (!conceptRefOk(pack, b.concept)) errors.push(`${where}: unknown concept ${b.concept}`);
    const k = `${b.platform}\0${b.container}\0${b.column}`;
    if (seenBindings.has(k)) errors.push(`${where}: bound twice`);
    seenBindings.add(k);
    checkCim(b.cim, `${where}.cim`, errors, objOf, namesOf);
    if (b.encoding !== undefined && b.encoding !== "json_string") errors.push(`${where}: encoding must be json_string`);
    if (b.encoding === "json_string" && (typeof b.column !== "string" || !b.column.includes("."))) errors.push(`${where}: a json_string binding needs a dotted column (head.path)`);
    if (b.provenance !== undefined) errors.push(...values.validateBindingProvenance(b.provenance, where));
  }
  if (pack.edges !== undefined && !Array.isArray(pack.edges)) errors.push("edges must be an array");
  const ids = new Set();
  for (const e of pack.edges || []) {
    if (!e || typeof e !== "object") { errors.push("edge must be an object"); continue; }
    if (!e.id) errors.push("edge without id");
    else if (ids.has(e.id)) errors.push(`duplicate edge id ${e.id}`);
    ids.add(e.id);
    if (!e.src || !conceptRefOk(pack, e.src.concept)) errors.push(`edge ${e.id}: src needs a known concept`);
    if (!e.dst || (!conceptRefOk(pack, e.dst.concept) && !(e.dst.type && taxonomy.type(e.dst.type)))) errors.push(`edge ${e.id}: dst needs a known concept or a taxonomy type`);
    if (!["confirmed", "validated", "asserted", "proposed"].includes(e.basis)) errors.push(`edge ${e.id}: basis must be confirmed|validated|asserted|proposed`);
    for (const h of e.hazards || []) if (typeof h === "string" && !hazardKnown(pack, h)) errors.push(`edge ${e.id}: unknown hazard ${h}`);
    if (e.spl || e.kql) errors.push(`edge ${e.id}: an edge carries no query; put it in templates`);
    if (e.intent !== undefined) for (const err of intent.validate(e.intent, (ref) => conceptRefOk(pack, ref))) errors.push(`edge ${e.id}: intent ${err}`);
  }
  if (pack.templates !== undefined && !Array.isArray(pack.templates)) errors.push("templates must be an array");
  const synthetic = [];
  for (const [i, t] of (Array.isArray(pack.templates) ? pack.templates : []).entries()) {
    if (!t || typeof t !== "object") { errors.push(`template #${i} must be an object`); continue; }
    const where = `template ${t.edge || "?"} on ${t.container || "?"}`;
    if (typeof t.edge !== "string" || !t.edge) errors.push(`${where}: edge is required`);
    else if (!t.edge.includes("/") && !ids.has(t.edge)) errors.push(`${where}: unknown edge ${t.edge}`);
    if (!t.container || typeof t.container !== "string" || UNSAFE.has(t.container)) errors.push(`${where}: container is required`);
    const langs = ["spl", "kql"].filter((l) => t[l] !== undefined);
    if (langs.length !== 1) errors.push(`${where}: exactly one of spl or kql`);
    for (const h of t.hazards || []) if (typeof h === "string" && !hazardKnown(pack, h)) errors.push(`${where}: unknown hazard ${h}`);
    if (langs.length === 1 && t.container) {
      // Rendered with dummy parameters and linted by pivot.validatePack,
      // whichever platform this page is on: a pack that only lints on the
      // machine that loads it is how the other platform's queries rot.
      synthetic.push({ id: `${t.edge}@${t.container}`, basis: "confirmed", src: { sourcetype: t.container, field: "x" }, dst: { sourcetype: t.container, field: "x" }, [langs[0]]: t[langs[0]] });
    }
  }
  if (pack.queries !== undefined && !Array.isArray(pack.queries)) errors.push("queries must be an array");
  const qids = new Set();
  for (const [i, q] of (Array.isArray(pack.queries) ? pack.queries : []).entries()) {
    if (!q || typeof q !== "object") { errors.push(`query #${i} must be an object`); continue; }
    const where = `query ${q.id || "?"}`;
    if (!q.id || !/^[a-z0-9][a-z0-9_-]*$/.test(q.id)) errors.push(`${where}: id must be lowercase letters, digits, dashes, underscores`);
    else if (qids.has(q.id)) errors.push(`duplicate query id ${q.id}`);
    qids.add(q.id);
    if (!q.label) errors.push(`${where}: label is required`);
    const containers = Array.isArray(q.containers) && q.containers.length && q.containers.every((c) => typeof c === "string" && c && !UNSAFE.has(c)) ? q.containers : null;
    if (!containers) errors.push(`${where}: containers must name at least one sourcetype`);
    const langs = ["spl", "kql"].filter((l) => q[l] !== undefined);
    if (!langs.length) errors.push(`${where}: spl or kql is required`);
    const checkHazards = (list) => {
      for (const h of list || []) {
        const ref = h && typeof h === "object" ? h.ref : h;
        if (typeof ref === "string" && !hazardKnown(pack, ref)) errors.push(`${where}: unknown hazard ${ref}`);
        if (h && typeof h === "object" && !(h.text || typeof h.ref === "string")) errors.push(`${where}: a hazard is an id, an object with text, or { ref, needs, unless }`);
      }
    };
    checkHazards(q.hazards);
    for (const lang of langs) {
      const t = q[lang];
      if (!t || typeof t !== "object") { errors.push(`${where}: ${lang} must be an object`); continue; }
      checkHazards(t.hazards);
      if (t.guard) for (const n of t.guard.all || []) if (!(pack.params && pack.params[n]) && !(t.required || []).includes(n)) errors.push(`${where}: guard names ${n}, which neither params nor required declares`);
      const own = t.containers === undefined ? containers : Array.isArray(t.containers) && t.containers.length && t.containers.every((c) => typeof c === "string" && c && !UNSAFE.has(c)) ? t.containers : null;
      if (t.containers !== undefined && !own) errors.push(`${where}: ${lang}.containers must name at least one sourcetype`);
      for (const c of own || []) synthetic.push({ id: `${q.id}@${c}`, basis: "confirmed", src: { sourcetype: c, field: "x" }, dst: { sourcetype: c, field: "x" }, hazards: [...(q.hazards || []), ...(t.hazards || [])], [lang]: t });
    }
  }
  if (pack.lists !== undefined) {
    if (!pack.lists || typeof pack.lists !== "object" || Array.isArray(pack.lists)) errors.push("lists must be an object");
    else for (const [name, l] of Object.entries(pack.lists)) {
      if (UNSAFE.has(name) || !/^[a-z][a-z0-9_]*$/.test(name)) errors.push(`list ${name}: name must be lowercase letters, digits, underscores`);
      if (!l || !Array.isArray(l.values) || !l.values.length || l.values.some((v) => typeof v !== "string" || !v)) errors.push(`list ${name}: values must be a non-empty array of strings`);
    }
  }
  checkWorkflows(pack, errors, ids, qids, (w, e) => {
    if (!e || !e.param || typeof e.param !== "string") { errors.push(`workflow ${w.id}: entries need a known concept and a param`); return; }
    if (e.concept !== undefined) {
      if (!conceptRefOk(pack, e.concept) || e.container !== undefined || e.column !== undefined) errors.push(`workflow ${w.id}: entries need a known concept and a param`);
      return;
    }
    const declared = pack.containers && typeof e.container === "string" && Object.prototype.hasOwnProperty.call(pack.containers, e.container);
    if (!declared || typeof e.column !== "string" || !e.column || UNSAFE.has(e.column)) errors.push(`workflow ${w.id}: a column entry needs a container the pack declares and a column`);
  });
  for (const [name, m] of Object.entries(pack.params || {})) {
    if (m && m.from_concept !== undefined && !conceptRefOk(pack, m.from_concept)) errors.push(`params.${name}: unknown from_concept ${m.from_concept}`);
    if (m && m.from_field !== undefined && (typeof m.from_field !== "string" || !m.from_field || UNSAFE.has(m.from_field))) errors.push(`params.${name}: from_field must be a column name`);
    if (m && m.from_field !== undefined && m.from_concept !== undefined) errors.push(`params.${name}: from_field or from_concept, not both`);
  }
  if (!errors.length) {
    // Every intent is compiled onto every container that binds its source
    // concept, on both platforms, and the results are linted beside the
    // hand-written templates. A container the intent cannot compile for
    // is skipped, as resolvedEdges() skips it; an intent that compiles
    // nowhere is a pack error, because it would show nowhere. A cross-feed
    // edge (dst by type) compiles too, under scope "type": its union spans
    // every container of the type, so the resolver here holds the bundled
    // packs only (withPackIndexed), never the learned pack: a pack is valid
    // or not on its own, not by what a user bound.
    withPackIndexed(pack, () => {
      for (const e of pack.edges || []) {
        if (e.intent === undefined || !(withinFeed(pack, e) || crossFeedByType(e))) continue;
        const skipped = [];
        let compiled = 0;
        for (const platform of PLATFORMS) {
          for (const container of srcContainersOf(pack, e, platform)) {
            try {
              const c = compileIntent(pack, e, platform, container);
              synthetic.push({ id: `${e.id}@${container} (compiled)`, basis: "confirmed", src: { sourcetype: container, field: "x" }, dst: { sourcetype: container, field: "x" }, [c.lang]: c.template });
              compiled += 1;
            } catch (err) {
              skipped.push(`${container}: ${err && err.message ? err.message : err}`);
            }
          }
        }
        if (!compiled) errors.push(`edge ${e.id}: intent compiles on no container${skipped.length ? ` (${skipped.join("; ")})` : " (nothing binds its source concept)"}`);
      }
    });
  }
  if (!errors.length) errors.push(...validatePack({ ...pack, edges: synthetic }));
  return errors;
}

// Runs fn with the resolver holding the bundled packs and the pack
// under validation (in place of any registered pack of the same id), then
// puts the resolver back as it was: validation happens before a pack is
// registered, and a pack under validation must not leave a trace (the
// same id is validated many times over, patched, in tests). The learned
// pack is left out on purpose: srcContainersOf and containersOfType read
// the resolver, and a user's own binding must not decide whether a
// bundled pack validates.
function withPackIndexed(pack, fn) {
  concepts._reset();
  for (const p of packs.values()) if (p.id !== LEARNED_ID && p.id !== pack.id) concepts.register(p);
  concepts.register(pack);
  try {
    return fn();
  } finally {
    reindex();
  }
}

// The resolver rebuilt from the Map: every pack in load order, the
// learned pack last so its bindings never precede a feed pack's on the
// same triple. Resolved edges are rebuilt on the next read.
function reindex() {
  concepts._reset();
  for (const p of packs.values()) if (p.id !== LEARNED_ID) concepts.register(p);
  for (const p of packs.values()) values.indexPack(p);
  const learned = packs.get(LEARNED_ID);
  if (learned) concepts.register(learned);
  edgeMemo = null;
}

// Structural checks a pack must pass before anything reads it. Returns [errors].
export function validate(pack) {
  if (!pack || typeof pack !== "object") return ["not an object"];
  return validatePackShape(pack);
}

export function register(pack) {
  const errors = validate(pack);
  if (errors.length) throw new Error(`pack ${pack && pack.id ? pack.id : "?"} rejected: ${errors.join("; ")}`);
  packs.set(pack.id, pack);
  if (packs.has(LEARNED_ID)) reindex(); // keeps the learned pack last
  else concepts.register(pack);
  values.indexPack(pack);
  edgeMemo = null;
  gen++;
  return pack;
}

// Set or replace a pack by id and rebuild the resolver from scratch, so a
// pack registered twice (the learned pack, after every confirm) leaves one
// record per triple. Validates like register().
export function replace(pack) {
  const errors = validate(pack);
  if (errors.length) throw new Error(`pack ${pack && pack.id ? pack.id : "?"} rejected: ${errors.join("; ")}`);
  packs.set(pack.id, pack);
  reindex();
  gen++;
  return pack;
}

export function remove(id) {
  if (!packs.delete(id)) return;
  values.dropPack(id);
  reindex();
  gen++;
}

// A counter that moves on every register(), replace(), remove() and
// _reset(): catalogue.syncLearned memoises its projection on it, so a
// pack change made from outside that call invalidates the memo.
export function generation() {
  return gen;
}

export async function load() {
  if (loaded) return;
  await taxonomy.load();
  let index = { packs: [] };
  try {
    index = await getJson("index.json");
  } catch {
    /* no bundled packs, fine */
  }
  const problems = [];
  for (const name of index.packs || []) {
    try {
      const pack = await getJson(name);
      register(pack);
    } catch (err) {
      problems.push(String(err && err.message ? err.message : err));
    }
  }
  loaded = true;
  if (problems.length) console.warn("[Reach] packs:", problems.join("\n"));
}

export function pack(id) {
  return packs.get(id) || null;
}

function allPacks() {
  return Array.from(packs.values());
}

// The feed a container mostly carries: of the packs binding columns on it,
// the one owning the most of them. The dev sample tables also bind three
// loader columns to the samples pack; that is not their feed.
function feedPackOf(platform, container) {
  const meta = concepts.container(platform, container);
  if (!meta) return null;
  const counts = new Map();
  for (const col of concepts.columnsOn(platform, container)) {
    const r = concepts.resolve(platform, container, col);
    if (r) counts.set(r.concept.packId, (counts.get(r.concept.packId) || 0) + 1);
  }
  let bestId = null;
  for (const [id, n] of counts) if (bestId === null || n > counts.get(bestId)) bestId = id;
  return bestId || meta.feedKeys[0] || meta.packIds[0] || null;
}

function containerColumnFor(platform, container, key) {
  if (!key) return null;
  const b = concepts.bindingsOf(key, platform).find((x) => x.container === container && !x.alias_of) || concepts.bindingsOf(key, platform).find((x) => x.container === container);
  return b ? b.column : null;
}

export function list() {
  const out = [];
  for (const p of packs.values()) {
    if (p.id === LEARNED_ID) continue; // the user's own bindings are not a feed
    out.push({
      id: p.id,
      name: p.name,
      pack_version: p.pack_version || null,
      description: p.description || "",
      source: p.source || "",
      sourcetypes: concepts.containers(PLATFORM).filter((c) => c.packIds.includes(p.id) || feedPackOf(PLATFORM, c.name) === p.id).map((c) => c.name),
      fields: Object.keys(p.concepts || {}).length,
      edges: (p.edges || []).length,
      workflows: (p.workflows || []).length,
      version: VERSION,
      feed: concepts.feed(p.id),
    });
  }
  return out;
}

export function sourcetype(st) {
  const meta = concepts.container(PLATFORM, st);
  if (!meta) return null;
  const packId = feedPackOf(PLATFORM, st);
  const feed = packId ? concepts.feed(packId) : null;
  const tags = Array.from(new Set([...((feed && feed.tags) || []), ...meta.tags]));
  return {
    packId,
    description: meta.description || (feed && feed.description) || null,
    discriminator: feed ? containerColumnFor(PLATFORM, st, feed.discriminator) : null,
    tags,
    kind: meta.kind,
    note: meta.note,
    feed,
  };
}

function conceptField(r) {
  const c = r.concept;
  const b = r.binding;
  return {
    packId: c.packId,
    description: c.description,
    notes: c.notes,
    role: c.role,
    tags: c.tags,
    sensitivity: c.sensitivity,
    cim: b.cim || c.cim,
    label: c.label,
    type: c.type,
    typeLabel: c.typeLabel,
    hazards: c.hazards,
    concept: c,
    binding: b,
    dictionary: values.dictionary(c.packId, c.id),
    bindingProvenance: bindingProvenanceOf(b),
  };
}

// How a column comes to carry its concept: the binding's own provenance
// as the pack wrote it, else what the pack's values sidecar says of it.
function bindingProvenanceOf(b) {
  if (!b || !b.packId) return null;
  const p = packs.get(b.packId);
  const raw = p && Array.isArray(p.bindings) ? p.bindings.find((x) => x.platform === b.platform && x.container === b.container && x.column === b.column) : null;
  if (raw && raw.provenance) return { kind: raw.provenance.kind, statement: raw.provenance.statement || null, cite: raw.provenance.cite || null };
  return values.bindingProvenance(b.packId, b);
}

export function field(st, name) {
  if (UNSAFE.has(st) || UNSAFE.has(name)) return null;
  const r = concepts.resolve(PLATFORM, st, name);
  return r ? conceptField(r) : null;
}

export function fieldsOn(st) {
  return Array.from(new Set(concepts.columnsOn(PLATFORM, st))).sort();
}

export function decode(st, name) {
  if (UNSAFE.has(st) || UNSAFE.has(name)) return null;
  const r = concepts.resolve(PLATFORM, st, name);
  if (r && r.concept.decode) return { ...r.concept.decode, packId: r.concept.packId };
  return null;
}

// ---------------------------------------------------------------------------
// Edges. An edge is intent between concepts; it is shown from a
// (container, column) where a query exists for a destination container
// this platform can query:
//
//   within a feed (dst is a concept of the same pack): the destination is
//   the container the user is on; a template for that container, or the
//   edge's intent compiled onto it (a hand-written template wins).
//   across feeds (dst is a taxonomy type or another pack's concept): every
//   container with a template for the edge, except the one the user is on;
//   with no template and a scope "type" intent, one view per source
//   container whose query unions every container of the type on this
//   platform (the source container leads), dst being the source container's
//   own column for the type and `union` naming the containers covered.
//
// A compiled view is the intent planned onto the container's bindings
// (intent.plan) and emitted by the platform's compiler as a template-shaped
// { spl | kql } that pivot.generate() renders like any other; it carries
// compiled: true. A container is skipped, silently, when the plan leaves a
// filter or record-type concept unresolved or the compiler refuses the plan.

function langOf(t) {
  return t.kql ? "kql" : "spl";
}

function platformOfLang(lang) {
  return lang === "kql" ? "sentinel" : "splunk";
}

// A pack's own hazard, worded for this platform when it says so.
export function packHazard(pack, ref) {
  const own = pack && pack.hazards && Object.prototype.hasOwnProperty.call(pack.hazards, ref) ? pack.hazards[ref] : null;
  if (!own) return null;
  const over = (own.platform && own.platform[PLATFORM]) || {};
  return { id: ref, level: over.level || own.level || "note", text: over.text || own.text };
}

function hazardObjects(pack, refs) {
  const out = [];
  for (const ref of refs || []) {
    if (ref && typeof ref === "object") { out.push(ref); continue; }
    const h = packHazard(pack, ref) || taxonomy.hazard(ref);
    if (h) out.push({ id: typeof ref === "string" ? ref : null, level: h.level, text: h.text });
  }
  return out;
}

function templatesFor(packId, edgeId) {
  const out = [];
  const qualified = `${packId}/${edgeId}`;
  for (const p of allPacks()) {
    for (const t of p.templates || []) {
      const ref = t.edge.includes("/") ? t.edge : `${p.id}/${t.edge}`;
      if (ref === qualified && platformOfLang(langOf(t)) === PLATFORM) out.push({ template: t, pack: p });
    }
  }
  return out;
}

function withinFeed(pack, e) {
  return Boolean(e.dst && e.dst.concept) && concepts.keyOf(pack.id, e.dst.concept).split("/")[0] === pack.id;
}

// A cross-feed edge whose destination is a taxonomy type and whose intent
// unions every container of that type (scope "type").
function crossFeedByType(e) {
  return Boolean(e.dst && e.dst.type && e.intent && e.intent.scope === "type");
}

// The containers on a platform that carry the edge's source concept.
function srcContainersOf(pack, e, platform) {
  const key = concepts.keyOf(pack.id, e.src && e.src.concept);
  return Array.from(new Set(concepts.bindingsOf(key, platform).map((b) => b.container)));
}

const COMPILERS = { splunk: compileSpl, sentinel: compileKql };

// A filter or record-type concept the plan could not resolve: the query
// would silently widen, so the container is not compiled for.
function blockingUnresolved(edgeIntent, plan) {
  const refs = new Set();
  for (const f of edgeIntent.filter || []) for (const c of f.any ? f.any : [f]) refs.add(c.concept);
  return plan.unresolved.filter((u) => refs.has(u) || u.startsWith("("));
}

// The edge's intent as a template for one container on one platform:
// { lang, template: { required, lines } }. Throws when the container
// cannot take it (the callers decide whether that is a skip or an error).
function compileIntent(pack, e, platform, container) {
  const plan = intent.plan(e.intent, { pack, platform, container });
  const blocking = blockingUnresolved(e.intent, plan);
  if (blocking.length) throw new Error(`unresolved ${blocking.join(", ")}`);
  return { lang: plan.lang, template: COMPILERS[platform].compile(plan), union: plan.scope === "type" ? plan.union.map((u) => u.container) : null };
}

// The column carrying a concept (or a concept of a type) on a container.
function dstColumnOn(pack, dst, container) {
  if (dst.concept) {
    const key = concepts.keyOf(pack.id, dst.concept);
    return { key, column: containerColumnFor(PLATFORM, container, key) || dst.concept };
  }
  for (const c of concepts.ofType(dst.type, PLATFORM)) {
    const col = containerColumnFor(PLATFORM, container, c.key);
    if (col) return { key: c.key, column: col };
  }
  return { key: null, column: dst.type };
}

function resolvedEdges() {
  if (edgeMemo) return edgeMemo;
  const out = [];
  for (const p of allPacks()) {
    for (const e of p.edges || []) {
      const srcKey = concepts.keyOf(p.id, e.src.concept);
      const srcBindings = concepts.bindingsOf(srcKey, PLATFORM);
      if (!srcBindings.length) continue;
      const inFeed = withinFeed(p, e);
      const srcContainers = new Set(srcBindings.map((b) => b.container));
      const view = (b, dstContainer, extra) => {
        const dst = dstColumnOn(p, e.dst, dstContainer);
        const containerMeta = concepts.container(PLATFORM, dstContainer);
        const containerHazards = (containerMeta && containerMeta.hazards) || [];
        const ownHazards = hazardObjects(p, e.hazards);
        return {
          id: e.id,
          kind: e.kind,
          label: e.label,
          src: { sourcetype: b.container, field: b.column },
          dst: { sourcetype: dstContainer, field: dst.column },
          basis: e.basis,
          basis_ref: e.basis_ref || null,
          cardinality: e.cardinality || null,
          scope: e.scope || [],
          hazards: [...ownHazards, ...containerHazards.filter((h) => !ownHazards.some((x) => (x.id || x.text) === (h.id || h.text)))],
          note: e.note || null,
          packId: p.id,
          templatePackId: null,
          concept: { src: srcKey, dst: dst.key, type: e.dst.type || null },
          ...extra,
        };
      };
      const templated = new Set();
      for (const { template: t, pack: tp } of templatesFor(p.id, e.id)) {
        const lang = langOf(t);
        templated.add(t.container);
        if (!inFeed && srcContainers.has(t.container)) continue; // a cross-feed edge back onto the feed itself
        const srcs = inFeed ? srcBindings.filter((b) => b.container === t.container) : srcBindings;
        for (const b of srcs) {
          const v = view(b, t.container, { label: t.label || e.label, [lang]: t[lang], templatePackId: tp.id });
          v.hazards = [...v.hazards, ...hazardObjects(tp, t.hazards)];
          out.push(v);
        }
      }
      // No template for a container the source concept lands on: the
      // intent, compiled for it. Across feeds the intent is a scope "type"
      // union led by the source container, and any template for the edge
      // on this platform stands in for it.
      if (e.intent === undefined) continue;
      const cross = !inFeed && crossFeedByType(e);
      if (!inFeed && !cross) continue;
      if (cross && templated.size) continue;
      for (const container of srcContainers) {
        if (templated.has(container)) continue;
        let c;
        try {
          c = compileIntent(p, e, PLATFORM, container);
        } catch {
          continue;
        }
        for (const b of srcBindings.filter((x) => x.container === container)) out.push(view(b, container, { [c.lang]: c.template, compiled: true, ...(cross ? { union: c.union } : {}) }));
      }
    }
  }
  edgeMemo = out;
  return out;
}

export function edgesFrom(st, name) {
  const out = [];
  for (const e of resolvedEdges()) if (e.src.sourcetype === st && e.src.field === name) out.push(e);
  return out;
}

export function edgesTo(st, name) {
  const out = [];
  for (const e of resolvedEdges()) if (e.dst.sourcetype === st && e.dst.field === name) out.push(e);
  return out;
}

export function edgesOn(st) {
  const out = [];
  const seen = new Set();
  for (const e of resolvedEdges()) {
    if (e.src.sourcetype !== st && e.dst.sourcetype !== st) continue;
    const k = `${e.id}\0${e.src.sourcetype}\0${e.dst.sourcetype}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out;
}

// One renderable form of a pack's edge on this platform: the edge resolved
// onto the first container with a template, preferring `container` when
// given. Workflows bind their results here.
export function edge(packId, id, { container } = {}) {
  const p = packs.get(packId);
  if (!p) return null;
  const views = resolvedEdges().filter((e) => e.packId === packId && e.id === id);
  if (!views.length) return null;
  return (container && views.find((e) => e.dst.sourcetype === container || e.src.sourcetype === container)) || views[0];
}

// A pack query on one of its containers (the first unless `container` names
// another), shaped like an edge so pivot.generate renders it: null when the
// pack, the query or the container is unknown. Hazard ids are resolved to
// objects here, gates kept, so the platform's wording applies.
export function query(packId, id, { container } = {}) {
  const p = packs.get(packId);
  const q = p && Array.isArray(p.queries) ? p.queries.find((x) => x.id === id) : null;
  if (!q) return null;
  // A query in both languages answers in this platform's; in one, in that one.
  const lang = q.spl && q.kql ? (PLATFORM === "sentinel" ? "kql" : "spl") : langOf(q);
  const containers = (q[lang] && Array.isArray(q[lang].containers) && q[lang].containers) || q.containers;
  const on = container ? containers.find((c) => c === container) : containers[0];
  if (!on) return null;
  // The query's hazards, then the language's own (an index macro is Splunk's business).
  const hazards = [...(q.hazards || []), ...((q[lang] && q[lang].hazards) || [])].map((h) => {
    const ref = h && typeof h === "object" ? h.ref : h;
    const known = typeof ref === "string" ? packHazard(p, ref) || taxonomy.hazard(ref) : null;
    if (h && typeof h === "object") return known ? { level: known.level, text: known.text, needs: h.needs || [], unless: h.unless || [] } : h;
    return known ? { level: known.level, text: known.text } : h;
  });
  return {
    id: q.id,
    label: q.label,
    note: q.note || null,
    packId: p.id,
    basis: "confirmed",
    containers: containers.slice(),
    src: { sourcetype: on, field: null },
    dst: { sourcetype: on, field: null },
    hazards,
    [lang]: q[lang],
  };
}

export function discriminators() {
  const out = {};
  for (const c of concepts.containers(PLATFORM)) {
    if (out[c.name]) continue;
    const rec = sourcetype(c.name);
    if (rec && rec.discriminator) out[c.name] = rec.discriminator;
  }
  return out;
}

// Parameter metadata. A pack's from_concept becomes the from_field of
// the container in hand (the popups read a literal column name off it).
export function paramMeta(packId, name, container) {
  const p = packs.get(packId);
  const m = p && p.params && p.params[name];
  if (!m) return null;
  let fromField = m.from_field || null;
  if (m.from_concept) {
    const key = concepts.keyOf(p.id, m.from_concept);
    fromField = (container && containerColumnFor(PLATFORM, container, key)) || (concepts.bindingsOf(key, PLATFORM)[0] || {}).column || null;
  }
  const over = (m.platform && m.platform[PLATFORM]) || {};
  return { label: over.label || m.label || name, placeholder: over.placeholder || m.placeholder || "", hint: over.hint || m.hint || "", from_field: fromField };
}

// Every pack input bound from a concept, as { name, concept: key }:
// the held-fact alias map (held.js) treats such an input and the concept's
// column as one fact.
export function conceptParams() {
  const out = [];
  for (const p of allPacks()) {
    for (const [name, m] of Object.entries(p.params || {})) if (m && m.from_concept) out.push({ name, concept: concepts.keyOf(p.id, m.from_concept) });
  }
  return out;
}

// Every pack input named as a column outright (from_field), as { name,
// column }: held.js treats the input and the column as one fact.
export function fieldParams() {
  const out = [];
  for (const p of allPacks()) {
    for (const [name, m] of Object.entries(p.params || {})) if (m && m.from_field && !m.from_concept) out.push({ name, column: m.from_field });
  }
  return out;
}

// Every parameter a pack's edges can take, with its meta, for binding from
// an event row (from_field) and for rendering inputs.
export function params(packId, container) {
  const p = packs.get(packId);
  const out = {};
  for (const name of Object.keys((p && p.params) || {})) out[name] = paramMeta(packId, name, container);
  return out;
}

// A workflow's entries name concepts; here they are the (sourcetype,
// field) pairs this platform carries them on, which is what the popups
// match a click against.
// Only on containers the workflow's results can actually be rendered
// from (a template, or an intent compiled for the container), the same
// rule edgesFrom() follows.
// A column entry names a container the pack declares, which is on one
// platform already; it is kept where that container is this platform's.
function resolvedEntries(p, w) {
  const resultEdges = new Set((w.results || []).filter((r) => r.edge).map((r) => r.edge));
  const renderable = new Set(resolvedEdges().filter((e) => e.packId === p.id && resultEdges.has(e.id)).map((e) => e.src.sourcetype));
  for (const r of w.results || []) {
    const q = r.query ? query(p.id, r.query) : null;
    for (const c of (q && q.containers) || []) renderable.add(c);
  }
  const out = [];
  for (const e of w.entries || []) {
    if (e.concept === undefined) {
      const meta = p.containers && p.containers[e.container];
      if (meta && meta.platform === PLATFORM) out.push({ sourcetype: e.container, field: e.column, param: e.param, concept: null });
      continue;
    }
    for (const b of concepts.bindingsOf(concepts.keyOf(p.id, e.concept), PLATFORM)) {
      if (!renderable.has(b.container)) continue;
      out.push({ sourcetype: b.container, field: b.column, param: e.param, concept: e.concept });
    }
  }
  return out;
}

export function workflows() {
  const out = [];
  for (const p of packs.values()) for (const w of p.workflows || []) out.push({ ...w, entries: resolvedEntries(p, w), packId: p.id });
  return out;
}

export function workflow(id) {
  return workflows().find((w) => w.id === id) || null;
}

export function lintOptions(packId) {
  const p = packs.get(packId);
  return { commands: (p && p.commands) || [], macros: (p && p.macros) || [] };
}

export function _reset() {
  packs.clear();
  concepts._reset();
  values._reset();
  edgeMemo = null;
  loaded = false;
  gen++;
}

export default { load, list, pack, sourcetype, field, fieldsOn, decode, edgesFrom, edgesTo, edgesOn, edge, query, discriminators, paramMeta, params, fieldParams, lintOptions, workflows, workflow, register, replace, remove, generation, validate, FORMAT, VERSION };
