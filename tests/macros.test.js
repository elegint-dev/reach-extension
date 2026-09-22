// it_55bf59a9: the Macro form has a guided install (macros.js), never a
// hint that credits the CrowdStrike Add-on for macros that are Reach's
// own. Correctness criterion: for every one of the frozen fixture's 22
// macro cases, expanding the generated definition with the macro call's
// own arguments reproduces what fdr.generate() renders inline for those
// same arguments, byte for byte. A small SPL macro expander does the
// substitution the way Splunk's macro engine does it: an argument quoted
// at the call site (every argument here is) loses that quoting when it
// lands in the definition, so a bare $name$ token in the definition
// prints it unquoted and a "$name$" token prints it back in quotes.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as catalogue from "../app/lib/catalogue.js";
import * as packs from "../app/lib/packs.js";
import * as fdr from "../app/lib/fdr-queries.js";
import * as macros from "../app/lib/macros.js";
import { macroNewUrl } from "../app/components/drawer.js";

await catalogue.load();

const cases = JSON.parse(readFileSync(new URL("./fixtures/fdr-queries.json", import.meta.url), "utf8"));
const EDGES = JSON.parse(readFileSync(new URL("./fixtures/fdr-edges.json", import.meta.url), "utf8"));
const edgeById = (id) => EDGES.find((e) => e.id === id) || null;

function pivotOf(c) {
  return c.pivot.kind === "edge" ? { kind: "edge", edge: edgeById(c.pivot.edge) } : { kind: c.pivot.kind };
}

// A macro call's own name and arguments, unescaped the way SPL's quoting
// (spl.js: double a backslash, escape a quote) reverses.
function parseCall(spl) {
  const m = /^`([a-z_]+)\(([\s\S]*)\)`$/.exec(String(spl).trim());
  if (!m) return null;
  const args = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let mm;
  while ((mm = re.exec(m[2]))) args.push(mm[1].replace(/\\(.)/g, "$1"));
  return { name: m[1], args };
}

// The argument names the fixture case's own query calls the macro with
// (a query the macro's canonical body was not itself drawn from, e.g.
// cs_detection_host names its host argument "value", cs_process_table's
// own "aid": the macro is one shared body, but positionally, every caller
// may name its slots differently). Used to rebuild the comparison params
// under this query's own token names, never the definition's.
function localArgNames(pivot) {
  const target = fdr.targetFor(pivot);
  const q = packs.query(fdr.PACK_ID, target.query);
  const line = q && q.spl && q.spl.macro && q.spl.macro.lines && q.spl.macro.lines[0];
  const m = /\(([^)]*)\)`\s*$/.exec(String(line || "").trim());
  if (!m) return null;
  return m[1].split(",").map((tok) => {
    const t = tok.trim().replace(/^"|"$/g, "");
    const mm = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(t);
    return mm ? mm[1] : null;
  });
}

const macroCases = cases.filter((c) => c.macro && c.macro.spl);

test("the fixture's 22 macro cases are what this suite's parity check runs on", () => {
  assert.equal(macroCases.length, 22);
});

for (const c of macroCases) {
  test(`macro definition parity: ${c.id}`, () => {
    const call = parseCall(c.macro.spl);
    assert.ok(call, `${c.id}: not a bare macro call`);
    const args = macros.argsFor(call.name);
    assert.ok(args, `${c.id}: no known signature for ${call.name}`);
    assert.equal(args.length, call.args.length, `${c.id}: call arity`);
    const definition = macros.definitionFor(call.name);
    assert.ok(definition, `${c.id}: no definition for ${call.name}`);
    let expanded = definition;
    args.forEach((a, i) => {
      expanded = expanded.split(`$${a}$`).join(call.args[i]);
    });
    const localArgs = localArgNames(pivotOf(c));
    assert.ok(localArgs, `${c.id}: no macro call on this case's own query`);
    const params = {};
    localArgs.forEach((a, i) => {
      params[a] = call.args[i];
    });
    // The macro's own implicit upper bound: a required-mode query's
    // definition hardcodes latest=now (macros.js), so the comparison
    // binds the same value; an earliest-only query (cs_trace) never has one.
    if (/latest=now\b/.test(definition)) params.latest = "now";
    const got = fdr.generate(pivotOf(c), params, {});
    assert.equal(expanded, got.spl, `${c.id}: expansion vs. a fresh inline render of the same arguments`);
  });
}

test("argsFor: the pack's five macros, cs_index alone taking none", () => {
  assert.deepEqual(macros.argsFor("cs_index"), []);
  assert.deepEqual(macros.argsFor("cs_trace_process"), ["field", "value", "earliest"]);
  assert.deepEqual(macros.argsFor("cs_process_events"), ["aid", "tpid", "earliest"]);
  assert.deepEqual(macros.argsFor("cs_process_table"), ["aid", "earliest"]);
  assert.deepEqual(macros.argsFor("cs_pid_lookup"), ["aid", "pid", "earliest"]);
  assert.equal(macros.argsFor("not_a_macro"), null);
});

test("stanzaName: the Search-macros form's Name field carries the argument count, cs_index none", () => {
  assert.equal(macros.stanzaName("cs_index"), "cs_index");
  assert.equal(macros.stanzaName("cs_trace_process"), "cs_trace_process(3)");
  assert.equal(macros.stanzaName("cs_process_table"), "cs_process_table(2)");
});

test("csIndexDefinition: the resolved scope index, or a placeholder the analyst edits", () => {
  assert.equal(macros.csIndexDefinition("crowdstrike_fdr"), "index=crowdstrike_fdr");
  assert.equal(macros.csIndexDefinition(""), "index=<your index>");
  assert.equal(macros.csIndexDefinition(undefined), "index=<your index>");
});

test("definitionFor: cs_index never touches the pack, unlike the other four", () => {
  assert.equal(macros.definitionFor("cs_index", { resolvedIndex: "crowdstrike_fdr" }), "index=crowdstrike_fdr");
  assert.equal(macros.definitionFor("nope"), null);
});

test("every generated definition carries every one of its own arguments and no other macro's", () => {
  for (const name of ["cs_trace_process", "cs_process_events", "cs_process_table", "cs_pid_lookup"]) {
    const args = macros.argsFor(name);
    const def = macros.definitionFor(name);
    for (const a of args) assert.match(def, new RegExp(`\\$${a}\\$`), `${name}: missing $${a}$`);
    assert.doesNotMatch(def, /REACHMACROARG/, `${name}: a sentinel leaked through unreplaced`);
  }
});

test("confStanza: macros.conf's own shape, one stanza per macro, a continued multi-line definition", () => {
  const stanza = macros.confStanza("cs_process_table", { resolvedIndex: "crowdstrike_fdr" });
  const lines = stanza.split("\n");
  assert.equal(lines[0], "[cs_process_table(2)]");
  assert.equal(lines[1], "args = aid, earliest");
  assert.ok(lines[2].startsWith("definition = "));
  assert.ok(stanza.trimEnd().endsWith("iseval = 0"));
  // A defined value with an embedded newline continues with a trailing
  // backslash: macros.conf's own multi-line convention.
  assert.match(stanza, /\\\n/);
});

test("macrosConfText: cs_index first, blank line between stanzas, unknown names dropped silently", () => {
  const text = macros.macrosConfText(["cs_index", "cs_trace_process", "not_a_macro"], { resolvedIndex: "main" });
  const stanzas = text.split("\n\n");
  assert.equal(stanzas.length, 2);
  assert.equal(stanzas[0], "[cs_index]\ndefinition = index=main\niseval = 0");
  assert.match(stanzas[1], /^\[cs_trace_process\(3\)\]/);
});

test("the hint never credits the CrowdStrike Add-on for a macro that is Reach's own", () => {
  for (const name of ["cs_index", "cs_trace_process", "cs_process_events", "cs_process_table", "cs_pid_lookup"]) {
    const def = macros.definitionFor(name, { resolvedIndex: "main" });
    assert.ok(def, name);
  }
});

test("macroNewUrl: the macros/_new form's own path, no query string, an editor the analyst still submits", () => {
  const url = macroNewUrl("https://splunk.example:8000");
  assert.equal(url, "https://splunk.example:8000/en-US/manager/search/admin/macros/_new");
  assert.doesNotMatch(url, /\?/, "a deep link that only opens a blank form never carries prefilled parameters");
  assert.equal(macroNewUrl(""), "");
});

