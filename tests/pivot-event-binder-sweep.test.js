// Every pack pivot a click on one of the fixture rows can reach (the FDR
// ledger's edges and the v2 packs' edgesFrom, on every field the row
// carries) is assembled the way a value click assembles one: facts.js
// eventParams() bound from the row's own time and fields, then the
// pivot's own base parameters. A row's own click never leaves a $name$
// placeholder behind except `value` (the click supplies it, this sweep
// does not hold one) and `index` (scope, never bound by the event).
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as packs from "../app/lib/packs.js";
import * as pivotLib from "../app/lib/pivot.js";
import { edgeRowsFor, pivotForEdgeRow, baseParamsForRow } from "../app/lib/reachability.js";
import * as fdr from "../app/lib/fdr-queries.js";
import { eventParams } from "../app/lib/facts.js";
import { HANDLE_OPEN } from "./fixtures/pages/handle-open-row.mjs";
import { IMPERSONATION, LINUX } from "./fixtures/pages/known-rows.mjs";
import { MAC_SIGNING } from "./fixtures/pages/mac-signing-rows.mjs";
import { KINDS } from "./_fdr-cases.js";

await catalogue.load();

const CONTAINER = "crowdstrike:events:sensor";
const ROWS = [
  { label: "handle-open", list: HANDLE_OPEN },
  { label: "impersonation", list: IMPERSONATION },
  { label: "linux", list: LINUX },
  ...MAC_SIGNING.map((r, i) => ({ label: `mac-signing-${i}`, list: r.fields })),
];

function rowReader(list) {
  const map = new Map(list);
  return (name) => map.get(name) ?? null;
}

// The fixtures carry an epoch-millisecond `timestamp`, the same instant
// their hand-written eventRow() prints as data-time-iso.
function timeOf(list) {
  const ms = new Map(list).get("timestamp");
  if (!ms) return null;
  const d = new Date(Number(ms));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function sweep() {
  let checked = 0;
  let bound = 0;
  let reasoned = 0;
  const unexplained = [];
  const onlyScope = (missing) => missing.every((n) => n === "value" || n === "index");
  const record = (out, label) => {
    if (!out.missing.length) { bound++; return; }
    if (onlyScope(out.missing)) reasoned++;
    else unexplained.push(`${label}: ${out.missing.join(",")}`);
  };

  for (const { label, list } of ROWS) {
    const read = rowReader(list);
    const time = timeOf(list);
    const recordType = read("event_simpleName");
    const evRec = recordType ? fields.event(recordType) : null;

    if (evRec) {
      for (const row of edgeRowsFor(fields.edges(), evRec, recordType)) {
        checked++;
        const pivot = pivotForEdgeRow(row, recordType);
        const params = { value: "x", ...eventParams({ time, read }), ...baseParamsForRow(row, recordType, recordType) };
        try {
          record(fdr.generate(pivot, params), `${label}/ledger/${row.edge.id}`);
        } catch (err) {
          unexplained.push(`${label}/ledger/${row.edge.id}: threw ${err.message}`);
        }
      }
    }

    for (const [name] of list) {
      for (const edge of catalogue.edgesFrom(CONTAINER, name)) {
        checked++;
        const pmeta = packs.params(edge.packId, edge.src.sourcetype);
        const params = { value: "x", ...eventParams({ time, read }) };
        for (const [pname, pm] of Object.entries(pmeta)) {
          if (pm.from_field && params[pname] === undefined) {
            const v = read(pm.from_field);
            if (v) params[pname] = v;
          }
        }
        try {
          record(pivotLib.generate(edge, params, { pack: packs.pack(edge.packId) }), `${label}/${name}/${edge.id}`);
        } catch (err) {
          unexplained.push(`${label}/${name}/${edge.id}: threw ${err.message}`);
        }
      }
    }
  }

  // The FDR kinds' own golden full bindings (tests/_fdr-cases.js): every
  // one already carries every parameter, so this is a coherence check on
  // the same generator, not a new binding path.
  for (const [kind, spec] of Object.entries(KINDS)) {
    checked++;
    try {
      record(fdr.generate({ kind }, spec.full), `kind:${kind}`);
    } catch (err) {
      unexplained.push(`kind:${kind}: threw ${err.message}`);
    }
  }

  return { checked, bound, reasoned, unexplained };
}

test("every pack pivot a fixture row can reach binds from the event, or leaves only value/index unbound", () => {
  const { checked, bound, reasoned, unexplained } = sweep();
  console.log(`pivot sweep: ${checked} checked, ${bound} fully bound, ${reasoned} unbound-with-reason (value/index only), ${unexplained.length} unexplained`);
  assert.ok(checked > 0, "the fixture rows reach at least one pivot");
  assert.deepEqual(unexplained, []);
});
