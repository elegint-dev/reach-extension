// The recipe's queries and the envelope live in recipe.js, built from
// kql.js's primitives; the bare query text and the stamp are what the
// portal runs and what a paste is checked against.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as recipe from "../app/lib/recipe.js";

test("envelope wraps the query and stamps it", () => {
  const e = recipe.envelope({ query: "T | take 1", step: "profile", env: "dev", params: { table: "T", sample: 5 }, gen: "2026-09-17T00:00:00Z" });
  assert.match(e.kql, /^T \| take 1\n\| summarize rows = make_list\(pack_all\(\)\)\n\| project reach = tostring\(pack\("meta", pack\("v", 1, "step", "profile", "env", "dev", "gen", "2026-09-17T00:00:00Z", "q", "[0-9a-f]{8}"\), "params", pack\("table", "T", "sample", 5\), "rows", rows\)\)$/);
  assert.equal(e.q, recipe.stamp("T | take 1"));
  assert.throws(() => recipe.envelope({ query: "T", step: "bad step" }), /identifier/);
});

test("recipe queries validate their inputs", () => {
  assert.match(recipe.profileQuery({ table: "ReachAzureAD_CL", sample: 100, window: "7d" }), /let S = ReachAzureAD_CL \| where TimeGenerated > ago\(7d\) \| take 100;/);
  assert.match(recipe.profileQuery({ table: "T" }), /dcountif\(val, isnotempty\(val\)\)/);
  assert.throws(() => recipe.profileQuery({ table: "T; bad" }), /identifier/);
  assert.match(recipe.recordTypesQuery({ table: "T", column: "EventName" }), /summarize n = count\(\) by value = tostring\(EventName\)/);
  assert.match(recipe.schemaQuery(["A", "B"]), /\(A \| getschema \| extend T = "A"\),\n  \(B \| getschema \| extend T = "B"\)/);
  assert.equal(recipe.schemaQuery(["A"]), 'A | getschema | extend T = "A" | project T, ColumnName, ColumnType');
  assert.match(recipe.inventoryQuery({ window: "30d" }), /^Usage\n\| where TimeGenerated > ago\(30d\)/);
  assert.match(recipe.watchlistReadQuery({ alias: "a'b", key: "k", value: "v" }), /_GetWatchlist\("a'b"\) \| take 2001/);
});
