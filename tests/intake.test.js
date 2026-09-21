import { test } from "node:test";
import assert from "node:assert/strict";
import { parse, parseCsv, IntakeError } from "../app/lib/intake.js";

const envelope = { meta: { v: 1, step: "profile", env: "dev", gen: "2026-09-17T00:00:00Z", q: "deadbeef" }, params: { table: "T", sample: 5 }, rows: [{ col: "A", n: 3, row_kind: "stat", total: 5 }, { col: "A", val: "x", n: 2, row_kind: "top" }] };

test("RFC 4180 CSV: quoted fields, doubled quotes, newlines inside quotes, CRLF, BOM", () => {
  const rows = parseCsv('﻿a,b\r\n"x, y","he said ""hi""\nthen left"\r\n1,2\n');
  assert.deepEqual(rows, [["a", "b"], ["x, y", 'he said "hi"\nthen left'], ["1", "2"]]);
  assert.deepEqual(parseCsv("a\tb\n1\t2"), [["a", "b"], ["1", "2"]]);
  assert.throws(() => parseCsv('a\n"unterminated'), /quoted field/);
});

test("a raw JSON envelope paste", () => {
  const out = parse(JSON.stringify(envelope));
  assert.equal(out.kind, "envelope");
  assert.equal(out.step, "profile");
  assert.equal(out.env, "dev");
  assert.equal(out.q, "deadbeef");
  assert.deepEqual(out.params, { table: "T", sample: 5 });
  assert.equal(out.rows.length, 2);
});

test("the one-row CSV export with the reach column, quotes doubled", () => {
  const json = JSON.stringify(envelope);
  const csv = `"reach"\r\n"${json.replace(/"/g, '""')}"\r\n`;
  const out = parse(csv);
  assert.equal(out.kind, "envelope");
  assert.equal(out.rows.length, 2);
  // extra columns around it are fine; the column is found by name
  const wide = `"TenantId","reach","Type"\n"t","${json.replace(/"/g, '""')}","x"\n`;
  assert.equal(parse(wide).step, "profile");
});

test("a cell copied with CSV quoting but no CSV around it", () => {
  const json = JSON.stringify(envelope);
  const out = parse(`"${json.replace(/"/g, '""')}"`);
  assert.equal(out.kind, "envelope");
});

test("plain exports come back as tables, and the user has to say the step", () => {
  const out = parse("T,ColumnName,ColumnType\nA,x,string\nA,y,long\n");
  assert.equal(out.kind, "table");
  assert.deepEqual(out.columns, ["T", "ColumnName", "ColumnType"]);
  assert.deepEqual(out.rows[1], { T: "A", ColumnName: "y", ColumnType: "long" });
  const arr = parse('[{"a":1},{"a":2,"b":3}]');
  assert.equal(arr.kind, "table");
  assert.deepEqual(arr.columns, ["a", "b"]);
});

test("what is refused, with a reason", () => {
  assert.throws(() => parse(""), (e) => e instanceof IntakeError && e.code === "empty");
  assert.throws(() => parse("{not json"), (e) => e.code === "json");
  assert.throws(() => parse(JSON.stringify({ meta: { v: 2, step: "x" }, rows: [] })), (e) => e.code === "envelope_version");
  assert.throws(() => parse(JSON.stringify({ hello: 1 })), (e) => e.code === "not_envelope");
  assert.throws(() => parse('reach\n"{""meta"":1}"\n"{""meta"":2}"\n'), (e) => e.code === "envelope_rows");
  assert.throws(() => parse("reach\nnot json\n"), (e) => e.code === "envelope_json");
});
