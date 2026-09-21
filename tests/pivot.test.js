import { test } from "node:test";
import assert from "node:assert/strict";
import { generate, validatePack, PivotError } from "../app/lib/pivot.js";

// The two hardest CloudTrail edges, written as data first; the renderer has
// to fit them, not the other way round.
const pack = {
  id: "aws-cloudtrail",
  hazards: {
    temp_creds: { level: "caution", text: "Temporary credentials expire; the key alone does not identify the human: follow the session's userIdentity.arn too." },
  },
  commands: ["dedup"],
  edges: [
    {
      id: "ct_tempkey_use",
      kind: "credential",
      label: "Later calls made with this temporary key",
      src: { sourcetype: "aws:cloudtrail", field: "responseElements.credentials.accessKeyId" },
      dst: { sourcetype: "aws:cloudtrail", field: "userIdentity.accessKeyId" },
      basis: "confirmed",
      basis_ref: "CloudTrail record contents: AssumeRole/GetSessionToken responseElements.credentials.accessKeyId is the userIdentity.accessKeyId of the calls that follow",
      cardinality: "1:n",
      scope: [],
      hazards: ["temp_creds"],
      spl: {
        required: ["value", "earliest"],
        lines: [
          "search $index$ $sourcetype$ earliest=$earliest:time$",
          { clause: "  latest=$latest:time$", needs: ["latest"] },
          "  userIdentity.accessKeyId=$value$",
          { clause: "  recipientAccountId=$account$", needs: ["account"] },
          "| table _time eventSource eventName userIdentity.arn sourceIPAddress errorCode requestID",
          "| sort - _time",
        ],
      },
    },
    {
      id: "ct_assumed_role_session",
      kind: "actor",
      label: "What this assumed-role session did",
      src: { sourcetype: "aws:cloudtrail", field: "responseElements.assumedRoleUser.arn" },
      dst: { sourcetype: "aws:cloudtrail", field: "userIdentity.arn" },
      basis: "confirmed",
      cardinality: "1:n",
      scope: [],
      hazards: [],
      spl: {
        required: ["value", "earliest"],
        lines: [
          "search $index$ $sourcetype$ earliest=$earliest:time$",
          { clause: "  latest=$latest:time$", needs: ["latest"] },
          "  userIdentity.arn=$value$",
          "| stats count, min(_time) as first_seen, max(_time) as last_seen, values(eventSource) as services, dc(eventName) as distinct_calls, values(sourceIPAddress) as src_ips by userIdentity.arn",
          "| convert ctime(first_seen) ctime(last_seen)",
        ],
      },
    },
  ],
};

test("renders with every parameter bound; optional clauses included", () => {
  const r = generate(pack.edges[0], { index: "main", value: "ASIAEXAMPLE123", earliest: "-24h", latest: "now", account: "123456789012" }, { pack });
  assert.equal(
    r.spl,
    [
      "search index=main sourcetype=aws:cloudtrail earliest=-24h",
      "  latest=now",
      '  userIdentity.accessKeyId="ASIAEXAMPLE123"',
      '  recipientAccountId="123456789012"',
      "| table _time eventSource eventName userIdentity.arn sourceIPAddress errorCode requestID",
      "| sort - _time",
    ].join("\n"),
  );
  assert.deepEqual(r.missing, []);
  assert.equal(r.asserted, false);
  assert.equal(r.sourcetype, "aws:cloudtrail");
  assert.deepEqual(r.hazards, [{ level: "caution", text: pack.hazards.temp_creds.text }]);
});

test("optional clauses drop when their parameter is unbound; required ones are reported", () => {
  const r = generate(pack.edges[0], { index: "main", value: "ASIA1" }, { pack });
  assert.ok(!r.spl.includes("latest="));
  assert.ok(!r.spl.includes("recipientAccountId"));
  assert.ok(r.spl.includes("earliest=$earliest$"));
  assert.deepEqual(r.missing, ["earliest"]);
});

test("index is a parameter: unbound → placeholder and missing", () => {
  const r = generate(pack.edges[1], { value: "arn:aws:sts::1:assumed-role/Admin/s", earliest: "-7d" }, { pack });
  assert.ok(r.spl.startsWith("search index=$index$ sourcetype=aws:cloudtrail earliest=-7d"));
  assert.deepEqual(r.missing, ["index"]);
});

test("values are always quoted and escaped; time modifiers only when unsafe", () => {
  const r = generate(pack.edges[0], { index: 'we"ird', value: 'x" | delete', earliest: "01/01/2026:00:00:00", latest: "now" }, { pack });
  assert.ok(r.spl.includes('index="we\\"ird"'));
  assert.ok(r.spl.includes('userIdentity.accessKeyId="x\\" | delete"'));
  assert.ok(r.spl.includes('earliest="01/01/2026:00:00:00"'));
  assert.ok(r.spl.includes("latest=now"));
});

test("a placeholder passed as a value does not count as bound", () => {
  const r = generate(pack.edges[0], { index: "main", value: "$value$", earliest: "-1h" }, { pack });
  assert.deepEqual(r.missing, ["value"]);
});

test("asserted and proposed edges carry an asserted hazard first", () => {
  const e = { ...pack.edges[1], basis: "proposed", note: "Same field name on both sourcetypes." };
  const r = generate(e, { index: "main", value: "v", earliest: "-1h" }, { pack });
  assert.equal(r.asserted, true);
  assert.equal(r.hazards[0].level, "asserted");
  assert.ok(/Proposed by discovery/.test(r.hazards[0].text));
});

test("lint: pack-declared commands are allowed, forbidden ones never", () => {
  const ok = { ...pack.edges[1], spl: { required: ["value"], lines: ["search $index$ $sourcetype$ userIdentity.arn=$value$", "| dedup requestID", "| table _time eventName"] } };
  assert.ok(generate(ok, { index: "main", value: "v" }, { pack }).spl.includes("| dedup requestID"));
  const bad = { ...ok, spl: { required: ["value"], lines: ["search $index$ $sourcetype$ userIdentity.arn=$value$", "| join requestID [search index=main]"] } };
  assert.throws(() => generate(bad, { index: "main", value: "v" }, { pack: { ...pack, commands: ["join"] } }), (err) => err instanceof PivotError && err.code === "lint" && /forbidden command: join/.test(err.message));
  const unknown = { ...ok, spl: { required: ["value"], lines: ["search $index$ $sourcetype$ userIdentity.arn=$value$", "| mvexpand x"] } };
  assert.throws(() => generate(unknown, { index: "main", value: "v" }, { pack }), /not in allowlist: mvexpand/);
});

test("malformed templates fail loudly", () => {
  assert.throws(() => generate({ id: "x", src: { sourcetype: "a" }, spl: { lines: [{ clause: "x" }] } }, {}, { pack }), /string or \{ clause, needs/);
  assert.throws(() => generate({ id: "x" }, {}, { pack }), /edge needs spl.lines/);
});

test("validatePack renders every edge with dummy params", () => {
  assert.deepEqual(validatePack(pack), []);
  const broken = { ...pack, edges: [{ ...pack.edges[0], id: "b", spl: { lines: ["search $index$ $sourcetype$", "| join x"] } }] };
  const errs = validatePack(broken);
  assert.equal(errs.length, 1);
  assert.ok(/^b: /.test(errs[0]));
});

test("a :list token renders an array through quoteList; a scalar in the slot, or an array in a scalar slot, is refused", () => {
  const e = { ...pack.edges[1], spl: { required: ["names", "earliest"], lines: ["search $index$ $sourcetype$ earliest=$earliest:time$", "  eventName IN ($names:list$)", "| table _time eventName"] } };
  const r = generate(e, { index: "main", earliest: "-24h", names: ["ConsoleLogin", 'Assume"Role', ""] }, { pack });
  assert.ok(r.spl.includes('  eventName IN ("ConsoleLogin", "Assume\\"Role")'), r.spl);
  assert.deepEqual(r.missing, []);
  assert.throws(() => generate(e, { index: "main", earliest: "-24h", names: "ConsoleLogin" }, { pack }), (err) => err instanceof PivotError && err.code === "bad_list" && /takes a list of values, not a string/.test(err.message));
  // Unbound (absent, empty, or only blanks): missing, never IN ().
  for (const names of [undefined, [], ["", " "]]) {
    const u = generate(e, { index: "main", earliest: "-24h", names }, { pack });
    assert.deepEqual(u.missing, ["names"], JSON.stringify(names));
    assert.ok(u.spl.includes('eventName IN ("$names$")'));
  }
  // The scalar token never takes a list: quote() would join it into one string.
  assert.throws(() => generate(pack.edges[1], { index: "main", value: ["a", "b"], earliest: "-1h" }, { pack }), (err) => err instanceof PivotError && err.code === "bad_list");
  // KQL: the same token, kql.quoteList.
  const k = { id: "k", basis: "confirmed", src: { sourcetype: "T", field: "x" }, dst: { sourcetype: "T", field: "x" }, kql: { required: ["names", "earliest"], lines: ["$table$", "| where TimeGenerated > $earliest:time$", "| where EventName in ($names:list$)"] } };
  assert.ok(generate(k, { earliest: "-1d", names: ["a", "b"] }, { pack }).spl.includes('| where EventName in ("a", "b")'));
  assert.throws(() => generate(k, { earliest: "-1d", names: "a" }, { pack }), (err) => err instanceof PivotError && err.code === "bad_list");
  // validatePack binds a list token to a one-element list.
  assert.deepEqual(validatePack({ ...pack, edges: [e, k] }), []);
});

// A query template with every feature the FDR searches need: a field
// token, line gates both ways, a guard, a macro form, gated hazards and an
// index macro default.
const fdrPack = {
  id: "fdr-like",
  macros: ["cs_index", "cs_lookup"],
  hazards: {
    time: { level: "note", text: "Time bounds are on _time." },
    index_macro: { level: "note", text: "index=`cs_index` is a macro." },
    host: { level: "note", text: "Bind aid: faster." },
    rows: { level: "danger", text: "Expect several rows." },
  },
};
const query = {
  id: "q",
  basis: "confirmed",
  src: { sourcetype: "st", field: null },
  dst: { sourcetype: "st", field: null },
  hazards: ["rows", { ref: "host", unless: ["aid"] }, { ref: "index_macro", unless: ["index"] }, { ref: "time", needs: ["earliest"] }, { ref: "time", needs: ["latest"] }],
  spl: {
    required: ["field", "value", "earliest"],
    index_macro: "cs_index",
    guard: { all: ["earliest"], code: "unscoped", message: "the window is required." },
    lines: [
      { clause: "search $index$ $sourcetype$ earliest=$earliest:time$ latest=$latest:time$", needs: ["latest"] },
      { clause: "search $index$ $sourcetype$ earliest=$earliest:time$", unless: ["latest"] },
      { clause: "  aid=$aid$", needs: ["aid"] },
      "  $field:field$=$value$",
      "| table _time $field:field$",
    ],
    macro: { lines: ['`cs_lookup("$field:field$", $value$, $earliest:qtime$)`'] },
  },
};

test("a field token renders a validated identifier bare, on SPL and on KQL, and refuses anything else", () => {
  const r = generate(query, { field: "ImageFileName", value: "x", earliest: "-24h", index: "main" }, { pack: fdrPack });
  assert.equal(r.spl, ["search index=main sourcetype=st earliest=-24h", '  ImageFileName="x"', "| table _time ImageFileName"].join("\n"));
  assert.throws(() => generate(query, { field: "Bad Field", value: "x", earliest: "-24h" }, { pack: fdrPack }), (err) => err instanceof PivotError && err.code === "bad_identifier" && err.message === "field is not a valid identifier: Bad Field");
  const u = generate({ ...query, spl: { ...query.spl, guard: undefined } }, { value: "x" }, { pack: fdrPack });
  assert.ok(u.spl.includes('  $field$="x"'), u.spl);
  assert.deepEqual(u.missing, ["field", "earliest"]);
  const k = { id: "k", basis: "confirmed", src: { sourcetype: "T", field: "x" }, dst: { sourcetype: "T", field: "x" }, kql: { required: ["col", "value"], lines: ["$table$", "| where $col:field$ == $value$"] } };
  assert.equal(generate(k, { col: "Account", value: "v" }, { pack: fdrPack }).spl, 'T\n| where Account == "v"');
  assert.throws(() => generate({ ...k, kql: { required: [], lines: ["$table$", "| where t > $e:qtime$"] } }, { e: "-1h" }, { pack: fdrPack }), (err) => err.code === "bad_template");
});

test("a line gated unless renders only while its parameter is unbound; needs and unless combine on one line", () => {
  const without = generate(query, { field: "f", value: "x", earliest: "-24h", index: "main" }, { pack: fdrPack });
  assert.ok(without.spl.startsWith("search index=main sourcetype=st earliest=-24h\n"), without.spl);
  const withLatest = generate(query, { field: "f", value: "x", earliest: "-24h", latest: "now", index: "main" }, { pack: fdrPack });
  assert.ok(withLatest.spl.startsWith("search index=main sourcetype=st earliest=-24h latest=now\n"), withLatest.spl);
  const both = { ...query, spl: { ...query.spl, lines: [{ clause: "search $index$ $sourcetype$ a=$a$", needs: ["a"], unless: ["b"] }, { clause: "search $index$ $sourcetype$", unless: ["a"] }, { clause: "search $index$ $sourcetype$ a=$a$ b=$b$", needs: ["a", "b"] }] } };
  assert.equal(generate(both, { a: "1", earliest: "-1h" }, { pack: fdrPack }).spl, 'search index=`cs_index` sourcetype=st a="1"');
  assert.equal(generate(both, { a: "1", b: "2", earliest: "-1h" }, { pack: fdrPack }).spl, 'search index=`cs_index` sourcetype=st a="1" b="2"');
  assert.equal(generate(both, { earliest: "-1h" }, { pack: fdrPack }).spl, "search index=`cs_index` sourcetype=st");
});

test("the index macro stands in for an unbound index, which is then not missing; a bound index replaces it", () => {
  const r = generate(query, { field: "f", value: "x", earliest: "-24h" }, { pack: fdrPack });
  assert.ok(r.spl.startsWith("search index=`cs_index` sourcetype=st"));
  assert.deepEqual(r.missing, []);
  assert.ok(r.hazards.some((h) => h.text === fdrPack.hazards.index_macro.text));
  const b = generate(query, { field: "f", value: "x", earliest: "-24h", index: "main" }, { pack: fdrPack });
  assert.ok(!b.hazards.some((h) => h.text === fdrPack.hazards.index_macro.text));
});

test("a guard throws its code naming the unbound parameters before anything renders; placeholders do not satisfy it", () => {
  for (const params of [{ field: "f", value: "x" }, { field: "f", value: "x", earliest: "$earliest$" }, { field: "f", value: "x", earliest: " " }]) {
    assert.throws(() => generate(query, params, { pack: fdrPack }), (err) => err instanceof PivotError && err.code === "unscoped" && err.message === "the window is required. Unbound: earliest.");
  }
});

test("the macro form renders the macro call with quoted time arguments and only its own parameters missing", () => {
  const r = generate(query, { field: "ImageFileName", earliest: "2022-07-27T10:40:00", index: "main" }, { pack: fdrPack, form: "macro" });
  assert.equal(r.form, "macro");
  assert.equal(r.spl, '`cs_lookup("ImageFileName", "$value$", "07/27/2022:10:40:00")`');
  assert.deepEqual(r.missing, ["value"]);
  assert.equal(r.sourcetype, "st");
  assert.equal(generate(query, { field: "f", value: "v", earliest: "-24h" }, { pack: fdrPack, form: "macro" }).spl, '`cs_lookup("f", "v", "-24h")`');
});

test("no_macro: no macro at all, or a parameter the inline lines carry and the macro cannot; latest at now and the index do not count", () => {
  const noMacro = { ...query, spl: { ...query.spl, macro: undefined } };
  assert.throws(() => generate(noMacro, { field: "f", value: "v", earliest: "-1h" }, { pack: fdrPack, form: "macro" }), (err) => err.code === "no_macro");
  assert.throws(() => generate(query, { field: "f", value: "v", earliest: "-1h", aid: "a" }, { pack: fdrPack, form: "macro" }), (err) => err.code === "no_macro" && /cannot carry aid/.test(err.message));
  assert.throws(() => generate(query, { field: "f", value: "v", earliest: "-1h", latest: "-5m" }, { pack: fdrPack, form: "macro" }), (err) => err.code === "no_macro" && /latest/.test(err.message));
  assert.equal(generate(query, { field: "f", value: "v", earliest: "-1h", latest: "now", index: "main" }, { pack: fdrPack, form: "macro" }).form, "macro");
  assert.throws(() => generate(query, { field: "f", value: "v" }, { pack: fdrPack, form: "macro" }), (err) => err.code === "unscoped", "the guard holds in the macro form too");
});

test("hazards gate on the bound parameters and repeat no text", () => {
  const texts = (r) => r.hazards.map((h) => h.text);
  const bare = generate(query, { field: "f", value: "v", earliest: "-1h" }, { pack: fdrPack });
  assert.deepEqual(texts(bare), [fdrPack.hazards.rows.text, fdrPack.hazards.host.text, fdrPack.hazards.index_macro.text, fdrPack.hazards.time.text]);
  const scoped = generate(query, { field: "f", value: "v", earliest: "-1h", latest: "now", aid: "a", index: "main" }, { pack: fdrPack });
  assert.deepEqual(texts(scoped), [fdrPack.hazards.rows.text, fdrPack.hazards.time.text]);
  assert.deepEqual(texts(generate(query, { field: "f", value: "v", earliest: "-1h", aid: "a", index: "main" }, { pack: fdrPack })), [fdrPack.hazards.rows.text, fdrPack.hazards.time.text]);
  const inlineObject = { ...query, hazards: [{ level: "caution", text: "own words", needs: ["aid"] }] };
  assert.deepEqual(texts(generate(inlineObject, { field: "f", value: "v", earliest: "-1h" }, { pack: fdrPack })), []);
  assert.deepEqual(texts(generate(inlineObject, { field: "f", value: "v", earliest: "-1h", aid: "a" }, { pack: fdrPack })), ["own words"]);
});

test("missing follows the required order first, then the lines", () => {
  const t = { ...query, spl: { ...query.spl, guard: undefined, required: ["value", "field"] } };
  assert.deepEqual(generate(t, {}, { pack: fdrPack }).missing, ["value", "field", "earliest"]);
});

test("validatePack renders the macro form too and reports a macro that cannot carry its guard", () => {
  assert.deepEqual(validatePack({ ...fdrPack, edges: [query] }), []);
  const badMacro = { ...query, spl: { ...query.spl, macro: { lines: ["`cs_lookup($value$)`"] } } };
  assert.ok(validatePack({ ...fdrPack, edges: [badMacro] }).some((e) => /cannot carry earliest/.test(e)), "a macro that cannot carry a guarded parameter never renders");
  const unknownMacro = { ...query, spl: { ...query.spl, macro: { lines: ['`cs_other("$field:field$", $value$, $earliest:qtime$)`'] } } };
  assert.ok(validatePack({ ...fdrPack, edges: [unknownMacro] }).some((e) => /unknown macro: cs_other/.test(e)));
  const badIndexMacro = { ...query, spl: { ...query.spl, index_macro: "cs index" } };
  assert.ok(validatePack({ ...fdrPack, edges: [badIndexMacro] }).some((e) => /index_macro/.test(e)));
});
