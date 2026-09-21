// lang.js is the one table over the two query languages: a caller picks
// quote, time and lint by name, both lints answer one shape, and the two
// compilers refuse the same things with the same CompileError.
import { test } from "node:test";
import assert from "node:assert/strict";
import { LANG, lang, CompileError, paramToken, literalText, TOKEN_RE } from "../app/lib/lang.js";
import * as spl from "../app/lib/spl.js";
import * as kql from "../app/lib/kql.js";
import * as compileSpl from "../app/lib/compile-spl.js";
import * as compileKql from "../app/lib/compile-kql.js";

test("spl.lint and kql.lint answer one shape, ok, violations and warnings, and both take an options object", () => {
  for (const [name, verdict] of [
    ["spl clean", spl.lint("search index=main sourcetype=x | stats count", { commands: [], macros: [] })],
    ["spl empty", spl.lint("", {})],
    ["spl forbidden", spl.lint("search x | join y")],
    ["kql clean", kql.lint("T | where TimeGenerated > ago(1d) | take 5", { commands: [] })],
    ["kql empty", kql.lint("")],
    ["kql warned", kql.lint("T | take 5")],
  ]) {
    assert.deepEqual(Object.keys(verdict).sort(), ["ok", "violations", "warnings"], name);
    assert.equal(typeof verdict.ok, "boolean", name);
    assert.ok(Array.isArray(verdict.violations) && Array.isArray(verdict.warnings), name);
  }
  assert.deepEqual(spl.lint("search x | join y"), { ok: false, violations: ["forbidden command: join"], warnings: [] });
  assert.equal(kql.lint("T | take 5").warnings.length, 1);
});

test("LANG picks the language's quote, list, time and lint by name; an unknown name is CompileError bad_lang", () => {
  assert.equal(LANG.spl.quote('a"b'), spl.quote('a"b'));
  assert.equal(LANG.kql.quote("a\nb"), kql.quote("a\nb"));
  assert.equal(LANG.spl.time("2026-09-17T23:06:00Z"), spl.timeModifier("2026-09-17T23:06:00Z"));
  assert.equal(LANG.kql.time("-24h"), "ago(24h)");
  assert.equal(LANG.spl.quoteList(["a", "b"]), '"a", "b"');
  assert.equal(LANG.kql.lint("T | where TimeGenerated > ago(1d)").ok, true);
  assert.equal(lang("kql"), LANG.kql);
  assert.throws(() => lang("sql"), (e) => e instanceof CompileError && e.code === "bad_lang");
  assert.ok(new LANG.spl.Error("x") instanceof spl.SplError);
  assert.ok(new LANG.kql.Error("x") instanceof kql.KqlError);
});

test("CompileError takes (code, message) in both compilers, and it is one class", () => {
  assert.equal(compileSpl.CompileError, CompileError);
  assert.equal(compileKql.CompileError, CompileError);
  const e = new CompileError("bad_plan", "compile takes a Plan");
  assert.equal(e.code, "bad_plan");
  assert.equal(e.message, "compile takes a Plan");
  assert.equal(new CompileError("bad_plan").message, "bad_plan");
  assert.throws(() => compileSpl.compile(null), (err) => err instanceof CompileError && err.code === "bad_plan");
  assert.throws(() => compileKql.compile(null), (err) => err instanceof CompileError && err.code === "bad_plan");
});

test("a token-shaped pack literal is refused with the same code on both platforms, and a plain literal passes", () => {
  assert.throws(() => literalText("x $value$ y", "filter[0]"), { name: "CompileError", code: "literal_token" });
  assert.throws(() => literalText(null, "filter[0]"), { name: "CompileError", code: "bad_literal" });
  assert.throws(() => literalText({}, "filter[0]"), { name: "CompileError", code: "bad_literal" });
  assert.equal(literalText("HOST$"), "HOST$");
  assert.equal(literalText(403), "403");
  assert.equal(literalText(true), "true");
  assert.equal(TOKEN_RE.test("cost$"), false);
  assert.equal(TOKEN_RE.test("$latest:time$"), true);
});

test("paramToken validates the name and writes the kind after a colon", () => {
  assert.equal(paramToken("value"), "$value$");
  assert.equal(paramToken("since", "time"), "$since:time$");
  assert.equal(paramToken("names", "list"), "$names:list$");
  assert.throws(() => paramToken("no-dash", "", "window.since"), (e) => e instanceof CompileError && e.code === "bad_param" && /window\.since/.test(e.message));
  assert.throws(() => paramToken(42), { code: "bad_param" });
});
