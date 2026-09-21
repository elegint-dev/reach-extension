// The $name:prefixes$ token: a starts-with-any match rendered for each
// language from one list, with every regex metacharacter escaped on the
// KQL side and a wildcard appended on the SPL side; a scalar is refused
// and an empty list is unbound.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as pivot from "../app/lib/pivot.js";

const PATHS = ["/usr/bin/", "/System/Applications/Font Book.app/", "/x/iCloud+.app/", "/y/(beta)/"];
const spl = { id: "t", basis: "confirmed", src: { sourcetype: "a" }, dst: { sourcetype: "a" }, spl: { lines: ["search index=main ImageFileName IN ($paths:prefixes$)"] } };
const kql = { id: "t", basis: "confirmed", src: { sourcetype: "T" }, dst: { sourcetype: "T" }, kql: { lines: ["$table$", "| where TimeGenerated > ago(1d)", "| where ImageFileName matches regex $paths:prefixes$"] } };

test("SPL renders each prefix as a quoted glob for IN (...)", () => {
  const out = pivot.generate(spl, { paths: PATHS });
  assert.equal(out.spl, 'search index=main ImageFileName IN ("/usr/bin/*", "/System/Applications/Font Book.app/*", "/x/iCloud+.app/*", "/y/(beta)/*")');
  assert.deepEqual(out.missing, []);
});

test("KQL renders one anchored alternation in a verbatim string with the metacharacters escaped and slashes left alone", () => {
  const out = pivot.generate(kql, { paths: PATHS });
  assert.equal(out.spl.split("\n")[2], '| where ImageFileName matches regex @"^(?:/usr/bin/|/System/Applications/Font Book\\.app/|/x/iCloud\\+\\.app/|/y/\\(beta\\)/)"');
  assert.equal(out.lang, "kql");
});

test("an unbound prefixes token is reported missing and rendered as its placeholder", () => {
  const out = pivot.generate(spl, {});
  assert.deepEqual(out.missing, ["paths"]);
  assert.match(out.spl, /IN \("\$paths\$"\)/);
});

test("a scalar in a prefixes slot is refused; an empty or all-blank list is unbound, not a search", () => {
  assert.throws(() => pivot.generate(spl, { paths: "/usr/bin/" }), (e) => e.name === "PivotError" && e.code === "bad_list");
  assert.deepEqual(pivot.generate(kql, { paths: [] }).missing, ["paths"]);
  assert.deepEqual(pivot.generate(spl, { paths: ["", " "] }).missing, ["paths"]);
});

test("a query with a prefixes token validates with a list dummy, and a time token with a time dummy whatever its name", () => {
  const pack = { queries: [], edges: [{ id: "e", basis: "confirmed", src: { concept: "x" }, dst: { concept: "x" }, spl: { lines: ["search index=main earliest=$window:time$ ImageFileName IN ($paths:prefixes$)"] } }] };
  assert.deepEqual(pivot.validatePack(pack), []);
});
