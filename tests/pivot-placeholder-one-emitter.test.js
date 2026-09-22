// pivot.js is the one place that decides whether a rendered SPL/KQL
// parameter is still an unfilled $name$ placeholder (PLACEHOLDER_RE,
// isBound()); fdr-queries.js used to keep its own copy of both, which is
// exactly the drift this guards against (it now imports pivot.js's).
// query-plan token vocabularies (lang.js, intent.js: $name, no closing
// $, a different shape for a different layer, already named in their own
// docstrings) and drawer.js's identical copy for <mark> highlighting
// (display only, never a bound-ness test) are not this: only a second
// definition of `isBound` or `PLACEHOLDER_RE` itself is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..", "app");
// pivot.js is the definition; scope.js's own isBound() is a private,
// unrelated, unexported check ("is an index already given", no
// placeholder regex at all) that happens to share a name.
const ALLOW = new Set(["lib/pivot.js", "lib/scope.js"]);
const REDEFINITION = /\b(?:function isBound|const PLACEHOLDER_RE)\b/;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (name.endsWith(".js")) out.push(p);
  }
  return out;
}

test("no module outside pivot.js redefines isBound() or PLACEHOLDER_RE; every other caller imports pivot.js's", () => {
  const offenders = [];
  for (const file of walk(ROOT)) {
    const rel = file.slice(ROOT.length + 1).replace(/\\/g, "/");
    if (ALLOW.has(rel)) continue;
    const text = readFileSync(file, "utf8");
    if (REDEFINITION.test(text)) offenders.push(rel);
  }
  assert.deepEqual(offenders, []);
});
