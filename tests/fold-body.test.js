// The shared fold-body invariant (app/components/foldBody.js): an open
// collapsible draws as one block, header then body then the closing line;
// the line never sits between header and body.
//
// Two checks. First, the registry below names every collapsible in app/
// (a native <details> fold or a class-toggled block that opens the same
// way) and what it must do to conform: "shared" callers carry the
// r-fold__body class and key their closing line to the fold's open state;
// "margin" callers are native <details> spaced by margin, never a border,
// so the failure this invariant guards against cannot occur; "popup"
// callers render inside an injected Splunk or Sentinel page, outside this
// app and its stylesheet. Second, a sweep of app/ for files that build a
// native <details> is compared against the registry's own list of such
// files: an unregistered file (new or renamed) fails, so a new collapsible
// that skips the shared pattern is caught here, not by eyeballing a diff.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");
const appDir = path.join(repoRoot, "app");
const css = readFileSync(path.join(appDir, "styles", "components.css"), "utf8");

const REGISTRY = [
  { file: "app/components/holding.js", marker: "r-holding__body", kind: "shared", details: false },
  { file: "app/components/drawer.js", marker: "r-drawer", kind: "shared", details: false },
  { file: "app/components/drawer.js", marker: "r-drawer__macro-install", kind: "margin", details: true },
  { file: "app/app.js", marker: "r-paste", kind: "shared", details: true },
  { file: "app/components/ledger.js", marker: "r-ledger__fold", kind: "margin", details: true },
  { file: "app/views/value.js", marker: "r-fold", kind: "margin", details: true }, // Other sourcetypes
  { file: "app/views/field.js", marker: "r-others", kind: "margin", details: true }, // Other sourcetypes
  { file: "app/views/field.js", marker: "r-decode", kind: "margin", details: true },
  { file: "app/views/field.js", marker: "r-samerole", kind: "margin", details: true },
  { file: "app/views/field.js", marker: "r-title__flags", kind: "margin", details: true },
  { file: "app/components/dictionary.js", marker: "r-decode", kind: "margin", details: true },
  { file: "app/views/sourcetype.js", marker: "r-typelist__wrap", kind: "margin", details: true },
  { file: "app/views/sourcetype.js", marker: "r-rolelist__group", kind: "margin", details: true },
  { file: "app/views/event.js", marker: "r-rolelist__group", kind: "margin", details: true },
  { file: "app/views/coverage.js", marker: "r-cov__feed", kind: "margin", details: true },
  { file: "app/views/coverage.js", marker: "r-cov__aside", kind: "margin", details: true },
  { file: "app/components/sourceTable.js", marker: "r-source-table__more", kind: "margin", details: true },
  { file: "app/components/annotation.js", marker: "r-ann__under", kind: "margin", details: true },
  { file: "app/components/meaning.js", marker: "r-meaning__evidence", kind: "margin", details: true },
  { file: "app/components/advisor.js", marker: "r-advisor--line", kind: "margin", details: true },
  { file: "app/views/notebook.js", marker: "r-nb__thread", kind: "margin", details: true },
  { file: "app/components/settingsBar.js", marker: "r-settings", kind: "margin", details: true },
  { file: "app/components/moduleList.js", marker: "r-module__fold", kind: "margin", details: true },
  { file: "app/lib/click-splunk.js", marker: "reach-details", kind: "popup", details: true },
  { file: "app/lib/click-section.js", marker: "reach-details", kind: "popup", details: true },
  { file: "app/lib/bands/pattern.js", marker: "reach-pattern__more", kind: "popup", details: true },
  { file: "app/lib/bands/band.js", marker: "reach-fold", kind: "popup", details: true },
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules") continue;
    const full = path.join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, out);
    else if (name.endsWith(".js")) out.push(full);
  }
  return out;
}

function relative(full) {
  return path.relative(repoRoot, full).split(path.sep).join("/");
}

test("every registered collapsible's marker class is still where the registry says", () => {
  for (const { file, marker } of REGISTRY) {
    const text = readFileSync(path.join(repoRoot, file), "utf8");
    assert.ok(text.includes(marker), `${file} no longer mentions "${marker}"; update the fold-body registry`);
  }
});

test("no file outside the registry builds a native <details> fold", () => {
  const found = new Set();
  for (const full of walk(appDir)) {
    const text = readFileSync(full, "utf8");
    if (/\bh\(\s*["']details["']/.test(text)) found.add(relative(full));
  }
  const known = new Set(REGISTRY.filter((r) => r.details).map((r) => r.file));
  const unregistered = [...found].filter((f) => !known.has(f));
  const missing = [...known].filter((f) => !found.has(f));
  assert.deepEqual(unregistered, [], "a details fold appeared outside the registry: add it and pick a kind (shared/margin/popup)");
  assert.deepEqual(missing, [], "a registered details fold is gone from its file: update the registry");
});

test("shared collapsibles (rail and paste/drawer) use the foldBody.js pattern, not their own border rule", () => {
  for (const { file, kind } of REGISTRY.filter((r) => r.kind === "shared" && !r.details)) {
    const text = readFileSync(path.join(repoRoot, file), "utf8");
    assert.ok(text.includes("foldBody"), `${file} draws a fold body but does not use foldBody.js`);
  }
  assert.match(css, /\.r-paste\[open\]\s*>\s*\.r-fold__body/, "the paste fold keys its closing line to the shared class, not .r-drawer directly");
  assert.match(css, /\.r-holding\.is-open\s+\.r-fold__body/, "the rail keys its closing line to the shared class, not .r-holding__body directly");
});

test("an open fold-body's closing line never sits between header and body (no border-top on the body, in either open shape)", () => {
  const bodyBlocks = [...css.matchAll(/\.r-holding__body\s*\{[^}]*\}/g)].map((m) => m[0]);
  assert.ok(bodyBlocks.length > 0, "no .r-holding__body rule found");
  for (const block of bodyBlocks) assert.ok(!/border-top/.test(block), `a .r-holding__body rule still sets border-top, splitting header from body:\n${block}`);

  const drawerOpen = css.match(/\.r-paste\[open\]\s*>\s*\.r-fold__body\s*\{[^}]*\}/);
  assert.ok(drawerOpen, "no .r-paste[open] > .r-fold__body rule found");
  assert.match(drawerOpen[0], /border-top:\s*0/, "the paste fold's open body should zero its own top border so the header's border is the only one between them");
});

test("the shared fold-body closing line draws after the body, once, per open shape", () => {
  const railClose = css.match(/\.r-holding\.is-open\s+\.r-fold__body\s*\{[^}]*\}/);
  assert.ok(railClose, "no rail closing-line rule found");
  assert.match(railClose[0], /border-bottom/, "the rail's open body should carry the closing line as a border-bottom, after everything in it");
});
