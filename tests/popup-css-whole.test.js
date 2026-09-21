// POPUP_CSS interpolates the bands' stylesheets when popup-shell.js
// evaluates. A band that imported the shell back would leave its string
// uninitialised at that moment and the sheet would read "undefined" in
// place of its rules. The band that does import the shell (meaning.js,
// for fieldHash) loads first here, so the sheet is checked in the order
// that would expose a cycle.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";

await import("../app/lib/bands/meaning.js");
const shell = await import("../app/lib/popup-shell.js");
const { PATTERN_CSS } = await import("../app/lib/bands/pattern.js");
const { VERDICT_CSS } = await import("../app/lib/bands/verdict.js");
const { ENRICH_CSS } = await import("../app/lib/bands/enrich.js");
const { HOLD_CSS, BENIGN_CSS } = await import("../app/lib/bands/hold-and-benign.js");

test("POPUP_CSS carries every band's stylesheet whole, with a band loaded before the shell", () => {
  for (const [name, css] of Object.entries({ PATTERN_CSS, VERDICT_CSS, ENRICH_CSS, HOLD_CSS, BENIGN_CSS })) {
    assert.ok(css.length > 100, `${name} has rules`);
    assert.ok(shell.POPUP_CSS.includes(css), `POPUP_CSS carries ${name}`);
  }
  assert.ok(!shell.POPUP_CSS.includes("undefined"), "no band string was in its temporal dead zone when the sheet was composed");
});

test("no band module imports the shell except meaning.js, which contributes no stylesheet", async () => {
  const { readFileSync, readdirSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const dir = fileURLToPath(new URL("../app/lib/bands/", import.meta.url));
  const importsShell = (f) => /from\s+["']\.\.\/popup-shell\.js["']/.test(readFileSync(dir + f, "utf8"));
  const offenders = readdirSync(dir).filter((f) => f.endsWith(".js") && f !== "meaning.js" && importsShell(f));
  assert.deepEqual(offenders, []);
  assert.ok(!/_CSS\s*=/.test(readFileSync(dir + "meaning.js", "utf8")), "meaning.js exports no stylesheet");
});
