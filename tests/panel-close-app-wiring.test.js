// app.js's half of it_3cb327f3: a real browser is the only thing that can
// drive chrome.tabs.getCurrent/chrome.windows.getCurrent and an actual
// window.close() on a side panel document (see the report), so this reads
// the source for the guards those two functions must carry rather than
// running them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const src = await readFile(new URL("../app/app.js", import.meta.url), "utf8");

test("a top-level tab sends reach:app:opened, guarded against a framed copy", () => {
  assert.match(src, /import \{ hasUnsavedInput \} from "\.\/lib\/panel-close\.js";/);
  const fn = src.slice(src.indexOf("function announceTopLevelOpen"), src.indexOf("function closePanelIfClean"));
  assert.match(fn, /window\.top !== window/, "checks window.top");
  assert.match(fn, /window\.REACH_FRAMED/, "checks the boot.js framed flag");
  assert.match(fn, /type: "reach:app:opened"/);
});

test("the panel closes only when nothing is unsaved", () => {
  const fn = src.slice(src.indexOf("function closePanelIfClean"));
  assert.match(fn, /hasUnsavedInput\(document\)/);
  assert.match(fn, /window\.close\(\)/);
  // hasUnsavedInput is checked before window.close() is ever reached.
  assert.ok(fn.indexOf("hasUnsavedInput") < fn.indexOf("window.close()"));
});

test("the port listener closes the panel on reach:panel:close, beside the existing reach:selection handler", () => {
  assert.match(src, /msg\.type === "reach:panel:close"\) closePanelIfClean\(\)/);
  assert.match(src, /msg\.type === "reach:selection" && msg\.selection/);
});
