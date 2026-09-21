// editor-bridge.js: the placement of a term or a stage into a query
// (pure), the runtime message the side panel sends the page, and what
// apply() does with no search bar in reach.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as bridge from "../app/lib/editor-bridge.js";
import { fakeChrome } from "./_chrome.js";

// Node defines navigator as a getter on the global; a clipboard stub goes
// in through defineProperty and the original comes back after.
function withClipboard(written, fn) {
  const had = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { value: { clipboard: { writeText: async (t) => written.push(t) } }, configurable: true, writable: true });
  return Promise.resolve().then(fn).finally(() => {
    if (had) Object.defineProperty(globalThis, "navigator", had);
    else delete globalThis.navigator;
  });
}

const { place, findTerm, searchBlock, pipePositions } = bridge;

test("pipePositions: pipes inside quotes, subsearches and parentheses are not top-level", () => {
  const q = 'index=a "x|y" [search b | fields c] (d | e) | stats count | table x';
  assert.deepEqual(pipePositions(q).map((i) => q.slice(i, i + 7)), ["| stats", "| table"]);
});

test("searchBlock: the text before the first top-level pipe; a generating command has none", () => {
  assert.deepEqual(searchBlock("index=a b | stats count", "spl"), { start: 0, end: 10, empty: false });
  assert.equal(searchBlock("| tstats count where index=a", "spl").empty, true);
  assert.equal(searchBlock("", "spl").empty, true);
});

test("append a term: joins the search block before the first pipe, implicit AND", () => {
  const out = place("index=main sourcetype=x | stats count", 'Image="C:\\\\x.exe"', { mode: "append", form: "term", field: "Image" });
  assert.equal(out.text, 'index=main sourcetype=x Image="C:\\\\x.exe" | stats count');
  assert.equal(out.how, "appended");
});

test("append a term: a newline before the pipe is kept where it was", () => {
  const out = place("index=main sourcetype=x\n| stats count", 'a="1"', { mode: "append", form: "term", field: "a" });
  assert.equal(out.text, 'index=main sourcetype=x a="1"\n| stats count');
});

test("append a term: a top-level OR in the block is wrapped so the AND binds the whole block", () => {
  const out = place("search index=main a OR b | stats count", 'Image="x"', { mode: "append", form: "term", field: "Image" });
  assert.equal(out.text, 'search (index=main a OR b) Image="x" | stats count');
});

test("append a term: an OR inside a subsearch or quotes does not wrap", () => {
  assert.equal(place('index=main [search a OR b] "c OR d" | stats count', "e=1", { mode: "append", form: "term", field: "e" }).text, 'index=main [search a OR b] "c OR d" e=1 | stats count');
});

test("append a term: a query that opens with a generating command gets a | search stage", () => {
  const out = place("| tstats count where index=main by host", 'host="a"', { mode: "append", form: "term", field: "host" });
  assert.equal(out.text, '| tstats count where index=main by host\n| search host="a"');
});

test("append a stage: on the end of the pipeline, on its own line", () => {
  const out = place("index=main sourcetype=x | stats count", '| regex Image="^C"', { mode: "append", form: "stage", field: "Image" });
  assert.equal(out.text, 'index=main sourcetype=x | stats count\n| regex Image="^C"');
  assert.equal(out.how, "appended");
});

test("an empty query becomes the text itself, whichever mode was asked", () => {
  for (const mode of ["append", "replace", "cursor"]) {
    const out = place("   ", 'host="a"', { mode, form: "term", field: "host" });
    assert.equal(out.text, 'host="a"');
    assert.equal(out.how, "set");
  }
});

test("set: the text is the whole query", () => {
  assert.deepEqual(place("index=main", "x", { mode: "set" }), { text: "x", how: "set", found: null });
});

test("replace: the field's existing term in the search block is swapped, a quoted value with spaces included", () => {
  const out = place('index=main Image="C:\\\\Program Files\\\\a.exe" host=b | stats count', 'Image="C:\\\\*\\\\a.exe"', { mode: "replace", form: "term", field: "Image" });
  assert.equal(out.text, 'index=main Image="C:\\\\*\\\\a.exe" host=b | stats count');
  assert.equal(out.how, "replaced");
  assert.equal(out.found, true);
});

test("replace: a TERM() that precedes the field test goes with it; an IN list is one term; a != term counts", () => {
  assert.equal(place('index=main TERM(1.2.3.4) src_ip="1.2.3.4" | stats count', 'src_ip="1.2.3.0/24"', { mode: "replace", form: "term", field: "src_ip" }).text, 'index=main src_ip="1.2.3.0/24" | stats count');
  assert.equal(place('index=main src_ip IN ("a", "b") | stats count', 'src_ip="c"', { mode: "replace", form: "term", field: "src_ip" }).text, 'index=main src_ip="c" | stats count');
  assert.equal(place('index=main src_ip!="a" | stats count', 'src_ip="c"', { mode: "replace", form: "term", field: "src_ip" }).text, 'index=main src_ip="c" | stats count');
});

test("replace: a term on a field whose name is a suffix of another is not confused", () => {
  const out = place('index=main dest_ip="9.9.9.9" src_ip="1.1.1.1" | stats count', 'src_ip="2.2.2.2"', { mode: "replace", form: "term", field: "src_ip" });
  assert.equal(out.text, 'index=main dest_ip="9.9.9.9" src_ip="2.2.2.2" | stats count');
});

test("replace: only the search block is searched; the same field in a later stage stays", () => {
  const out = place('index=main src_ip="1.1.1.1" | where src_ip="2.2.2.2"', 'src_ip="3.3.3.3"', { mode: "replace", form: "term", field: "src_ip" });
  assert.equal(out.text, 'index=main src_ip="3.3.3.3" | where src_ip="2.2.2.2"');
});

test("replace with no term on the field falls to append and says found: false", () => {
  const out = place("index=main sourcetype=x | stats count", 'src_ip="c"', { mode: "replace", form: "term", field: "src_ip" });
  assert.equal(out.text, 'index=main sourcetype=x src_ip="c" | stats count');
  assert.equal(out.how, "appended");
  assert.equal(out.found, false);
});

test("replace of a stage rung is an append: a stage has no term to swap", () => {
  const out = place('index=main Image="a" | stats count', '| regex Image="^a"', { mode: "replace", form: "stage", field: "Image" });
  assert.equal(out.text, 'index=main Image="a" | stats count\n| regex Image="^a"');
});

test("findTerm: a field with dots in its name is escaped, not read as a regex", () => {
  const hit = findTerm('userIdentity.arn="x" userIdentityXarn="y"', "userIdentity.arn", "spl");
  assert.equal(hit.text, 'userIdentity.arn="x"');
});

test("KQL: a term appends as a | where stage; a stage appends as it is", () => {
  assert.equal(place("SecurityEvent | take 10", 'Image startswith "C:"', { mode: "append", form: "term", field: "Image", platform: "sentinel" }).text, 'SecurityEvent | take 10\n| where Image startswith "C:"');
  assert.equal(place("SecurityEvent", '| extend x = extract("a", 1, Image)', { mode: "append", form: "stage", field: "Image", platform: "kql" }).text, 'SecurityEvent\n| extend x = extract("a", 1, Image)');
});

test("KQL: replace swaps the column's test inside a | where stage", () => {
  const out = place('SecurityEvent\n| where Image == "x" and Account has "a"', 'Image startswith "C:\\\\"', { mode: "replace", form: "term", field: "Image", platform: "kql" });
  assert.equal(out.text, 'SecurityEvent\n| where Image startswith "C:\\\\" and Account has "a"');
  assert.equal(out.found, true);
});

test("the relay message names its type and carries the request whole", () => {
  assert.equal(bridge.APPLY_MESSAGE, "reach:editor:apply");
  assert.equal(bridge.onMessage({ type: "something:else" }), null);
  assert.equal(bridge.onMessage(null), null);
});

test("where: with no document and no chrome.tabs the bridge can only copy", () => {
  assert.equal(bridge.where(), "clipboard");
});

test("apply on Sentinel copies with a notice, whatever the mode", async () => {
  const written = [];
  await withClipboard(written, async () => {
    const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "append", platform: "sentinel" });
    assert.equal(res.ok, true);
    assert.equal(res.how, "copied");
    assert.match(res.notice, /Logs editor/);
  });
  assert.deepEqual(written, ['Image startswith "C:"']);
});

test("apply on Splunk with no search bar in reach copies and says where to paste", async () => {
  const written = [];
  await withClipboard(written, async () => {
    const res = await bridge.apply({ text: 'a="1"', form: "term", field: "a", mode: "append", platform: "splunk" });
    assert.equal(res.how, "copied");
    assert.match(res.notice, /search bar/);
  });
  assert.deepEqual(written, ['a="1"']);
});

test("apply with no clipboard either reports it instead of throwing", async () => {
  const res = await bridge.apply({ text: "x", platform: "sentinel" });
  assert.equal(res.ok, false);
  assert.match(res.notice, /clipboard/);
});

test("onMessage with no search bar answers ok: false rather than touching the page", async () => {
  const res = await bridge.onMessage({ type: bridge.APPLY_MESSAGE, text: "x", mode: "append" });
  assert.equal(res.ok, false);
  assert.match(res.notice, /no search bar/);
});

// ---------------------------------------------------------------------------
// readFromTab: the read counterpart of apply's tab relay. A chrome.tabs
// stub stands in for the extension APIs; no globalThis.document in these
// tests, so the bridge is never in the page itself.

function withChromeTabs(tabsImpl, fn) {
  const fake = fakeChrome({ id: "reach" });
  fake.chrome.tabs = tabsImpl;
  const restore = fake.install();
  return Promise.resolve().then(fn).finally(restore);
}

test("READ_MESSAGE names the read relay, a sibling of the apply one", () => {
  assert.equal(bridge.READ_MESSAGE, "reach:editor:read");
  assert.equal(bridge.onReadMessage({ type: "something:else" }), null);
  assert.equal(bridge.onReadMessage(null), null);
});

test("readFromTab: the active tab's content script gets the request, and its reply comes back whole", async () => {
  const sent = [];
  const res = await withChromeTabs(
    {
      query: async (opts) => {
        assert.deepEqual(opts, { active: true, lastFocusedWindow: true });
        return [{ id: 7 }];
      },
      sendMessage: async (tabId, msg) => {
        sent.push([tabId, msg]);
        return { ok: true, text: "index=main sourcetype=x", cursor: 5 };
      },
    },
    () => bridge.readFromTab(),
  );
  assert.deepEqual(sent, [[7, { type: bridge.READ_MESSAGE }]]);
  assert.deepEqual(res, { ok: true, text: "index=main sourcetype=x", cursor: 5 });
});

test("readFromTab: no runtime, no active tab, or no content script there all fall back to null, not a throw", async () => {
  assert.equal(await bridge.readFromTab(), null, "no chrome at all");
  assert.equal(
    await withChromeTabs({ query: async () => [], sendMessage: async () => ({ ok: true, text: "x" }) }, () => bridge.readFromTab()),
    null,
    "no active tab",
  );
  assert.equal(
    await withChromeTabs(
      {
        query: async () => [{ id: 3 }],
        sendMessage: async () => {
          throw new Error("Could not establish connection");
        },
      },
      () => bridge.readFromTab(),
    ),
    null,
    "no content script in that tab",
  );
});

test("onReadMessage with no search bar answers ok: false with an empty text and cursor, rather than touching the page", async () => {
  const res = await bridge.onReadMessage({ type: bridge.READ_MESSAGE });
  assert.equal(res.ok, false);
  assert.match(res.reason, /no search bar/);
  assert.equal(res.text, "");
  assert.equal(res.cursor, null);
});

// ---------------------------------------------------------------------------
// Sentinel: the Logs blade's Monaco through sentinel-editor-inject.js. The
// real inject runs in a vm context over a fake window, document and monaco;
// the bridge talks to it through the shared document, as in the blade.

import vm from "node:vm";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const INJECT = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "sentinel-editor-inject.js"), "utf8");

class FakeRange {
  constructor(a, b, c, d) {
    Object.assign(this, { startLineNumber: a, startColumn: b, endLineNumber: c, endColumn: d });
  }
}

function fakeModel(text, language = "kusto") {
  const lines = () => text.split("\n");
  const end = () => ({ lineNumber: lines().length, column: lines()[lines().length - 1].length + 1 });
  const full = () => Object.assign(new FakeRange(1, 1, end().lineNumber, end().column), { getEndPosition: end, collapseToEnd: () => new FakeRange(end().lineNumber, end().column, end().lineNumber, end().column) });
  const model = {
    ops: [],
    stack: 0,
    getValue: () => text,
    getFullModelRange: full,
    getLanguageId: () => language,
    pushStackElement: () => model.stack++,
    pushEditOperations: (sel, edits) => {
      model.ops.push({ edits, stackBefore: model.stack });
      for (const op of edits) model.applyOp(op);
      return null;
    },
    applyOp: (op) => {
      text = op.range.startLineNumber === 1 && op.range.startColumn === 1 && op.range.endLineNumber === end().lineNumber ? op.text : text + op.text;
    },
  };
  return model;
}

function fakeEditor({ width = 800, height = 200, text = "", focus = false } = {}) {
  const model = fakeModel(text);
  const ed = {
    edits: [],
    undoStops: 0,
    node: { getBoundingClientRect: () => ({ width, height }), style: {} },
    getDomNode: () => ed.node,
    getModel: () => model,
    hasTextFocus: () => focus,
    getPosition: () => ({ lineNumber: 1, column: 3 }),
    getSelection: () => new FakeRange(1, 3, 1, 3),
    pushUndoStop: () => ed.undoStops++,
    executeEdits: (src, ops) => {
      ed.edits.push({ src, ops, stopsBefore: ed.undoStops });
      for (const op of ops) model.applyOp(op);
    },
    setPosition: () => {},
    revealPositionInCenterIfOutsideViewport: () => {},
    focus: () => {},
  };
  return ed;
}

// A blade frame: one document, the inject loaded once when a script tag
// for it lands, the editors (or, for a Monaco without getEditors, the
// models) behind it set per test. `blocked` makes the script tag fire
// error instead, as a page CSP would.
function makeBlade({ listsEditors = true, blocked = false } = {}) {
  const d = new EventTarget();
  d.editors = [];
  d.models = [];
  d.elements = [];
  d.scripts = [];
  d.documentElement = { dataset: {} };
  d.querySelector = () => null;
  d.querySelectorAll = (sel) => (sel === ".monaco-editor" ? d.elements : []);
  d.getElementById = (id) => d.scripts.find((s) => s.id === id) || null;
  d.createElement = () => new EventTarget();
  d.head = {
    appendChild(s) {
      d.scripts.push(s);
      if (!s.src.endsWith("sentinel-editor-inject.js")) return;
      if (blocked) queueMicrotask(() => s.dispatchEvent(new Event("error")));
      else blade.loadInject();
    },
  };
  const monaco = { editor: listsEditors ? { getEditors: () => d.editors } : { getModels: () => d.models }, Range: FakeRange };
  const sandbox = { document: d, monaco, CustomEvent, setTimeout, console };
  sandbox.window = sandbox;
  const ctx = vm.createContext(sandbox);
  const blade = {
    doc: d,
    loads: 0,
    loadInject() {
      this.loads++;
      vm.runInContext(INJECT, ctx);
    },
    sized(on) {
      d.elements = on ? [{ getBoundingClientRect: () => ({ width: 800, height: 200 }), style: {} }] : [{ getBoundingClientRect: () => ({ width: 0, height: 0 }), style: {} }];
    },
  };
  return blade;
}

function inBlade(blade, fn) {
  const hadDocument = globalThis.document;
  globalThis.document = blade.doc;
  const fake = fakeChrome({ id: "reach" });
  delete fake.chrome.tabs; // a content script has no tabs API: the bridge is in the page, or the clipboard
  const restore = fake.install();
  return Promise.resolve().then(fn).finally(() => {
    restore();
    globalThis.document = hadDocument;
    if (hadDocument === undefined) delete globalThis.document;
  });
}

test("a query ending in a newline still gets its stage on a new line, KQL and SPL alike", () => {
  assert.equal(place("SecurityEvent | take 10\n", 'Image startswith "C:"', { mode: "append", form: "term", field: "Image", platform: "sentinel" }).text, 'SecurityEvent | take 10\n| where Image startswith "C:"');
  assert.equal(place("index=main | stats count\n\n", "sort -count", { mode: "append", form: "stage", platform: "splunk" }).text, "index=main | stats count\n| sort -count");
});

const blade = makeBlade();

test("Sentinel: with no sized Monaco in the frame the bridge is not ready and injects nothing", async () => {
  await inBlade(blade, async () => {
    blade.sized(false);
    assert.equal(bridge.where(), "clipboard");
    assert.equal(await bridge.kqlReady(), false);
    assert.equal(blade.doc.scripts.length, 0);
    const written = [];
    await withClipboard(written, async () => {
      const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "append", platform: "sentinel" });
      assert.equal(res.how, "copied");
      assert.match(res.notice, /Logs editor/);
    });
    assert.deepEqual(written, ['Image startswith "C:"']);
  });
});

test("Sentinel: a sized Monaco loads the inject once by id, marks the page, and the bridge is ready", async () => {
  await inBlade(blade, async () => {
    blade.sized(true);
    blade.doc.editors = [fakeEditor({ text: "SecurityEvent | take 10" })];
    assert.equal(bridge.where(), "page");
    assert.equal(await bridge.kqlReady(), true);
    assert.equal(blade.doc.scripts.length, 1);
    assert.equal(blade.doc.scripts[0].id, bridge.KQL_INJECT_ID);
    assert.equal(blade.doc.scripts[0].src, "chrome-extension://reach/sentinel-editor-inject.js");
    assert.equal(blade.doc.documentElement.dataset.reachEditorBridge, "1");
    assert.equal(blade.loads, 1);
  });
});

test("Sentinel: the inject guards a second load: one reply per read", async () => {
  await inBlade(blade, async () => {
    blade.loadInject();
    let replies = 0;
    const count = () => replies++;
    blade.doc.addEventListener("reach-editor-kql-text", count);
    const r = await bridge.readKql();
    blade.doc.removeEventListener("reach-editor-kql-text", count);
    assert.equal(r.ok, true);
    assert.equal(replies, 1);
  });
});

test("Sentinel: read carries an id the reply echoes, with the text and a zero-based cursor", async () => {
  await inBlade(blade, async () => {
    blade.doc.editors = [fakeEditor({ text: "SecurityEvent\n| take 10" })];
    const seen = {};
    const onReq = (e) => (seen.request = e.detail);
    const onRep = (e) => (seen.reply = e.detail);
    blade.doc.addEventListener("reach-editor-read-kql", onReq);
    blade.doc.addEventListener("reach-editor-kql-text", onRep);
    const r = await bridge.readKql();
    blade.doc.removeEventListener("reach-editor-read-kql", onReq);
    blade.doc.removeEventListener("reach-editor-kql-text", onRep);
    assert.deepEqual(Object.keys(seen.request), ["id"]);
    assert.equal(seen.reply.id, seen.request.id);
    assert.deepEqual(JSON.parse(JSON.stringify(r)), { ok: true, text: "SecurityEvent\n| take 10", cursor: { row: 0, column: 2 } });
  });
});

test("Sentinel: an append is one executeEdits at the end of the model between two undo stops", async () => {
  await inBlade(blade, async () => {
    const ed = fakeEditor({ text: "SecurityEvent\n| take 10" });
    blade.doc.editors = [ed];
    const seen = {};
    const onReq = (e) => (seen.request = e.detail);
    blade.doc.addEventListener("reach-editor-set-kql", onReq);
    const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "append", platform: "sentinel" });
    blade.doc.removeEventListener("reach-editor-set-kql", onReq);
    assert.deepEqual(res, { ok: true, how: "appended", notice: "Added to the search" });
    assert.deepEqual(seen.request, { id: seen.request.id, text: '\n| where Image startswith "C:"', mode: "append" });
    assert.equal(ed.edits.length, 1);
    assert.equal(ed.edits[0].src, "reach");
    assert.deepEqual({ ...ed.edits[0].ops[0].range }, { startLineNumber: 2, startColumn: 10, endLineNumber: 2, endColumn: 10 });
    assert.equal(ed.edits[0].stopsBefore, 1);
    assert.equal(ed.undoStops, 2);
    assert.equal(ed.getModel().getValue(), 'SecurityEvent\n| take 10\n| where Image startswith "C:"');
  });
});

test("Sentinel: replace swaps the column's test in place through a whole-model edit", async () => {
  await inBlade(blade, async () => {
    const ed = fakeEditor({ text: 'SecurityEvent\n| where Image == "a"\n| take 10' });
    blade.doc.editors = [ed];
    const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "replace", platform: "sentinel" });
    assert.equal(res.how, "replaced");
    assert.equal(ed.edits[0].ops[0].range.startLineNumber, 1);
    assert.equal(ed.getModel().getValue(), 'SecurityEvent\n| where Image startswith "C:"\n| take 10');
  });
});

test("Sentinel: the focused editor wins over a larger one", async () => {
  await inBlade(blade, async () => {
    const big = fakeEditor({ width: 1200, height: 600, text: "big" });
    const focused = fakeEditor({ width: 400, height: 100, text: "focused", focus: true });
    blade.doc.editors = [big, focused];
    assert.equal((await bridge.readKql()).text, "focused");
  });
});

test("Sentinel: every editor at zero size (Simple mode) is refused with a reason, and apply copies instead", async () => {
  await inBlade(blade, async () => {
    const hidden = fakeEditor({ width: 0, height: 0, text: "SecurityEvent" });
    blade.doc.editors = [hidden];
    const r = await bridge.setKql("x", "append");
    assert.equal(r.ok, false);
    assert.match(r.reason, /size/);
    assert.equal(hidden.edits.length, 0);
    const written = [];
    await withClipboard(written, async () => {
      const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "append", platform: "sentinel" });
      assert.equal(res.how, "copied");
      assert.match(res.notice, /size.*copied instead/);
    });
    assert.deepEqual(written, ['Image startswith "C:"']);
  });
});

test("Sentinel: with no editor listed the inject answers with a reason rather than silence", async () => {
  await inBlade(blade, async () => {
    blade.doc.editors = [];
    const r = await bridge.readKql();
    assert.equal(r.ok, false);
    assert.match(r.reason, /no query editor/);
  });
});

test("Sentinel: a Monaco without getEditors edits the one query model through the model, undo stack kept", async () => {
  const old = makeBlade({ listsEditors: false });
  await inBlade(old, async () => {
    old.sized(true);
    const model = fakeModel("SecurityEvent | take 10");
    old.doc.models = [fakeModel("some json", "json"), model];
    assert.equal(await bridge.kqlReady(), true);
    assert.deepEqual(JSON.parse(JSON.stringify(await bridge.readKql())), { ok: true, text: "SecurityEvent | take 10", cursor: null });
    const res = await bridge.apply({ text: 'Image startswith "C:"', form: "term", field: "Image", mode: "append", platform: "sentinel" });
    assert.equal(res.how, "appended");
    assert.equal(model.ops.length, 1);
    assert.equal(model.ops[0].stackBefore, 1);
    assert.equal(model.stack, 2);
    assert.equal(model.getValue(), 'SecurityEvent | take 10\n| where Image startswith "C:"');
    old.doc.models = [fakeModel("a"), fakeModel("b")];
    const r = await bridge.setKql("x", "append");
    assert.equal(r.ok, false);
    assert.match(r.reason, /2 models/);
  });
});

test("Sentinel: a script the page refuses makes the bridge not ready at once, and stays so without another wait", async () => {
  const shut = makeBlade({ blocked: true });
  await inBlade(shut, async () => {
    shut.sized(true);
    const t0 = Date.now();
    assert.equal(await bridge.kqlReady(), false);
    assert.equal(await bridge.kqlReady(), false);
    assert.ok(Date.now() - t0 < 500);
    assert.equal(shut.doc.scripts.length, 1);
    const written = [];
    await withClipboard(written, async () => {
      const res = await bridge.apply({ text: "x", form: "term", field: "f", mode: "append", platform: "sentinel" });
      assert.equal(res.how, "copied");
      assert.match(res.notice, /did not load; copied instead/);
    });
  });
});
