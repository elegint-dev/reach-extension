// Runs in the Logs blade frame's own (main) JS world, the Sentinel
// counterpart of search-history-inject.js. The blade's query editor is
// Monaco, whose instances live on the page's `monaco` global and never on
// a DOM node, so the isolated-world content script cannot reach them. This
// file is loaded as a real <script src> from sentinel-grid.js and bridges
// back over DOM CustomEvents.
//
// Events, all on document:
//   reach-editor-read-kql   { id }                 replies reach-editor-kql-text { id, ok, text, cursor, reason }
//   reach-editor-set-kql    { id, text, mode? }    replies reach-editor-kql-set { id, ok, reason }
//                             mode set (default): the text becomes the whole query
//                             mode append: the text goes on the end of the query
//                             mode replace: the text goes over the selection, or in at the cursor
//                             mode insert: the same as replace (search-history-inject.js's word for it)
//   reach-editor-bridge-ready                      once the listeners are up; the same fact sits on
//                                                  <html data-reach-editor-bridge="1">
//
// Every edit goes in between two undo stops, so one insert is one Ctrl+Z:
// through the editor (executeEdits) when this Monaco lists its editors,
// else through the model (pushEditOperations), which keeps the undo stack
// and loses only the cursor. Simple mode keeps a hidden Monaco whose
// rendered line is a fragment of the query, so only an editor with real
// size is read or written; a request with none in reach is refused with a
// reason, never applied to the hidden one.

(function () {
  if (window.__reachEditorBridge) return;
  window.__reachEditorBridge = true;

  const MIN_WIDTH = 120;
  const MIN_HEIGHT = 20;

  function flash(node) {
    if (!node || !node.style) return;
    node.style.transition = "box-shadow .15s ease-out";
    node.style.boxShadow = "0 0 0 2px #a78bfa";
    setTimeout(() => {
      node.style.transition = "box-shadow .6s ease-out";
      node.style.boxShadow = "";
      setTimeout(() => {
        node.style.transition = "";
      }, 650);
    }, 150);
  }

  function sized(node) {
    if (!node || typeof node.getBoundingClientRect !== "function") return false;
    const r = node.getBoundingClientRect();
    return r.width >= MIN_WIDTH && r.height >= MIN_HEIGHT;
  }

  function area(node) {
    const r = node.getBoundingClientRect();
    return r.width * r.height;
  }

  // The editor a request lands in: the focused one, else the largest, of
  // those with a real size and a model. Without getEditors (Monaco before
  // 0.34) the one sized .monaco-editor on the page and the one model in
  // the query language stand in, model-only. { editor?, model, node } or
  // { reason }.
  function targetOf() {
    const m = window.monaco;
    if (!m || !m.editor) return { reason: "no Monaco on this page" };
    if (typeof m.editor.getEditors === "function") {
      const live = m.editor.getEditors().filter((e) => e && typeof e.getModel === "function" && e.getModel() && sized(e.getDomNode && e.getDomNode()));
      if (!live.length) return { reason: "no query editor with a size on this page (Simple mode hides it)" };
      const focused = live.find((e) => typeof e.hasTextFocus === "function" && e.hasTextFocus());
      const editor = focused || live.sort((a, b) => area(b.getDomNode()) - area(a.getDomNode()))[0];
      return { editor, model: editor.getModel(), node: editor.getDomNode() };
    }
    if (typeof m.editor.getModels !== "function") return { reason: "this Monaco lists neither editors nor models" };
    const nodes = Array.from(document.querySelectorAll(".monaco-editor")).filter(sized);
    if (!nodes.length) return { reason: "no query editor with a size on this page (Simple mode hides it)" };
    const models = m.editor.getModels().filter((x) => x && typeof x.getValue === "function");
    const kusto = models.filter((x) => typeof x.getLanguageId === "function" && /kusto|kql/i.test(x.getLanguageId()));
    const pick = kusto.length ? kusto : models;
    if (pick.length !== 1 || nodes.length !== 1) return { reason: `this Monaco does not list its editors and ${pick.length} models sit behind ${nodes.length} editors` };
    return { model: pick[0], node: nodes[0] };
  }

  function reply(name, detail) {
    document.dispatchEvent(new CustomEvent(name, { detail }));
  }

  document.addEventListener("reach-editor-read-kql", (e) => {
    const id = e.detail && e.detail.id;
    let detail = { id, ok: false, text: "", cursor: null, reason: "" };
    try {
      const t = targetOf();
      if (t.model) {
        const pos = t.editor && typeof t.editor.getPosition === "function" ? t.editor.getPosition() : null;
        detail = { id, ok: true, text: t.model.getValue(), cursor: pos ? { row: pos.lineNumber - 1, column: pos.column - 1 } : null, reason: "" };
      } else detail.reason = t.reason;
    } catch (err) {
      detail.reason = err && err.message ? err.message : String(err);
    }
    reply("reach-editor-kql-text", detail);
  });

  document.addEventListener("reach-editor-set-kql", (e) => {
    const id = e.detail && e.detail.id;
    const text = e.detail && e.detail.text;
    const mode = (e.detail && e.detail.mode) || "set";
    if (typeof text !== "string") {
      reply("reach-editor-kql-set", { id, ok: false, reason: "no text" });
      return;
    }
    try {
      const t = targetOf();
      if (!t.model) {
        reply("reach-editor-kql-set", { id, ok: false, reason: t.reason });
        return;
      }
      const { editor, model } = t;
      const full = model.getFullModelRange();
      let range;
      if (mode === "append") {
        const end = full.getEndPosition();
        range = new window.monaco.Range(end.lineNumber, end.column, end.lineNumber, end.column);
      } else if (mode === "insert" || mode === "replace") {
        range = (editor && editor.getSelection()) || full.collapseToEnd();
      } else range = full;
      if (editor) {
        editor.pushUndoStop();
        editor.executeEdits("reach", [{ range, text, forceMoveMarkers: true }]);
        editor.pushUndoStop();
        const after = model.getFullModelRange().getEndPosition();
        if (mode === "set" || mode === "append") editor.setPosition(after);
        editor.revealPositionInCenterIfOutsideViewport(editor.getPosition() || after);
        editor.focus();
      } else {
        model.pushStackElement();
        model.pushEditOperations([], [{ range, text, forceMoveMarkers: true }], () => null);
        model.pushStackElement();
      }
      flash(t.node);
      reply("reach-editor-kql-set", { id, ok: true, reason: "" });
    } catch (err) {
      console.warn("[Reach] sentinel-editor: could not set the query", err);
      reply("reach-editor-kql-set", { id, ok: false, reason: err && err.message ? err.message : String(err) });
    }
  });

  document.documentElement.dataset.reachEditorBridge = "1";
  document.dispatchEvent(new CustomEvent("reach-editor-bridge-ready"));
})();
