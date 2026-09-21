// Runs in the page's own (main) JS world, unlike search-history.js itself.
// Content scripts live in an isolated world: they share the DOM with the
// page but not JS properties the page's own scripts attach to DOM nodes.
// Ace's `.env.editor` on the search bar's element is exactly that, so the
// isolated-world script cannot reach it directly. This file is loaded as a
// real <script src> (the one way an isolated-world script can get code to
// actually run in the main world) and bridges back via DOM CustomEvents,
// which, unlike expando properties, do cross the world boundary.
//
// Events, all on document:
//   reach-history-set-search   { text, mode? }   mode set (default): replace the bar's text
//                                                mode insert: insert at the cursor (or over the selection)
//                                                mode append: insert at the end of the text
//   reach-history-read-search  { id }            replies with reach-history-search-text { id, ok, text, cursor }
//   reach-history-bridge-ready                   dispatched once this script has its listeners up; the
//                                                same fact sits on <html data-reach-search-bridge="1">
// search-history.js and app/lib/editor-bridge.js both load this file; the
// guard below keeps a second load from registering the listeners twice.

(function () {
  if (window.__reachSearchBridge) return;
  window.__reachSearchBridge = true;

  // A silent text swap is easy to miss, especially right as the dropdown
  // that caused it closes: flash the bar so the change reads as an event,
  // not just a diff you might notice later.
  function flash(bar) {
    bar.style.transition = "box-shadow .15s ease-out";
    bar.style.boxShadow = "0 0 0 2px #a78bfa";
    setTimeout(() => {
      bar.style.transition = "box-shadow .6s ease-out";
      bar.style.boxShadow = "";
      setTimeout(() => {
        bar.style.transition = "";
      }, 650);
    }, 150);
  }

  function editorOf() {
    const bar = document.querySelector(".search-bar-input");
    const editorEl = bar && bar.querySelector(".ace_editor");
    const editor = editorEl && editorEl.env && editorEl.env.editor;
    return editor ? { bar, editor } : null;
  }

  document.addEventListener("reach-history-set-search", (e) => {
    try {
      const text = e.detail && e.detail.text;
      if (typeof text !== "string") return;
      const mode = (e.detail && e.detail.mode) || "set";
      const found = editorOf();
      if (!found) return;
      const { bar, editor } = found;
      if (mode === "insert") editor.insert(text);
      else if (mode === "append") {
        editor.navigateFileEnd();
        editor.insert(text);
      } else editor.setValue(text, -1);
      editor.focus();
      flash(bar);
    } catch (err) {
      console.warn("[Reach] search-history: could not set the search bar", err);
    }
  });

  document.addEventListener("reach-history-read-search", (e) => {
    const id = e.detail && e.detail.id;
    let detail = { id, ok: false, text: "", cursor: null };
    try {
      const found = editorOf();
      if (found) {
        const pos = found.editor.getCursorPosition();
        detail = { id, ok: true, text: found.editor.getValue(), cursor: { row: pos.row, column: pos.column } };
      }
    } catch (err) {
      console.warn("[Reach] search-history: could not read the search bar", err);
    }
    document.dispatchEvent(new CustomEvent("reach-history-search-text", { detail }));
  });

  document.documentElement.dataset.reachSearchBridge = "1";
  document.dispatchEvent(new CustomEvent("reach-history-bridge-ready"));
})();
