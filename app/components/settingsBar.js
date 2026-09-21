// settingsBar: the top-bar disclosure for the things kept across sessions,
// this browser only. Its content is the module list (moduleList.js), the
// same element options.html draws: every module with its toggle, its
// sends line and its settings, so where the SIEM is, the scope a search
// runs in, the pinned values and every enrichment key sit in one list.
// Facts held for the case live in the Holding panel (holding.js), which
// never shows the index; this is the editor that is reachable from every
// route, the panel folds on the wide ones.

import { h } from "./h.js";
import * as scope from "../lib/scope.js";
import { moduleList } from "./moduleList.js";

export function settingsBar() {
  const list = moduleList({ context: "panel" });
  const panel = h("div", { class: "r-settings__panel" }, list);

  // The word on the wide surfaces, a gear in the panel, where the control
  // shares the omnibox's row (components.css, surfaces).
  // A question waiting inside (the index chooser) shows on the closed
  // control as a count, so the ask is seen from the route that raised it.
  const badge = h("span", { class: "r-settings__badge", hidden: true });
  const summary = h(
    "summary",
    { class: "r-settings__summary", "aria-label": "Settings", title: "Settings" },
    h("span", { class: "r-settings__word" }, "Settings"),
    h("span", { class: "r-settings__glyph", "aria-hidden": "true" }, "⚙"),
    badge,
  );
  function renderBadge() {
    const n = scope.index() ? 0 : scope.pending().length;
    badge.textContent = n ? String(n) : "";
    badge.hidden = !n;
    summary.title = n ? `Settings: ${n === 1 ? "one index to choose" : n + " indexes to choose"}` : "Settings";
  }
  scope.subscribe(renderBadge);
  renderBadge();
  const el = h("details", { class: "r-settings" }, summary, panel);

  function onOutsideClick(e) {
    if (!el.contains(e.target)) el.open = false;
  }
  el.addEventListener("toggle", () => {
    if (el.open) document.addEventListener("click", onOutsideClick);
    else document.removeEventListener("click", onOutsideClick);
  });

  // Built once for the session: the copy.js lines are re-asked when the
  // surface changes (app.js).
  el.refreshCopy = () => list.refreshCopy();
  return el;
}

export default settingsBar;
