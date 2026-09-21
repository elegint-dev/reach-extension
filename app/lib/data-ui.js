// The load-failure panel for a catalogue.load() that threw (BundleError,
// catalogue.js), kept apart from the loaders so a content script can load
// the packs without pulling in the DOM-builder layer.

import { h } from "../components/h.js";

export function renderLoadError(err, target) {
  const mount =
    target ||
    (typeof document !== "undefined" ? document.getElementById("boot-error") || document.body : null);
  if (!mount) return null;
  const serve = err && err.code === "needs_server";
  const panel = h(
    "div",
    { class: "r-bootfail", role: "alert" },
    h("h1", null, serve ? "Reach has to be served, not opened" : "Reach cannot read its data"),
    h("p", null, (err && err.message) || "The packs failed to load."),
    err && err.detail ? h("p", { class: "r-secondary" }, err.detail) : null,
    h("p", { class: "r-secondary" }, serve ? "From the repository root:" : "From the repository root, serve the tree and reload:"),
    h(
      "pre",
      { class: "r-bootfail__cmd", tabindex: "0" },
      h(
        "code",
        null,
        serve
          ? "python3 -m http.server 8000\n\nthen open  http://localhost:8000/"
          : "python3 -m http.server 8000",
      ),
    ),
    h(
      "p",
      { class: "r-secondary" },
      serve
        ? "Reach is plain static files with no build step and no network calls. A local file server is the only thing it needs."
        : h(
            "span",
            null,
            "Check that ",
            h("code", null, "python3 -m http.server"),
            " is running from the repository root, not from inside ",
            h("code", null, "app/"),
            ".",
          ),
    ),
  );
  mount.hidden = false;
  mount.replaceChildren(panel);
  return panel;
}
