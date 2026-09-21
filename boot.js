// Classic script, loaded synchronously from <head> (not type=module) so it
// runs before first paint and before app.js, which is deferred by being a
// module. MV3 extension pages cannot run inline <script>: script-src 'self'
// forbids it, so this file exists to be that "self" source instead.

// Theme before first paint, so a chosen theme never flashes the other one.
try {
  var t = localStorage.getItem("reach.theme");
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
} catch (e) { /* storage blocked: fall back to prefers-color-scheme */ }

// The catalogue app (and the options page, which loads this file too)
// marks itself so app/lib/platform.js knows to take the platform from
// ?platform= or memory, not the hostname. Runs synchronously here, well
// before app.js (a deferred module) executes.
window.REACH_APP = true;

// index.html is a web-accessible resource, so any site can put the
// extension's copy in an iframe and dress its buttons up as its own. The
// worker refuses discovery from a framed sender; this keeps the page from
// showing anything clickable in the first place. Only the extension's own
// copy is guarded: the served page is framed on purpose by the width
// harness, and the panel, popup and options page are top-level documents.
if (location.protocol === "chrome-extension:" && window.top !== window) {
  window.REACH_FRAMED = true;
  document.addEventListener("DOMContentLoaded", function () {
    var page = document.getElementById("page");
    var box = document.getElementById("boot-error");
    if (!page || !box) return; // the options page has no boot slot
    page.hidden = true;
    box.hidden = false;
    box.innerHTML =
      '<div class="r-bootfail" role="alert">' +
      '<h1>Reach does not run inside another page</h1>' +
      '<p>This copy of Reach was embedded by another site. Open Reach from its toolbar icon or side panel instead.</p>' +
      '</div>';
  });
}

// ES modules are blocked by CORS on file://, so app.js never runs there and
// cannot render its own message. This script can, but only once the body it
// touches has been parsed (this file itself runs during <head>, before
// <body> exists).
if (location.protocol === "file:") {
  document.addEventListener("DOMContentLoaded", function () {
    var page = document.getElementById("page");
    var box = document.getElementById("boot-error");
    if (!page || !box) return;
    page.hidden = true;
    box.hidden = false;
    box.innerHTML =
      '<div class="r-bootfail" role="alert">' +
      '<h1>Reach has to be served, not opened</h1>' +
      '<p>This page was opened straight from disk (file://). Browsers block a page on file:// from loading its own modules and data, so Reach cannot read its knowledge base.</p>' +
      '<p class="r-secondary">Serve the folder that holds this file, for example:</p>' +
      '<pre class="r-bootfail__cmd" tabindex="0"><code>python3 -m http.server 8000\n\nthen open  http://localhost:8000/</code></pre>' +
      '<p class="r-secondary">Nothing else is needed: no build step, no install, and no network at runtime.</p>' +
      '</div>';
  });
}
