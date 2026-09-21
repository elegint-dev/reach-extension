// Builds splunk-search.html from the pieces captured off a live Splunk
// search page (raw/, untracked): the results table head, a few event rows,
// the search bar, and the Splunk half of the field-value popup. See
// README.md here for the capture snippet. Run from the repo root:
//
//   node tests/fixtures/pages/build-splunk-fixture.mjs
//
// What the build does to the captures:
//   - strips everything Reach itself had added to the page when the capture
//     was taken (the extension was loaded): data-reach-* marks, the f-v
//     class and data-field-name on JSON leaves, the key-name wiring, and
//     the REACH section inside the popup
//   - replaces identifying values: agent ip, customer id, our own sensor's
//     aid and host, the machine name; the public attack_data replay keeps
//     its own values (they are published)
//   - drops Splunk's render bookkeeping (data-render-time)
//   - appends the hand-written ProcessHandleOpDetectInfo row (handle-open-row.mjs)
//     after the captured rows, since the capture has ProcessRollup2 only,
//     then the three mac signing rows (mac-signing-rows.mjs) the hunt keeps,
//     then the impersonation and Linux rows (known-rows.mjs) the verdict's
//     other tiers land on
//   - wraps the pieces in a page shell that carries the /static/@ asset
//     marker the content scripts gate on, an editor shim that answers the
//     search bar bridge the way Ace does, and a popup shim that opens
//     Splunk's own field-value menu on a .f-v click the way Splunk Web does
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handleOpenRow } from "./handle-open-row.mjs";
import { macSigningRows } from "./mac-signing-rows.mjs";
import { knownRows } from "./known-rows.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const raw = (name) => fs.readFileSync(path.join(here, "raw", name), "utf8");

const SEARCH = "index=main sourcetype=crowdstrike:events:sensor aid=f0778584e83c4efc9cf026bc1e7f0489 event_simpleName=ProcessRollup2";

// --- sanitising ---------------------------------------------------------------

function stripReach(html) {
  let out = html;
  // JSON-tree leaves: back to Splunk's own markup.
  out = out.replace(/<span class="t (\w+) f-v" data-path="([^"]*)" data-reach-tagged="1" data-field-name="[^"]*" role="button" aria-haspopup="true" style="cursor: pointer;">/g, '<span class="t $1" data-path="$2">');
  out = out.replace(/<span class="key-name" data-field-name="[^"]*" data-reach-key="1" role="button" aria-haspopup="dialog" style="cursor: pointer;">/g, '<span class="key-name">');
  // Anything else Reach marked.
  out = out.replace(/ data-reach-[a-z-]+="[^"]*"/g, "");
  out = out.replace(/ data-render-time="[^"]*"/g, "");
  // The REACH section and its stylesheet inside the captured popup.
  out = out.replace(/<style>[\s\S]*$/, "");
  return out;
}

const REPLACE = [
  [/\b35\.157\.24\.242\b/g, "203.0.113.10"],
  [/\b98\.97\.37\.254\b/g, "203.0.113.20"],
  [/\b124cb22314bf4f519be84bce582e7a6b\b/g, "00000000000000000000000000000001"],
  [/\baed7b35fa4ff4dcba1042fdf81b642cc\b/g, "00000000000000000000000000000002"],
  [/\bc26d2f327b6a49eebc1432e094ee4a84\b/g, "0123456789abcdef0123456789abcdef"],
  [/Manageds-Virtual-Machine\.local/g, "mac-lab-01.example"],
  [/\b0f3f8488a7d2\b/g, "sensor-mac-01"],
];

function sanitise(html) {
  let out = stripReach(html);
  for (const [re, to] of REPLACE) out = out.replace(re, to);
  const leak = /localhost:8001|splunkd_|session_id|csrf/i.exec(out);
  if (leak) throw new Error(`fixture still carries ${leak[0]}`);
  return out;
}

// --- the page ---------------------------------------------------------------------

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

const STYLE = `
body{margin:0;background:#1e1e1e;color:#e6e6e6;font:13px/1.4 -apple-system,"Segoe UI",Roboto,sans-serif}
.search-bar{padding:12px 16px;background:#2b2b2b}
.search-bar-input{position:relative;background:#111;border:1px solid #444;border-radius:3px;padding:6px 8px;min-height:20px}
.ace_editor{position:relative;font:13px/20px Menlo,Consolas,monospace;white-space:pre}
.ace_line{white-space:pre}
.ace_text-input{position:absolute;opacity:0;height:1px;width:1px}
.search-results{padding:8px 16px}
table.events-results{border-collapse:collapse;width:100%}
.events-results th,.events-results td{vertical-align:top;text-align:left;padding:4px 6px;border-bottom:1px solid #333}
.events-results td.expands{width:14px}
.events-results td._time{width:110px;white-space:nowrap}
.json-tree{font:12px/1.5 Menlo,Consolas,monospace}
.json-tree .key-name{color:#c9a0dc}
.json-tree .t.string{color:#9ad}
.json-tree .t.num{color:#f8c}
.condensed-selected-fields{list-style:none;padding:0;margin:8px 0 0;display:flex;gap:16px;flex-wrap:wrap}
.f-v{color:#6bf;cursor:pointer;text-decoration:none}
.dropdown-menu{position:absolute;display:none;background:#fff;color:#222;border:1px solid #bbb;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,.35);min-width:280px;z-index:1000}
.dropdown-menu.open{display:block}
.dropdown-menu ul{list-style:none;margin:0;padding:6px 0}
.dropdown-menu li{display:flex;justify-content:space-between;padding:4px 14px}
.dropdown-menu a{color:#1a5fb4;text-decoration:none}
.dropdown-menu .info{color:#777;margin-left:8px}
.dropdown-menu .arrow{display:none}
.fields-sidebar{padding:8px 16px;display:flex;justify-content:space-between}.fields-sidebar a{color:#6bf;text-decoration:none}
.popdown-dialog{position:absolute;display:none;width:600px;box-sizing:border-box;padding:12px;background:#fff;color:#222;border:1px solid #bbb;border-radius:4px;box-shadow:0 2px 12px rgba(0,0,0,.35);z-index:1000}
.popdown-dialog.open{display:block}
`;

// The Ace shim: enough of Ace's editor object for search-history-inject.js
// (getValue, setValue, insert, navigateFileEnd, focus, getCursorPosition)
// and the rendered .ace_line divs context.js reads. Rendering keeps one
// .ace_line per line of the value, as Ace does.
const SHIM = `
(function () {
  var bar = document.querySelector(".search-bar-input");
  var editorEl = bar.querySelector(".ace_editor");
  var layer = editorEl.querySelector(".ace_text-layer");
  var value = Array.prototype.map.call(layer.querySelectorAll(".ace_line"), function (l) { return l.textContent; }).join("\\n");
  var cursor = { row: 0, column: value.length };
  function esc(s) { return s.replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }); }
  function render() {
    layer.innerHTML = value.split("\\n").map(function (line) { return '<div class="ace_line_group" style="height:20px"><div class="ace_line" style="height:20px">' + esc(line) + "</div></div>"; }).join("");
    editorEl.style.height = 20 * value.split("\\n").length + "px";
  }
  function offset() {
    var lines = value.split("\\n");
    var o = 0;
    for (var i = 0; i < cursor.row && i < lines.length; i++) o += lines[i].length + 1;
    return Math.min(value.length, o + cursor.column);
  }
  var editor = {
    getValue: function () { return value; },
    setValue: function (text, pos) { value = String(text); var lines = value.split("\\n"); cursor = pos === -1 ? { row: 0, column: 0 } : { row: lines.length - 1, column: lines[lines.length - 1].length }; render(); },
    insert: function (text) { var at = offset(); value = value.slice(0, at) + String(text) + value.slice(at); var before = value.slice(0, at + String(text).length).split("\\n"); cursor = { row: before.length - 1, column: before[before.length - 1].length }; render(); },
    navigateFileEnd: function () { var lines = value.split("\\n"); cursor = { row: lines.length - 1, column: lines[lines.length - 1].length }; },
    focus: function () { editorEl.querySelector(".ace_text-input").focus(); },
    getCursorPosition: function () { return { row: cursor.row, column: cursor.column }; },
  };
  editorEl.env = { editor: editor };
  window.__fixtureEditor = editor;
  render();

  // Splunk's field-value menu: destroyed and recreated on every open,
  // appended to body, positioned under the clicked element. The <ul> is
  // the one Splunk Web renders (captured), minus the counts' meaning.
  var template = document.getElementById("fixture-popup-template").content;
  var seq = 0;
  document.addEventListener("click", function (e) {
    var open = document.querySelector(".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown");
    if (open && !open.contains(e.target)) open.remove();
    var el = e.target.closest && e.target.closest(".f-v");
    if (!el) return;
    e.preventDefault();
    var popup = template.firstElementChild.cloneNode(true);
    popup.id = "dialog-view" + ++seq;
    var r = el.getBoundingClientRect();
    popup.style.top = Math.round(r.bottom + window.scrollY + 6) + "px";
    popup.style.left = Math.round(r.left + window.scrollX) + "px";
    popup.style.display = "block";
    document.body.appendChild(popup);
    popup.querySelectorAll("a").forEach(function (a) { a.addEventListener("click", function (ev) { ev.preventDefault(); }); });
  });

  // Splunk's field-info popdown: opened by a click on a field name in the
  // sidebar, appended to body, a fixed width, positioned under the name
  // and kept inside the viewport by Splunk itself.
  document.addEventListener("click", function (e) {
    var openInfo = document.querySelector(".popdown-dialog.shared-fieldinfo");
    if (openInfo && !openInfo.contains(e.target)) openInfo.remove();
    var link = e.target.closest && e.target.closest(".field-info-link");
    if (!link) return;
    e.preventDefault();
    var d = document.createElement("div");
    d.className = "popdown-dialog shared-fieldinfo open";
    d.innerHTML = "<h3>" + link.dataset.fieldName + '</h3><div class="field-info-reports-section"><p>Top values / Rare values / Events with this field</p></div>';
    var r = link.getBoundingClientRect();
    d.style.top = Math.round(r.bottom + window.scrollY + 6) + "px";
    d.style.left = Math.round(Math.max(12, Math.min(r.left + window.scrollX, document.documentElement.clientWidth - 600 - 12))) + "px";
    document.body.appendChild(d);
  });
})();
`;

function build() {
  const thead = sanitise(raw("splunk-thead.html"));
  const captured = sanitise(raw("splunk-rows.html")) + "\n" + sanitise(raw("splunk-rows-mac.html"));
  const n = (captured.match(/shared-eventsviewer-list-body-row"/g) || []).length;
  const rows = captured + "\n" + handleOpenRow(n + 1) + "\n" + macSigningRows(n + 2) + "\n" + knownRows(n + 5);
  const bar = sanitise(raw("splunk-bar.html"));
  const popup = sanitise(raw("splunk-popup.html")).replace(/ id="dialog-view\d+"/, "").replace(/ style="[^"]*"/, "").replace(/ data-cid="[^"]*"/, "");
  const page = `<!DOCTYPE html>
<html lang="en" class="no-js">
<head>
<meta charset="utf-8">
<title>Search | Splunk (fixture)</title>
<link rel="shortcut icon" href="/en-US/static/@953D2FCCE07AB92B2558FF04B90FC097F72063F472BC8C211321FB291E8127C7/img/favicon.ico">
<style>${STYLE}</style>
</head>
<body class="locale-en">
<div class="search-bar">
${bar}
</div>
<div class="fields-sidebar"><a href="#" class="field-info-link" data-field-name="ImageFileName">ImageFileName</a><a href="#" class="field-info-link" data-field-name="CommandLine">CommandLine</a></div>
<div class="search-results">
<div class="search-results-events-container">
<div class="shared-eventsviewer">
<table class="table table-chrome table-striped table-row-expanding events-results events-results-table hide-line-num">
${thead}
<tbody class="shared-eventsviewer-list-body">
${rows}
</tbody>
</table>
</div>
</div>
</div>
<template id="fixture-popup-template">${popup}</template>
<script>${SHIM}</script>
</body>
</html>
`;
  fs.writeFileSync(path.join(here, "splunk-search.html"), page);
  fs.writeFileSync(path.join(here, "splunk-search.json"), JSON.stringify({ search: SEARCH, path: "/en-US/app/search/search", query: { q: `search ${SEARCH}`, sid: "1700000000.1" } }, null, 2) + "\n");
  console.log(`wrote splunk-search.html (${page.length} bytes), ${(rows.match(/shared-eventsviewer-list-body-row"/g) || []).length} rows`);
}

build();
