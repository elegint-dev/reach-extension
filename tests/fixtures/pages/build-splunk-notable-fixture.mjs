// Builds splunk-notable.html from splunk-search.html: the same page shell,
// search bar shim and popup shim, with the event rows replaced by one
// notable-shaped row (sourcetype stash, the ESCU search's name, the risk
// object and the entity fields a runbook binds from). No capture is
// needed: the dev Splunk has no Enterprise Security, so the row is written
// to the notable field list Splunk documents. Run from the repo root:
//
//   node tests/fixtures/pages/build-splunk-notable-fixture.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const SEARCH = "index=notable sourcetype=stash search_name=\"ESCU - Disabled Kerberos Pre-Authentication Discovery With Get-ADUser - Rule\"";

const FIELDS = [
  ["dest", "WIN-DC01"],
  ["orig_sid", "scheduler__nobody__DA-ESS-ContentUpdate__RMD5a1b2c3d4e5f60718_at_1789661400_12"],
  ["risk_object", "WIN-DC01"],
  ["risk_object_type", "system"],
  ["rule_name", "ESCU - Disabled Kerberos Pre-Authentication Discovery With Get-ADUser - Rule"],
  ["search_name", "ESCU - Disabled Kerberos Pre-Authentication Discovery With Get-ADUser - Rule"],
  ["security_domain", "endpoint"],
  ["src", "10.1.2.3"],
  ["urgency", "high"],
  ["user", "jdoe"],
];

function esc(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function leaf([name, value]) {
  return `<br>&nbsp;&nbsp;<span class="key level-1"><span class="key-name">${esc(name)}</span>: <span class="t string" data-path="${esc(name)}">${esc(value)}</span></span>`;
}

function selected(name, value) {
  return `<li><span class="field">${name} =</span> <span class="field-value"><a href="#" aria-haspopup="true" role="button" aria-expanded="false" class="f-v" data-field-name="${name}" title="${esc(value)}">${esc(value)}</a></span></li>`;
}

function row() {
  return `<tr data-cid="view90001" version="2" class="shared-eventsviewer-list-body-row" data-view="views/shared/eventsviewer/list/body/row/Master"><td class="expands none "><button aria-expanded="false" aria-label="Expand event fields"><i aria-hidden="true" class="icon-triangle-right-small"></i></button></td><td tabindex="0" class="line-num"><span>1</span></td><td class="_time" tabindex="0"><span class="formated-time" data-time-iso="2026-09-17T16:10:00.000+00:00"><span>9/17/26</span><br><span>4:10:00.000 PM</span></span></td><td class="col-icon" style="display:none" tabindex="0"><em class="icon"><img src="" alt="Column icon"></em></td><td class="event"><div data-cid="view90002" version="2" class="shared-eventsviewer-shared-rawfield" data-view="views/shared/eventsviewer/shared/RawField"><div class="json-event  wrap "><div class="json-tree shared-jsontree" data-cid="view90003" version="2" data-view="views/shared/JSONTree"><span>{</span><a href="#" class="jscollapse" aria-label="Collapse" data-original-title="" title="">[-]</a><span>${FIELDS.map(leaf).join("")}</span><br><span>}</span></div></div><div class="raw-event normal wrap " tabindex="0"></div><a href="#" class="toggle-raw-json">Show as raw text</a></div><div data-cid="view90004" version="2" class="shared-eventsviewer-list-body-row-selectedfields" data-view="views/shared/eventsviewer/list/body/row/SelectedFields"><ul class="condensed-selected-fields">${selected("host", "es-search-head")}${selected("source", "Disabled Kerberos Pre-Authentication Discovery With Get-ADUser")}${selected("sourcetype", "stash")}</ul></div><div data-cid="view90005" version="2" class="shared-eventsviewer-list-body-row-rcdiscobuttonplaceholder" data-view="views/shared/eventsviewer/list/body/row/RcDiscoButtonPlaceholder"></div></td></tr>`;
}

function build() {
  const base = fs.readFileSync(path.join(here, "splunk-search.html"), "utf8");
  const meta = JSON.parse(fs.readFileSync(path.join(here, "splunk-search.json"), "utf8"));
  const start = base.indexOf('<tbody class="shared-eventsviewer-list-body">');
  const end = base.indexOf("</tbody>", start);
  if (start < 0 || end < 0) throw new Error("splunk-search.html: no results body");
  let page = `${base.slice(0, start)}<tbody class="shared-eventsviewer-list-body">\n${row()}\n${base.slice(end)}`;
  // The search bar's rendered Ace lines carry the base fixture's search
  // (cut at the editor's width, as captured); this page's is the notable
  // search. Only the bar is touched, never the shim's template string.
  const barEnd = page.indexOf('<div class="search-results">');
  page = page.slice(0, barEnd).replace(/(class="ace_line" style="height:20px">)[^<]*/g, `$1${esc(SEARCH)}`) + page.slice(barEnd);
  fs.writeFileSync(path.join(here, "splunk-notable.html"), page);
  fs.writeFileSync(path.join(here, "splunk-notable.json"), JSON.stringify({ search: SEARCH, path: meta.path, query: { q: `search ${SEARCH}`, sid: "1700000000.2" } }, null, 2) + "\n");
  console.log(`wrote splunk-notable.html (${page.length} bytes)`);
}

build();
