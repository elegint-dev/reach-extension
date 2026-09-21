// One ProcessHandleOpDetectInfo row for splunk-search.html, written by hand
// in Splunk's clean event-row markup (the shape build-splunk-fixture.mjs
// leaves after stripping what Reach adds): the T1003.001 capture carries
// ProcessRollup2 rows only, and the field click on DesiredAccess and the
// RawProcessId to TargetProcessId chain need a handle-open event to land on.
// build-splunk-fixture.mjs appends it after the captured rows, so a refreshed
// capture keeps it. eventRow() is the markup itself, shared with the other
// hand-written rows (mac-signing-rows.mjs).
//
//   node tests/fixtures/pages/handle-open-row.mjs   prints the row

export const HANDLE_OPEN = [
  ["CommandLine", '"C:\\Tools\\procdump.exe" -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp'],
  ["ComputerName", "win-lab-01"],
  ["ConfigBuild", "1007.3.0015406.1"],
  ["ConfigStateHash", "1172426367"],
  ["ContextProcessId", "255667414"],
  ["DesiredAccess", "2097151"],
  ["EffectiveTransmissionClass", "3"],
  ["Entitlements", "15"],
  ["HandleOperationType", "1"],
  ["ImageFileName", "\\Device\\HarddiskVolume1\\Tools\\procdump.exe"],
  ["ParentProcessId", "307075862"],
  ["PatternId", "10403"],
  ["RawProcessId", "936"],
  ["TargetProcessCommandLine", "C:\\Windows\\system32\\lsass.exe"],
  ["TargetProcessId", "5497396"],
  ["TargetProcessImageFileName", "\\Device\\HarddiskVolume1\\Windows\\System32\\lsass.exe"],
  ["TemplateDisposition", "30"],
  ["TemplateInstanceId", "4"],
  ["UserName", "Administrator"],
  ["aid", "f0778584e83c4efc9cf026bc1e7f0489"],
  ["aip", "203.0.113.10"],
  ["cid", "00000000000000000000000000000001"],
  ["event_platform", "Win"],
  ["event_simpleName", "ProcessHandleOpDetectInfo"],
  ["id", "e1c2f6a0-0d98-11ed-acf0-06aeb8794401"],
  ["name", "ProcessHandleOpDetectInfoV3"],
  ["timestamp", "1658918560312"],
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

// One event row in Splunk's list markup: `fields` as the JSON tree's
// leaves in order, `time` the event's ISO time with its two rendered
// halves, `selected` the host, source and sourcetype line.
export function eventRow(n, fields, { time, selectedFields }) {
  const cid = (k) => `view9${String(n).padStart(2, "0")}${k}`;
  return `<tr data-cid="${cid(1)}" version="2" class="shared-eventsviewer-list-body-row" data-view="views/shared/eventsviewer/list/body/row/Master"><td class="expands none "><button aria-expanded="false" aria-label="Expand event fields"><i aria-hidden="true" class="icon-triangle-right-small"></i></button></td><td tabindex="0" class="line-num"><span>${n}</span></td><td class="_time" tabindex="0"><span class="formated-time" data-time-iso="${time.iso}"><span>${time.date}</span><br><span>${time.clock}</span></span></td><td class="col-icon" style="display:none" tabindex="0"><em class="icon"><img src="" alt="Column icon"></em></td><td class="event"><div data-cid="${cid(2)}" version="2" class="shared-eventsviewer-shared-rawfield" data-view="views/shared/eventsviewer/shared/RawField"><div class="json-event  wrap "><div class="json-tree shared-jsontree" data-cid="${cid(3)}" version="2" data-view="views/shared/JSONTree"><span>{</span><a href="#" class="jscollapse" aria-label="Collapse" data-original-title="" title="">[-]</a><span>${fields.map(leaf).join("")}</span><br><span>}</span></div></div><div class="raw-event normal wrap " tabindex="0"></div><a href="#" class="toggle-raw-json">Show as raw text</a></div><div data-cid="${cid(4)}" version="2" class="shared-eventsviewer-list-body-row-selectedfields" data-view="views/shared/eventsviewer/list/body/row/SelectedFields"><ul class="condensed-selected-fields">${selectedFields.map(([name, value]) => selected(name, value)).join("")}</ul></div><div data-cid="${cid(5)}" version="2" class="shared-eventsviewer-list-body-row-rcdiscobuttonplaceholder" data-view="views/shared/eventsviewer/list/body/row/RcDiscoButtonPlaceholder"></div></td></tr>`;
}

export function handleOpenRow(n = 6) {
  return eventRow(n, HANDLE_OPEN, {
    time: { iso: "2022-07-27T10:42:40.312+00:00", date: "7/27/22", clock: "10:42:40.312 AM" },
    selectedFields: [
      ["host", "attack_data_attack_techniques_T1003.001_atomic_red_team_crowdstrike_falcon"],
      ["source", "crowdstrike"],
      ["sourcetype", "crowdstrike:events:sensor"],
    ],
  });
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) console.log(handleOpenRow());
