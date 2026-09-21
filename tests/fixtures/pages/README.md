# Page fixtures for the Chrome harness

The pages `tests/chrome/` drives with the real extension loaded. Both are
static HTML with a few lines of script standing in for the host's own
behaviour; neither loads anything from the network.

| file | stands for | origin in the harness |
|---|---|---|
| `splunk-search.html` | a Splunk Web search page, event list view, five captured rows plus six hand-written rows: a `ProcessHandleOpDetectInfo` event, three mac signing rows, a Mac impersonation and an Ubuntu 22.04 process | `https://splunk.fixture.test/en-US/app/search/search?q=…&sid=…` (`splunk-search.json`) |
| `sentinel-logs.html` | the Logs blade frame: KQL editor and the results grid | `https://sandbox-1.reactblade.portal.azure.net/logs` |
| `splunk-notable.html` | the same search page with one notable-shaped row (sourcetype `stash`, an ESCU `search_name`, the risk object and entity fields); built from `splunk-search.html` by `build-splunk-notable-fixture.mjs`, no capture | the search URL with `sid=1700000000.2` (`splunk-notable.json`) |
| `sentinel-alerts.html` | the Logs blade on a `SecurityAlert` query: `AlertName`, `AlertType`, `CompromisedEntity`, `Techniques`, `Entities`; written by hand like `sentinel-logs.html` | `https://sandbox-1.reactblade.portal.azure.net/alerts` |

The harness answers those URLs from these files by request interception
(`context.route`), so the content scripts see a real `https` origin that
matches what they are registered on, with no server, DNS entry or
certificate.

## splunk-search.html

Captured from the dev Splunk (`http://localhost:8001`, Splunk 10.4.3) on
the T1003.001 search
(`index=main sourcetype=crowdstrike:events:sensor aid=f0778584e83c4efc9cf026bc1e7f0489 event_simpleName=ProcessRollup2`),
plus two macOS `ProcessRollup2` rows from our own sensor, so the known-good
verdict has a mac event to read, plus one `ProcessHandleOpDetectInfo` row
written by hand in `handle-open-row.mjs` (`DesiredAccess` 2097151,
`TargetProcessId` 5497396, `RawProcessId` 936, `TemplateDisposition` 30),
the event the field-name click and the PID chain land on; the build appends
it after the captured rows, so `nth-of-type` locators on the captured rows
hold. After it come three mac `ProcessRollup2` rows written by hand in
`mac-signing-rows.mjs` (rows 7 to 9): two starts of a Finder signed under
`com.apple.finder` by a third-party team (`CsValidationCategory` 6) and one
unsigned `/usr/libexec/notasystemd` claiming a `com.apple.` name. The
captured mac rows are Apple's own contactsd, the case the mac signing hunt
excludes, so these are the rows its predicate keeps;
`tests/fixtures/hunt-rows.json` is the stats the hunt's namespace search
makes of them, and `tests/hunt-fixture-rows.test.js` holds the two together.
Then two `ProcessRollup2` rows from `known-rows.mjs` (rows 10 and 11) for
the verdict's other tiers: a Mac row claiming Apple's contactsd path under
`SigningId` `com.evil.contactsd` (impersonation) and an Ubuntu 22.04 row on
`/usr/bin/curl` with the hash the bundled Linux corpus lists and
`aid_os_version` `Ubuntu 22.04` (normal); tests find the two verdict rows
by their text.
The rows keep Splunk's markup as rendered:
the JSON tree (`.json-tree`, `.key-name`, `.t[data-path]`) and the
selected-fields line (`<a class="f-v" data-field-name="host|source|sourcetype">`),
which is what `app/lib/context.js` reads the sourcetype off.

What the build script changes (`build-splunk-fixture.mjs`, see its header):

- everything Reach itself had added to the page at capture time is stripped
  (`data-reach-*`, the `f-v` class and `data-field-name` on JSON leaves, the
  wiring on key names, the REACH section in the popup), so the content
  scripts do their own work on the fixture;
- identifying values are replaced: agent ip (`aip`) with 203.0.113.x,
  customer ids (`cid`) with zeros, our sensor's `aid` and `host`, the
  machine name. The attack_data replay's own values are published and stay;
- `<link href="/en-US/static/@…/img/favicon.ico">` stays: the `/static/@`
  path is the Splunk Web asset signature the content scripts gate on;
- two shims are added in a `<script>`: an Ace-shaped editor on
  `.search-bar-input .ace_editor` (`env.editor` with `getValue`, `setValue`,
  `insert`, `navigateFileEnd`, `focus`, `getCursorPosition`; renders one
  `.ace_line` per line) that `search-history-inject.js` drives, and Splunk's
  field-value menu (`.dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown.open`,
  appended to body on a `.f-v` click, removed on the next click outside),
  the element `value-popup.js` appends its section to. The menu's `<ul>` is
  the captured one. `window.__fixtureEditor` exposes the editor to tests;
- a hand-written fields sidebar (`.fields-sidebar`, two `a.field-info-link[data-field-name]`
  names, one at each edge of the page) and a shim for Splunk's field-info
  popdown (`.popdown-dialog.shared-fieldinfo.open`, 600px wide, appended to
  body under the clicked name and kept inside the viewport, as Splunk does),
  the element `field-info-popup.js` places its flyout beside.

### Refreshing it

1. Start the capture endpoint from the repo root:
   `node tests/fixtures/pages/capture-server.mjs` (listens on 127.0.0.1:8799,
   writes into `raw/`, which is untracked).
2. Open the search on the dev Splunk in Chrome, wait for the rows, and run
   this in the page (devtools console, or the browser tools):

   ```js
   const post = (name, body) => fetch("http://127.0.0.1:8799/?name=" + name, { method: "POST", body }).then((r) => r.text());
   const rows = Array.from(document.querySelectorAll(".shared-eventsviewer-list-body-row")).slice(0, 3);
   await post("splunk-thead.html", rows[0].closest("table").querySelector("thead").outerHTML);
   await post("splunk-rows.html", rows.map((r) => r.outerHTML).join("\n"));
   await post("splunk-bar.html", document.querySelector(".search-bar-input").outerHTML);
   rows[0].querySelector(".f-v").click();
   await new Promise((r) => setTimeout(r, 1000));
   await post("splunk-popup.html", document.querySelector(".dropdown-menu.shared-eventsviewerdrilldown-fieldvaluedrilldown.open").outerHTML);
   ```

   Then the same for the mac rows, on
   `index=* sourcetype=crowdstrike:events:sensor event_platform=Mac event_simpleName=ProcessRollup2 | head 2`,
   posting them as `splunk-rows-mac.html`.
3. `node tests/fixtures/pages/build-splunk-fixture.mjs`. The build refuses
   a fixture that still carries a hostname or a session marker; extend the
   replacement table in the script when a new capture brings a new value
   to hide (a customer id, an internal host), and read the diff of
   `splunk-search.html` before committing.
4. `npm run test:chrome`.

## sentinel-logs.html

Not a capture. Written by hand to the shape of the live blade recorded in
`docs/SENTINEL.md` (section 7, "The Logs blade, as found with the extension
loaded"): the results grid is ag-Grid, so it is `.ag-root[role=grid]`, header
cells `role=columnheader` with `aria-colindex`, rows `role=row` with
`aria-rowindex` and absolutely positioned (DOM order is not row order: the
fixture's rows are deliberately out of order), cells `role=gridcell` with
`aria-colindex`; the query editor is a `.monaco-editor` with real size and
its text in `.view-lines .view-line`. The rows mirror three of the Splunk
fixture's Windows events and its macOS `contactsd` event as the seeded
`ReachCrowdStrike_CL` table would show them (`Type` projected, the pack's
column names, `EventPlatform` and `SigningId` after the hash and the
process id), so a right-click on the Mac row's `SHA256HashData` reaches a
known-good verdict from the bundled corpus, as the Splunk fixture's Mac row
does. The sixth row (`aria-rowindex` 6) is the Splunk fixture's hand-written
`ProcessHandleOpDetectInfo` event, with `DesiredAccess` and `RawProcessId`
as columns 10 and 11 (`aria-colindex`, empty on the other rows), for the
column click and the PID chain. Rows 7 and 8 are the Splunk fixture's
impersonation and Ubuntu rows as the table would show them, the Ubuntu
row's release in `AidOsVersion` (column 12, empty elsewhere). The last
column (13) is `ContextProcessId`, `255667414` on the handle-open row and
empty elsewhere, so scenario 3's second hop runs on the blade; a column is
only ever appended, since the suites locate cells by `aria-colindex`.

The shim is the blade's value menu: a right-click on a body cell opens
`.ag-popup > .ag-popup-child > .ag-menu > .ag-menu-list[role=menu]` with
Copy value / Filter for / Filter to exclude as `role=menuitem` rows, inside
the grid's overlay layer, which is the element `sentinel-grid.js` waits for
and appends to. A header has no menu, as in the blade. There is no Monaco
behind the editor, so the KQL bridge reports no editor and the pattern
block offers Copy, not Insert; the Insert path on Sentinel is a real-portal
check.

### Refreshing it

The blade is a cross-origin iframe and the portal does not keep a session
for a fetch from the console, so a capture goes through the same endpoint
from inside the frame: select the blade frame in devtools, then post
`document.querySelector(".ag-root").outerHTML` and the editor's
`.monaco-editor` element. Strip the hashed React class names (they change
per build; the selectors above do not), the workspace and tenant ids in any
`href`, and any `TenantId` or `_ResourceId` column, and keep the ARIA
attributes and `ag-*` structural classes. Update the row values to match
the seeded sample table if the capture is from a different query.

## What the fixtures do not stand in for

Discovery (runs searches on a live tab), enrichment fetches (VirusTotal
through the background worker), the side panel's implicit mode (a panel
open in the window takes the click), the portal's deep link, and Insert
into Monaco. Those need the real extension in a real Chrome against the
dev Splunk or the portal; `.claude/agents/panel-validator.md` says how.
