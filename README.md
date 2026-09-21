# Reach: a data catalogue for your SIEM data, in place

> **One extension, two SIEMs.** On a Splunk Web page Reach is the Splunk
> catalogue described below; in the Azure portal's Logs blade it is the
> Sentinel one: right-click a value or a column header and Reach adds what
> it knows, with the KQL pivots a pack declares, copied or opened as a query
> tab already run. Which one a page gets is decided by the page (its
> hostname); the catalogue app is told by whoever opens it
> (`index.html?platform=sentinel|splunk`, remembered).


A browser extension. In Splunk Web, click a field or a value and Reach adds
what it knows to Splunk's own menu: what the field means **on that
sourcetype**, how it is produced, what its values decode to, how full it is,
and (where a pack covers the feed) what you can pivot to and the SPL to
paste. You can describe the field right there, and the note follows the
field: to every event of that sourcetype, and, where a pack binds the field
to a concept, to the same field under its other name on the other SIEM.

The catalogue is three layers, in fixed precedence:

| layer | what | where it comes from |
|---|---|---|
| **user** | descriptions, roles, tags, sensitivity, owners | you, from a popup or the app; export/import to share |
| **pack** | curated knowledge for one feed, with a pivot graph; written once per feed and bound to each SIEM's column names | bundled: CrowdStrike FDR, AWS CloudTrail, Entra ID sign-ins, Falcon sensor telemetry |
| **discovered** | inventory, fill rates, top values, provenance, decode tables | your own Splunk, one click per search |

Keys are `sourcetype` then field. Index is a qualifier, never the key:
one sourcetype lives in many indexes and one index holds many sourcetypes.

## Install

1. `chrome://extensions` → Developer mode → **Load unpacked** → this directory.
2. Open a Splunk Web page, click the Reach icon, **Enable on this Splunk
   instance** (a per-origin permission; nothing is enabled broadly), reload.
3. Click any field or value. **Open the catalogue →** in the popup opens the
   app.

Local lookups always run automatically. A search runs on your Splunk only
from an explicit click, in a tab you already have open, with that tab's
session. Nothing leaves your browser except to your own Splunk, unless
you set up the optional VirusTotal lookup below, which sends one clicked
value to virustotal.com with your own key and only when you click its button.
See [docs/PRIVACY.md](docs/PRIVACY.md) for the full data-flow account.

## VirusTotal (optional, your own key)

When the value you clicked is a public IP address, a public hostname or a
file hash, the popup can offer **Check on VirusTotal**. It is off until you
add your own key, and even then nothing is sent until you click that
button: click the value, then click VT. Internal addresses and names
(`10.x`, `192.168.x`, `*.local`, FDR's `aid`, …) are never offered.

1. Create a free VirusTotal account at
   [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) and
   confirm the email.
2. Copy your key from
   [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).
3. Reach icon → **Settings** → **VirusTotal** → paste → **Save key**. The
   browser asks once to let Reach contact `www.virustotal.com`. **Test key**
   spends one lookup to prove the whole path works.

The free key allows 4 lookups a minute and 500 a day, and VirusTotal's
terms restrict the public API to non-commercial use; the key and the
terms are yours. The key is stored in this browser only, is read only by
the extension's background worker, and never reaches the SIEM page. See
[SECURITY.md](SECURITY.md), data flow 4.

## Third-party licenses and attribution

Reach includes data and enrichment content from MITRE ATT&CK, Splunk, CISA,
LOLDrivers, Microsoft Sentinel, SigmaHQ, and enumerated platform-default
binary corpora. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for
full license texts and attribution.

## Develop

```bash
npm test                              # node's test runner, no dependencies
npm run test:chrome                   # the extension in Chrome against fixture pages (see Tests)
python3 -m http.server 8765           # the app as a plain page (localStorage; no discovery)
```

Content-script changes need an extension reload (↻ on chrome://extensions)
and a page reload; bump `version` in `manifest.json` with every change so
the loaded build is identifiable.

Driving discovery from the served copy (`:8765`) instead of the extension's
own pages used to go through a `chrome.runtime.onMessageExternal` relay,
opted into locally via an `externally_connectable` manifest entry. That
relay is gone: `onMessageExternal` fires for any installed extension, not
just pages matching `externally_connectable.matches` (that key only gates
web-page senders), so it let any other extension run arbitrary SPL against
this user's Splunk by forging the sender the relay's own `sender.id !==
chrome.runtime.id` check relies on. Exercise discovery through the
extension's own pages instead; a content script orphaned by an extension
reload answers "receiving end does not exist." Reload that Splunk tab.

### Tests

`npm test` is the node suite (`tests/*.test.js`, `node --test`, no
dependencies): a test per behaviour, fixtures under `tests/fixtures/`. It
stays fast; nothing in it opens a browser.

`npm run test:chrome` loads the unpacked build into Playwright's Chromium
(new headless, a persistent profile: the one mode that takes extensions)
and drives it against two saved pages under `tests/fixtures/pages/`: a
Splunk search page captured from the dev instance and a Logs blade grid
slice. It checks what the node suite cannot: the content scripts attach, a
value click opens the host's own popup with the REACH section in it (value
row, pattern block, verdict, enrich row), Hold lands in `chrome.storage`,
Insert lands in the search bar through the editor bridge, a blade
right-click gets the section in the grid's menu, and the side panel page
lays out at 380 px. Assertions are on the DOM; a failing test leaves one
screenshot under `tests/chrome/screenshots/`. Once per clone:

```bash
npm install                           # playwright, the one devDependency
npx playwright install chromium       # its Chromium build, once
```

About five seconds a run. The build under test is staged into a temp dir
with the two fixture origins added as `host_permissions`, the one manifest
difference, because host access is granted per origin from the popup's
native prompt in the product and no automation can click it; the content
scripts are then registered the way `background.js` registers them.
Discovery, enrichment fetches, the side panel's implicit mode and Insert
into the portal's Monaco are not covered: they need the real extension
against the dev Splunk or the portal. `tests/fixtures/pages/README.md`
says how the fixtures were captured and how to refresh them.

## Sentinel

1. `chrome://extensions` → Developer mode → **Load unpacked** → this directory.
2. Open the Logs blade on a workspace, click the Reach icon, **Enable in the
   Azure portal** (grants `portal.azure.com` and the blade's
   `*.reactblade.portal.azure.net` origin), reload the tab.
3. Right-click a value in the results grid; right-click a column header;
   expand a row and right-click a leaf of a dynamic column. Alt+click opens
   Reach's panel without the blade's menu.
4. **Discover** in the app is a recipe: each step is a link that opens the
   Logs blade with a query already run; Copy value on the one result cell
   and paste it back.

After ↻ on `chrome://extensions`, reload the portal tab too: a blade frame
keeps an orphaned copy of the content script otherwise, and every click in
it fails silently.

## Layout

```
manifest.json, background.js          MV3 shell; per-origin content-script registration; message relay
json-tree-fields.js                   makes Splunk's JSON-tree leaves clickable through Splunk's own menu
value-popup.js, field-info-popup.js   the two in-Splunk surfaces
discovery-agent.js, live-lookup.js    run a search / REST read on the Splunk page for the app
sentinel-workspace.js, sentinel-grid.js  Sentinel: the workspace off the portal URL; the Logs-blade grid hooks (all frames)
app/lib/platform.js                   which SIEM this build targets, and the words for the key
app/lib/kql.js, recipe.js, intake.js  Sentinel: KQL primitives + deep link; the discovery recipe, its queries and envelope; pasted results
app/lib/sentinel-context.js           Sentinel: which cell, column and table a click landed on
app/lib/context.js                    which event was clicked: sourcetype, index, record type
app/lib/catalogue.js                  the merge: user > pack > discovered, keyed (sourcetype, field); user notes keyed by concept when bound
app/lib/packs.js, app/packs/          packs v1 (per platform) and v2 (one feed, bindings per platform); the taxonomy
app/lib/concepts.js, taxonomy.js      the resolver: (platform, container, column) → concept; concept types above feeds
app/lib/values.js, app/packs/*.values.json  the data dictionary: format, values with a meaning each, examples, provenance, cite; one sidecar per pack, fetched per container (docs/PACKS.md)
app/lib/intent.js                     query intent in concepts, planned onto a container's columns
app/lib/compile-spl.js                the SPL emitter: a plan → a template pivot.js renders ($param$ tokens, never a value)
app/lib/compile-kql.js                the KQL emitter: the same plan → a KQL template, tostring() on dynamic paths
app/lib/learned.js                    the learned layer: bindings the user confirmed, projected into the resolver as one pack; coverage and blockers
app/lib/propose.js                    the name-first proposer: tokens, vocabulary, feed election, tiers; matches across environments
app/lib/shapes.js                     what a column's values look like (ARN, IP, GUID, JSON, ...): confirms or vetoes a proposal
app/lib/segments.js                   a value cut along its shape (path, command line, URL, ARN, email, IP, domain, GUID): the pieces a pattern keeps or opens
app/lib/ladder.js                     the construct ladder: segments plus keep, any or like per piece to the cheapest SPL and KQL construct, with the reason
app/lib/editor-bridge.js, search-history-inject.js  the editor bridge: read the search bar, insert or replace a term (Splunk's Ace, main world); the side panel relays through the page; Sentinel copies
app/lib/known.js, app/data/known/     known-good verdict on a process value against the bundled macOS/Linux corpus
app/lib/store.js                      chrome.storage.local / localStorage
app/lib/layer.js                      the discovered layer's store: one key per environment, one writer for both platforms, a byte budget that says what it dropped
app/lib/discovery.js                  the fixed inventory / profile / provenance / decode searches
app/lib/discovery-sweep.js            full discovery: those searches for every inventoried sourcetype, one at a time, cancellable, resumable
app/lib/pack-fields.js, app/packs/*.fields.json  a pack's field catalogue: the per-field records, record types and join graph a vendor's add-on lands (the Falcon pack's is the FDR bundle), one sidecar per pack, fetched per container
app/lib/spl.js                        SPL text primitives: quote, list, time modifier, the Splunk Cloud command lint
app/lib/pivot.js                      the query renderer: a pack edge's or query's template lines, tokens and gates, to SPL or KQL
app/lib/fdr-queries.js, reachability.js  the FDR pivot graph: a view's pivot spec mapped onto the crowdstrike-falcon pack's queries, the join graph's notes on a hop
app/views/, app/components/           the app: catalogue, sourcetype, field, discover, coverage (the confirm flow), share, FDR workflows
app/lib/notebook.js, notebook-md.js   the investigation notebook (held values with provenance, pivots as edges, notes) and its Markdown; app/views/notebook.js draws it
app/lib/surface.js, copy.js           the three widths (wide tab, narrow tab, side panel) and the lines written twice for the panel
app/styles/                           tokens, base (the page grid per surface), components (each one's wide design, then every width rule in one section)
tests/                                node --test; tests/chrome/ the Chrome harness (npm run test:chrome); tests/fixtures/pages/ the pages it drives
```
