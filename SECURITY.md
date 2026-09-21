# Security

What Reach can and cannot do, where its data goes, and what a reviewer in a
regulated environment should check before approving it. Every claim below
points at the file and symbol that enforces it; verify the code, not the
sentence. This text describes version 0.5.58.

## The boundary

Reach is a browser extension that runs only on origins the user has
individually enabled from its popup: Splunk Web origins, one per click, and
the Azure portal pair (`portal.azure.com` and the Logs blade's
`*.reactblade.portal.azure.net`, one prompt naming both, `content-config.js`
`SENTINEL`). On those pages it:

- reads the DOM to know which field, value, sourcetype or table and index
  were clicked;
- adds a section to Splunk's own field and value menus, and to the Logs
  blade's grid menu;
- on Splunk, on an explicit click, dispatches a search job through Splunk's
  REST API using the browser's existing Splunk Web session, and reads the
  results. One click authorises one search, or, from the Discover page's
  "Full discovery" button, a bounded batch of the same fixed discovery
  searches: enumerated before it starts, run one sourcetype at a time,
  cancellable between steps, stopped by itself after three relay failures
  in a row. Nothing runs without a click and nothing is scheduled;
- on Sentinel, builds KQL as text and hands it to the user: the clipboard,
  the blade's own editor, or a portal deep link. It never runs a query
  there and never touches the network;
- stores the user's own annotations, notebook, runbooks, benign marks and
  discovered facts in the browser's extension storage.

It does not:

- run on any origin that has not been enabled from the popup;
- contact any host other than the SIEM origin the page is already on,
  with four opt-in exceptions, each a module that is off until the user
  switches it on in Settings and accepts a host-permission prompt:
  `www.virustotal.com` (data flow 4), `hashlookup.circl.lu` and
  `api.first.org` (data flow 5), and a self-hosted MISP or IntelOwl at an
  origin the user types (data flow 6);
- hold, store, or transmit a credential of any kind for Splunk or
  Sentinel. The credentials it can hold are the VirusTotal key and the
  self-hosted instance's token, both supplied by the user, both in
  `chrome.storage.local`, each sent only to its own host;
- write to indexed data, knowledge objects, saved searches, alerts,
  configuration, or any Splunk endpoint other than the search-job
  endpoints it dispatches to and the GET reads listed under data flow 2.
  "Save as scheduled alert" on a hunt page writes the SPL into the open
  tab's search bar (`app/lib/editor-bridge.js` `apply`, mode `set`) and
  the analyst saves it in Splunk; Reach itself saves nothing there;
- write to anything outside the browser except, with a second toggle on,
  a sighting or a proposed attribute on the user's own MISP (data flow 6);
- load remote code, send telemetry, or call any other third-party service.

## Data flows

The first three are the extension's normal operation and involve no host
but the user's own SIEM. Everything after that is off until the user turns
it on. VirusTotal, CIRCL and EPSS are named third parties; the self-hosted
instance is not, because the user types its origin.

**1. Bundled data → the page.** The packs and their sidecars
(`app/packs/*.json`, read by `app/lib/packs.js` `getJson`), the enrichment
bundles (`app/data/enrich/*.json`, one loader per source under
`app/lib/enrich/`) and the known-good corpus (`app/data/known/*.json`,
`app/lib/known.js` `getJson`: one macOS index of signing ids, paths and
builds, no file hashes, and four Linux files with package checksums)
ship inside the extension and are read with `fetch()` against the
extension's own URL, each on its first use. No network.

**2. The Splunk page → the same Splunk origin.** Every request in
`live-lookup.js` and `discovery-agent.js` is a relative path
(`/<locale>/splunkd/__raw/...`) with `credentials: "include"`
(`live-lookup.js` `authedFetch`). The browser resolves that to the origin
the tab is on; there is no hostname anywhere in the extension. Requests
carry the page's own CSRF cookie and `X-Requested-With`, exactly as Splunk
Web's own JavaScript does. The endpoints touched:

| endpoint | method | purpose |
|---|---|---|
| `search/v2/jobs` | POST | dispatch a search (`live-lookup.js` `dispatch`, `runReporting`) |
| `search/v2/jobs/<sid>` | GET | poll status (`pollUntilDone`) |
| `search/v2/jobs/<sid>/results`, `/results_preview` | GET | read results (`fetchResults`, `fetchStats`) |
| `search/v2/jobs/<sid>` | DELETE | cancel an abandoned job (`cancelJob`) |
| `search/v2/jobs/<sid>` | GET | the advisor's Measure button: the counts (scanCount, eventCount, resultCount, runDuration, optimizedSearch) of a job the user already ran, read on that click only, the sid pattern-checked (`discovery-agent.js` `JOB_RE`) and only `JOB_KEYS` returned; the same endpoint as the poll row above, no new class |
| ten GET paths: `data/props/{extractions,fieldaliases,calcfields,lookups}`, `data/transforms/{extractions,lookups}`, `data/indexes`, `datamodel/model`, `configs/conf-macros`, `configs/conf-props` | GET | read declared field structure, exact-match allowlist (`discovery-agent.js` `REST_ALLOW`) |

The POST and DELETE act on search jobs the user's own session created.
Nothing writes to indexes, lookups, saved searches, alerts, or
configuration.

Every dispatch follows a click, and every search is a fixed template or a
query the page rendered and the user saw:

- a pivot's or a pack workflow's search from the value page, a popup or
  the workflow page (Run);
- the Discover page's discovery searches (`app/lib/discovery.js`:
  `inventory`, `profile`, `recordTypes`, `provenance`, `decodes`); the
  "Full discovery" button runs the same per-sourcetype searches for every
  sourcetype the inventory returned, one sourcetype at a time
  (`app/lib/discovery-sweep.js`), with the list settled before the first
  search, a cancel that takes effect before the next step, a per-job
  deadline passed down the relay (`timeoutMs`, clamped in
  `discovery-agent.js`), and an automatic stop after three relay-level
  failures in a row. The page has to stay open: there is no alarm, no
  offscreen document, no worker-side loop, so closing the tab ends the
  batch;
- the "Fleet corpus" button on the Discover page (`discovery.orgCorpus`,
  the SPL of `orgCorpusSpl`): one reporting search over the analyst's own
  Falcon process events in the chosen index and window, `stats dc(aid) ...
  by SHA256HashData, ImageFileName, SigningId, event_platform`, capped at
  20,000 rows, stored in the discovered layer as the environment's
  `org_corpus`. It is not part of full discovery and its button says it
  scans every process event in the window;
- a hunt (`discovery.hunt`): a pack workflow's search run once as the
  page rendered it, rows handed back to the page, nothing stored;
- the pattern builder's test search and the History control's
  `| history` search over the user's own search history
  (`search-history.js`), each on its own click.

A search from an in-page popup is dispatched by the content script
itself on that tab (`app/lib/click-splunk.js`, through `live-lookup.js`,
from an `isTrusted` click). A search from the app pages goes through the
relay: the page asks the worker (`background.js` `reach:discover:run`),
the worker forwards to a content script on an open tab of that origin,
and `discovery-agent.js` runs it with the tab's session.

**3. The user's own records → a file or the clipboard.** Export and import
of the annotation catalogue and the runbooks (`app/views/share.js`,
`app/lib/share.js`) produce a JSON file via a Blob download
(`app/components/download.js`) and read one the user picks. A runbook page
exports one runbook the same way and hands a Sentinel incident task list
to the clipboard or a file (`app/views/runbook.js`, `app/lib/runbooks-tasks.js`).
The notebook copies an investigation as Markdown or plain text
(`app/views/notebook.js`). No upload target exists.

**4. One clicked value → `www.virustotal.com`, with the user's own key.**
Opt-in, default off, and gated three times. VirusTotal is a `mode: "fetch"`
source in `app/lib/enrich/virustotal.js`, and the registry's `gate()`
(`app/lib/enrich.js`) refuses any fetch or stream source whose id is not in
the caller's `enabledIds` (the sources whose module is on, configured and
permitted), so a fetch source inherits this opt-in by construction rather
than by each caller remembering to check.

- *Setup.* The VirusTotal module is off by default (`app/lib/modules.js`,
  tier `off`). Switching it on in Settings requests the
  `https://www.virustotal.com/*` host permission from that click
  (`modules.js` `setEnabled` → `requestHosts`, the one `permissions.request`
  call site besides the popup's enable button) and the switch stays off if
  the grant is refused. The key is then pasted into the module's settings
  and stored in `chrome.storage.local` under `vtApiKey` on Save
  (`app/components/moduleList.js` `genericBody`). "Forget" deletes the
  key; switching the module off deletes the key and revokes the
  permission. Reach ships no key and never will; the free public API's
  terms are the user's to accept, and the settings hint says so.
- *Which values.* A row offers the lookup only when the clicked value
  passes `app/lib/virustotal.js` `classify()`: a public IPv4 or IPv6
  address, a hostname with a public-looking TLD, or a hex string of
  exactly MD5/SHA-1/SHA-256 length. Refused before any button exists:
  RFC 1918, loopback, link-local, CGNAT, multicast and reserved addresses,
  names under `.local`, `.internal`, `.corp`, `.lan`, `.arpa` and the
  like, and a 32-hex value on an id field such as FDR's `aid`
  (`NOT_A_HASH_FIELD`). An internal address is never sent anywhere.
  `tests/virustotal.test.js` pins each of these.
- *Which clicks.* The value click that opened the popup sends nothing;
  rendering the offer sends nothing. The request is made only from an
  `isTrusted` click on the row's own button (`app/lib/bands/enrich.js`),
  one value per click, never for a column, a grid, or in the background.

The request itself is made by the background worker (`background.js`
`lookup()`, driven by the `relay` descriptor in
`app/lib/enrich/virustotal.js`), the only code that ever reads the key. A
content script sends `{ kind, id }` and receives the report or one
sentence; the key is never in a message, never in a content script, never
in page context. The worker re-checks that the module is on
(`modules.on`), re-validates the kind and id (the descriptor's `accepts`)
so a forged message cannot turn it into a proxy for the key, checks the
permission on every call, sends `credentials: "omit"`, and caches answers
for ten minutes (`cacheTtlMs`) so re-opening a popup does not spend quota.
`tests/virustotal-relay.test.js` covers the handler end to end against a
canned VirusTotal.

What VirusTotal receives: the value, the key, and whatever the browser's
network stack sends with any HTTPS request. What VirusTotal can infer:
that this account looked up that indicator at that time. That is the
inherent cost of the feature and the reason it is off by default.

**5. One clicked hash → `hashlookup.circl.lu`; one clicked CVE id →
`api.first.org`.** Two keyless lookups, each its own module, off by
default, each requesting its one host permission when switched on and
revoking it when switched off. The same relay (`background.js` `lookup()`
over the descriptors in `app/lib/enrich/circl.js` and
`app/lib/enrich/epss.js`) with the same checks: module on, the source's
flag key true, permission held, kind and id re-checked (a 32, 40 or 64 hex
hash; `CVE-YYYY-NNNN`), GET, `credentials: "omit"`. No key exists to
protect; what each service receives is the one value.

**6. One clicked value → a self-hosted MISP or IntelOwl, at an origin the
user types.** Opt-in, default off (nothing is saved until an origin passes
validation and the permission prompt is accepted), and different from
flows 4 and 5 in one respect: the destination is not a name Reach ships,
it is whatever origin the user types into the module's settings.

- *Setup.* The user picks a provider (MISP or IntelOwl), types an origin,
  and pastes a token from their own account on that instance.
  `app/lib/enrich/selfhosted.js` `originStatus()` requires `https://`, or
  `http://` only for `localhost` or an RFC 1918 address (with a warning
  kept and shown, never silently dropped); the Save click requests
  `chrome.permissions.request` for exactly that origin
  (`${protocol}//${host}/*`, `patternFor`, the same shape `popup.js`
  builds for a Splunk origin) and only stores the origin, provider and
  token once that is granted. "Forget" removes all three and revokes the
  permission; so does switching the module off.
- *Which values.* The same conservative rule as VirusTotal for hash, IP
  and domain (`app/lib/virustotal.js` `classify()`), plus a CVE id
  (`app/lib/shapes.js` `detectCve()`) and an absolute URL (`detectUrl()`),
  since a self-hosted instance is not limited to VirusTotal's three shapes.
- *Which clicks.* Same discipline as flow 4: the request is made only
  from an explicit click on the row's own button, one value per click.
- *The request.* `background.js` `lookup()`, driven by the `relay`
  descriptor in `app/lib/enrich/selfhosted.js`, is the only code that
  reads the origin, token and provider; a content script sends
  `{ kind, id }` and gets the summarised result back, never the token.
  The kind and id are re-checked against the fixed set
  (`hash|ip|domain|url|cve`) before any fetch, `credentials: "omit"`
  throughout. MISP: `GET /attributes/restSearch`; IntelOwl:
  `GET /api/jobs?observable_name=`, never `analyze_observable`.
  `registerForGrant` in `background.js` excludes every fetch-target host
  (read from the relay descriptors' `hosts`) from Splunk and Sentinel
  content-script registration, so granting this permission never adds the
  server to Splunk discovery.
- *Writes (MISP only, off by default).* With the module's "Allow writes
  to MISP" toggle on (`reach.enrich.selfhosted.writes`), a result row
  offers two more clicks, each one request through `background.js`
  `write()` over the same descriptor's `writes`: "Record sighting" (`POST
  /sightings/add/<attribute id>`, body `{ source: "Reach" }`) on a hit, and
  "Propose to MISP" on a held value with no hit (`GET /events/index`, the
  recent page, then `POST /attributes/add/<event id>` with the value, its
  MISP type, the Hold reason as comment and `to_ids: false`). `write()`
  runs every check `lookup()` runs (module on, origin saved, permission
  held, the message's ids and kind re-checked against fixed shapes), then
  the writes toggle (`writable`); a module that is off or a toggle that is
  off answers a refusal before any fetch. A click on "Propose to MISP"
  never holds or pins: the action draws only for a value already in the
  notebook and reads that pin's reason
  (`tests/enrich-row-write-actions-never-hold.test.js`). MISP's own
  `Security.check_sec_fetch_site_header` guard (on by default) answers 405
  to any POST whose `Sec-Fetch-Site` is not `same-origin`, which an
  extension worker's request never is, so the toggle's hint says the
  instance needs that guard off; Reach does not try to get around it.
  `tests/enrich-selfhosted-write.test.js` covers the gate order.

What the self-hosted instance receives: the value, and the token, over
HTTPS, exactly as the user configured it. With writes on, also the sighting
or the proposed attribute the user clicked to send, and the Hold reason
typed for that value. This is the user's own server, under the user's own
account and terms; it is documented here as a data flow, not as a
third-party recipient (see `docs/COMPLIANCE.md` §4 for the
user-specified-server reading this rests on).

No other host leaves the browser. There is no analytics, no crash
reporting, no update check beyond the browser's own extension update
mechanism.

## Supply chain

`package.json` declares no dependencies. There is no build step, bundler,
transpiler, or CDN reference. What is in the repository is what runs; a
reviewer can read all of it. Tests run with `node --test` and, for the
browser suite, Playwright against the unpacked build. The shipped package
is the committed tree with comments stripped, never minified
(`tools/dev/strip-comments.mjs`, "Building a release" below).

## Permissions

`manifest.json` requests `scripting`, `storage`, `activeTab` and
`sidePanel`. Host access is declared only as `optional_host_permissions`:
`*://*/*`, `https://www.virustotal.com/*`, `https://hashlookup.circl.lu/*`
and `https://api.first.org/*`. Nothing is granted at install. The manifest
sets no `content_security_policy`, so the extension pages run under
Manifest V3's default (`script-src 'self'; object-src 'self'`).

A host permission is granted from a user gesture at two call sites only.
The popup's enable button (`popup.js` `onToggle`) requests exactly one
Splunk origin as `<origin>/*`, or the Azure portal pair in one prompt.
`app/lib/modules.js` `requestHosts` requests a module's fetch-target hosts
when the module is switched on (VirusTotal, CIRCL, EPSS: the fixed host in
the module's `hosts`) or when the self-hosted relay's Save click passes
validation (the typed origin, `hosts` as a function of the settings);
`revokeHosts` removes them when the module goes off or is forgotten.
Content scripts are registered for the granted page origin by the popup
(`upsertScripts`) and again by the background worker when Chrome reports
the grant (`chrome.permissions.onAdded`, `registerForGrant`): Chrome's
native permission prompt closes the popup, and its script can die before
it registers, so the worker registers for exactly the origins the grant
named and no others, skipping every fetch-target host (they are fetch
targets, not pages). Disabling from the popup unregisters the scripts and
removes the permission.

At startup the background worker re-registers content scripts only for
origins the permission system still grants (`background.js`
`restoreTrustedOrigins()`). The stored list is treated as a hint, not a
source of truth, so a permission revoked from `chrome://extensions` stays
revoked.

Every Splunk content script begins by checking for a Splunk Web asset
signature in the DOM and exits if it is absent; the two Sentinel scripts
run only on the portal pair's match patterns. These are cost-saving
checks, not a security boundary; the boundary is the per-origin grant.

## What Splunk still controls

Reach does not bypass, replace, or supplement any Splunk control. It
dispatches searches the same way the Splunk Web search bar does, so:

- **Authorization** is the user's Splunk role. Reach cannot read an index,
  sourcetype, or field the user's role cannot read. There is no service
  account and no second credential to govern.
- **Audit** is Splunk's own. Every search Reach dispatches is a job on the
  search head, attributed to the user's session, visible in `_audit` and
  the job inspector like any other. Nothing runs outside that trail.
- **Quotas** (search concurrency, disk, and time bounds) are the user's
  role's. Abandoned jobs are cancelled (`live-lookup.js` `cancelJob`).
- **Session lifetime** is Splunk Web's. Reach reads the CSRF cookie fresh
  on every request and never caches it; when the session ends, so does
  Reach's access.

## What Microsoft still controls

On the portal Reach reads the Logs blade's grid on a right-click and
writes KQL as text. It never reads a token, never calls
`api.loganalytics.io` or any Azure endpoint, and never runs a query: the
user runs it in the editor and, for discovery, pastes the result back
(`docs/SENTINEL.md` §5). The one navigation it triggers is the portal's own
"share link to query" URL, opened on a click. The blade script posts that
link to the top frame with `postMessage` (`sentinel-grid.js`); the receiver
(`sentinel-workspace.js`) accepts only a `reach:open` message from a
`*.reactblade.portal.azure.net` origin whose URL matches the Logs blade
deep-link shape exactly, and opens it in a new tab.

## Inside the extension

**Messaging.** The app page and content scripts talk through the
background worker, which accepts messages only from this extension
(`background.js` `relay()`); the content-script agent checks the same
(`discovery-agent.js`, every `onMessage` listener). There is no
`onMessageExternal` listener and no `externally_connectable` entry, so no
other extension and no web page can reach the relay. The discovery
messages (`reach:discover:tabs`, `:run`, `:rest`) are further accepted
only from a top-level extension document: the side panel (no sender tab)
or the catalogue tab (frame 0), never from a copy of `index.html` framed
by a web page (`fromTopLevelExtensionPage`); and a run or REST call names
an origin the worker itself lists as enabled (`enabledOrigins`:
`trustedOrigins` plus the registered content scripts), or it is refused
before any tab is looked for. `reach:selection` and the enrichment
messages are outside that check: the Sentinel blade script runs in a
subframe and sends them from there. `reach:selection` is cleaned to a
fixed set of short strings (`cleanSelection`) before it reaches the panel.

**Framing.** `index.html` is web-accessible (the popups link to it), so a
web page can embed the extension's copy. `boot.js` hides the page and
shows a notice when the document is not top-level under
`chrome-extension:`; the relay refuses the framed sender regardless.
`web_accessible_resources` lists only what a content script imports
(`app/lib/*`, `app/components/*`, `app/data/*`, `app/packs/*`,
`live-lookup.js`), the two page-injected bridges
(`search-history-inject.js`, `sentinel-editor-inject.js`), and
`index.html`; `tests/war.test.js` holds the list to the import closure.

**DOM construction.** Every element is built with `app/components/h.js`,
which sets text through `createTextNode` and attributes through
`setAttribute`. There is no `innerHTML` with dynamic content, no `eval`,
no `Function`. Pack data, Splunk results, grid cells and imported files
are all rendered as text.

**SPL and KQL construction.** Discovery searches are fixed templates
(`app/lib/discovery.js`; the full-discovery batch calls the same
functions and builds no SPL of its own); index, sourcetype, and field
names from the page are either matched against a strict character
allowlist or quoted with backslash-then-quote escaping (`discovery.js`
`term`, `indexClause`). Pivot SPL and KQL from a pack are generated by
`app/lib/spl.js` and `app/lib/kql.js` with the same quoting. The query a
user approves is captured at render time and dispatched verbatim, never
re-read from the DOM at click time.

**Imported files.** A catalogue or runbook import is checked for format
and version (`app/lib/share.js` `read`, `app/lib/catalogue.js`
`importUser`, `app/lib/runbooks-store.js` `importDoc`) and its keys are
refused if they are `__proto__`, `constructor`, or `prototype`
(`catalogue.js` `isUnsafeKey`, applied on import and on every annotation
write path). Field names arrive from page content (a JSON leaf's dotted
path, a grid column), so the same guard applies to annotations made from
a popup.

**Links.** The only typed URLs that become an `href` are the Splunk base
in the standalone page, accepted only if it parses as `http:` or `https:`
(`app/lib/settings.js` `isHttpUrl`), and the self-hosted origin's MISP
page link, validated by `originStatus`. Pack citations are protocol-checked
the same way (`app/components/meaning.js`).

## Storage

Every key Reach writes belongs to one module in the registry
(`app/lib/modules.js` `keysOf`), and `tests/modules-registry.test.js`,
`tests/storage-keys.test.js` and `tests/wipe.test.js` hold every store's
exported `KEY`, `KEYS` or `PREFIX` to it. In `chrome.storage.local`:

- shell: the enabled-origin list (`trustedOrigins`), the Sentinel panel
  preference and the onboarding card's dismissed flag
  (`reach.sentinel.alwaysPanel`, `reach.onboarding.dismissed`), the
  module switches (`reach.modules`);
- catalogue: the user's annotations and confirmed bindings
  (`reach.catalogue.user`);
- hold: the investigation notebook (`reach.notebook`);
- settings: the index or workspace override and the Splunk app namespace
  (`csIndex`, `spAppNamespace`);
- discovery: the discovered layer, one document per environment under
  `reach.catalogue.discovered.` plus its index
  (`reach.catalogue.discovered.envs`), the sweep's resume state
  (`reach.catalogue.discovery.sweep`) and the Sentinel workspace list
  (`reach.sentinel.workspaces`); the fleet corpus lives inside each
  environment's document as `org_corpus` and belongs to the verdicts
  module, which clears it in place;
- runbooks: `reach.runbooks`;
- benign: the known-benign list (`reach.benign`) and the
  "offer the exclusion in the editor" switch (`reach.benign.inject`);
- virustotal, circl, epss, selfhosted: `vtApiKey`,
  `reach.enrich.circl.enabled`, `reach.enrich.epss.enabled`, and
  `reach.enrich.selfhosted.{provider,origin,token,writes}`, all empty or
  false by default.

The key and the token are readable by anyone with the browser profile and
devtools, as any extension-stored secret is; each is the user's own,
revocable at its source, and "Forget" deletes it. Nothing is written to
`chrome.storage.sync`, which would replicate it to the user's browser
account.

A handful of working values bypass that store and go to the writing page's
own `localStorage` (the platform and theme shown, pinned values, the index
scope, the Splunk base URL, a served copy's development extension id) or
`sessionStorage` (the navigation trail, the held facts for the current
case, the last clicked event). Every writer of those is an extension page:
the side panel, the catalogue tab, the popup or the options page
(`app/components/holding.js`, `moduleList.js`, `app/lib/selection.js`,
`app/app.js`, `popup.js`). A content script imports `app/lib/scope.js`,
which reads `reach.scope` from the host page's `localStorage` at import
and writes nothing there; no Reach key is written into a Splunk or Azure
page's storage. (Versions before 0.5.55 carried a migration in
`scope.js` that could write `reach.scope` or `reach.pinned` into the host
page's `localStorage` when a content script imported it and an older key
was present; whatever such a version left behind is that site's data
until the user clears it.)

Three literal keys sit outside the registry, so "Clear all Reach data"
does not remove them: the History control's two preferences
(`historyAutoRun`, `historyTimeMode`, written by `search-history.js`) and
the portal fact the grid script rewrites on every blade load
(`reach.sentinel.currentWorkspace`, named as the exception in
`tests/storage-keys.test.js`). Uninstalling removes them with everything
else.

The catalogue app's standalone mode (served as a plain page, without the
extension) uses `localStorage` for the `chrome.storage.local` data too.
That mode has no Splunk access at all. Discovery is unavailable without
the extension.

## What is stored and how to remove it

`app/lib/wipe.js` clears every key family the registry lists, module by
module (`clearModule`, `run`): "Clear all Reach data" in Settings calls
`run`, unregisters every `reach-*` content script and, if the checkbox is
ticked, revokes every optional host permission. Switching one module off
runs the same clear for that module alone (`modules.js` `setEnabled`
through `useClearer`). `tests/wipe.test.js` scans `app/lib` for an
exported `KEY`/`KEYS`/`PREFIX` constant the registry has not been told
about, so a new store's key cannot land silently outside this list.

**Uninstall removes:** every `chrome.storage.local` key, and every key an
extension page (the catalogue tab, side panel, popup, options page) wrote
to its own `localStorage`/`sessionStorage`. This is automatic; no button
needed.

**Uninstall does not remove:** an investigation copied to the clipboard
("Copy as Markdown" / "Copy plain text", `app/views/notebook.js`), a
runbook's task list copied the same way, because a clipboard write has no
extension-storage record to delete, and a catalogue, runbook or task-list
file downloaded to disk (`app/components/download.js`), because it is now
a file like any other download.

**Revoking a host permission** (popup, Settings, or `chrome://extensions`)
stops content scripts running on that origin again. `sessionStorage` is
per tab: a wipe run from one tab clears that tab's held facts; another
open extension tab keeps its own until it closes, and the wipe says so.

## Known limitations

These are inherent to the design. They are stated so a reviewer can
decide whether they matter in the deployment at hand.

**A content script sees the page.** On an enabled origin, Reach's scripts
can read the whole DOM, including search results. That is what lets it
know which sourcetype an event has. The control is the per-origin grant:
Reach sees only the SIEM pages the user chose to enable, and nothing on
any other site.

**Two scripts run in the page's main world.** `search-history-inject.js`
is loaded as a `<script>` into the Splunk page (`search-history.js`)
because Splunk's search bar is an Ace editor whose instance is reachable
only from the page's own JavaScript context; `sentinel-editor-inject.js`
does the same for the Logs blade's Monaco editor (`sentinel-grid.js`).
Each listens for a few DOM events, accepts only strings, writes text into
the editor or reads it back, and focuses it. Neither runs a search, neither
messages the extension, and neither gives the page anything it did not
already have. A strict page Content-Security-Policy blocks the script; the
History button or the Insert offer then does nothing, and nothing else is
affected.

**Trust in the SIEM origin.** Reach trusts what the enabled origin serves.
A compromised Splunk Web instance could feed it misleading results; it
could not, through Reach, reach any other origin, any other tab, or the
extension's own storage beyond the annotations the user writes.

**Future versions have the same access as this one.** The permission
model does not constrain what an update may do on an already-enabled
origin. For a managed deployment, pin the version: force-install through
the `ExtensionSettings` policy with a self-hosted `update_url`, and
review each version before publishing it there, rather than relying on
store auto-update.

## Security-relevant changes

Findings and narrowings, in reverse order:

- **0.5.58**: two additions to what a click may send, both documented
  above rather than left under the old wording. The self-hosted relay
  gained MISP writes (data flow 6), behind a second toggle that is off by
  default: the "write to nothing outside the browser" statement was
  narrowed to name the sighting and the proposed attribute. The Discover
  page gained the "Fleet corpus" search (data flow 2), a reporting search
  over the analyst's own Falcon process events, run only from its own
  button and never as part of full discovery. Review points: `write()` and
  its gate order in `background.js`, `writes` and `writable` in
  `app/lib/enrich/selfhosted.js`, `orgCorpusSpl` in `app/lib/discovery.js`.

- **0.4.90**: a web page could frame the web-accessible `index.html`
  with `#/discover?env=<an enabled origin>` and dress up its Inventory
  button, whose click ran a real `tstats` search through the relay with
  the user's session. The relay now refuses discovery from any sender
  that is not a top-level extension document, and any origin it does not
  itself list as enabled; `boot.js` refuses to show the app when framed;
  the Splunk Discover view arms only on a listed origin; and
  `web_accessible_resources` shrank from `app/*` and `boot.js` to the
  paths content scripts import. Review points: `fromTopLevelExtensionPage()`
  and `enabledOrigins()` in `background.js`, the guard in `boot.js`,
  `tests/relay.test.js`, `tests/boot.test.js`, `tests/war.test.js`.

- **0.4.67**: "Full discovery" (`app/lib/discovery-sweep.js`) runs the
  existing discovery searches for every inventoried sourcetype from one
  click. The "one click, one search" wording above was narrowed to "one
  click, one search or one enumerated, cancellable batch of the same
  searches" rather than left standing. The batch introduces no new
  endpoint, SPL template, permission or trigger; `timeoutMs` is the one
  new relay field, clamped on the page side. Review points: the runner's
  step list and its stop conditions, and the clamp in
  `discovery-agent.js`.

- **0.4.31**: first third-party call. A VirusTotal lookup (data flow 4)
  was added as an opt-in, bring-your-own-key feature: the "contact no
  host but the SIEM" and "hold no credential" statements above were
  narrowed accordingly rather than left standing. Review points: the
  classifier that decides what may be offered (`app/lib/virustotal.js`),
  the worker handler that alone reads the key (`background.js`), and the
  `isTrusted` click gate in `app/lib/bands/enrich.js`.

- **0.3.12**: `use_dynamic_url` (added in 0.3.6, below) was reverted.
  Chrome has an open, unfixed bug where a dynamic `import()` of a
  web-accessible module from a content script fails under a dynamic URL:
  exactly the pattern `value-popup.js`, `field-info-popup.js`, and
  `search-history.js` all use to load `app/lib/*.js`, so every field/value
  popup silently stopped rendering its Reach section. With it reverted, a
  page can again detect that this extension is installed by probing its
  web-accessible resources at their fixed, per-install URL (a page cannot
  read anything through that probe beyond the fact of installation: no
  Splunk data, no credentials, no code execution). Revisit if Chrome fixes
  the underlying bug.
- **0.3.7** (`d1bd056`): `background.js` had an `onMessageExternal`
  listener, intended for a local development workflow, that forged the
  sender identity the relay's authorization check relies on. The
  accompanying comment assumed the listener was inert without an
  `externally_connectable` manifest entry; the opposite is true: that key
  gates web pages, and its absence lets any installed extension connect.
  Any other extension could therefore have enumerated the user's enabled
  Splunk origins and dispatched arbitrary SPL with the user's session. The
  listener was removed; the development workflow it served was dropped.
  The same commit moved settings off `storage.sync`; the migration shim
  has since been removed.
- **0.3.6** (`149c167`): prototype pollution through a crafted catalogue
  import; `use_dynamic_url` on web-accessible resources so a page cannot
  probe for the extension's presence (reverted in 0.3.12, above).

## Building a release

The working directory contains files that must not ship: `.claude/`
(tooling state), `tools/` (seeding, fetch and corpus scripts for
development, and an ignored credentials file), `tests/`, `docs/`, and the
repository metadata (`README.md`, this file, `package.json`,
`CLAUDE.md`). None is referenced by `manifest.json`; `.gitattributes` marks
them `export-ignore`. Build the published package with `npm run package`,
which runs `git archive HEAD`, honours that list, strips comments from the
`.js`, `.css` and `.html` files and zips the result, never by zipping the
working directory. The archive is the committed tree plus `LICENSE` and
`THIRD-PARTY-NOTICES.md`; uncommitted changes are not included. The
claims in this document describe the archived tree.

## Reporting

Open an issue in this repository, or contact the maintainer directly for
anything that should not be public before a fix is available.
