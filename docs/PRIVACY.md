# Reach Privacy Policy

Version 2.2, dated 2026-09-20. This policy covers the Reach browser
extension as published on the Chrome Web Store.

## Summary

Reach is free, carries no ads, and has no accounts. Everything it keeps
stays in your own browser profile. Nothing leaves your browser except
through the actions listed under "Data sent to third parties" below,
each of which you start yourself with a click.

## Who we are

Reach is published by ReadyCheck, the trader named on the Chrome Web
Store listing, and developed in the open under the elegint-dev name at
elegint.dev. Questions about this policy go to contact@readycheck.ai.
"We" means ReadyCheck. This policy is hosted at https://elegint.dev/privacy,
and the source is public at https://github.com/elegint-dev/reach-extension
(MIT).

## What the extension does

Reach is a data catalogue for Splunk and Microsoft Sentinel. On a
Splunk Web page or an Azure portal Logs blade that you have enabled it
on, it reads what you click and shows what that field means, how it
decodes, and what it can reach. It reads only the page you are on, only
after you enable that site, and it acts only when you click something.
Its reference catalogues (CISA KEV, MITRE ATT&CK, Sigma, Splunk ESCU,
Microsoft Sentinel analytic rules, LOLDrivers, LOLRMM), the data packs
and the known-good corpus of platform binaries (for macOS the signing
ids and paths of Apple's own binaries and the builds each was seen on,
no file hashes; for Linux the package checksums) ship inside the
extension and are read from there.

## Data we collect

None. We run no server, no account system, no analytics, no crash
reporting and no telemetry. The extension never sends us what you
clicked, what you enabled, or the fact that you use it. The one figure
we ever see is the aggregate install count the Chrome Web Store shows
every publisher, which comes from Google, not from Reach.

## Data stored on your device

Reach keeps its data in the extension's own `chrome.storage.local`:
the sites you enabled it on and which modules you switched on or off;
your annotations and the column-to-concept bindings you confirmed;
facts discovered from your own Splunk instance or Sentinel workspace
(inventories, field profiles, record types, decode tables, and, if you
run it, the fleet corpus: which binaries your own hosts run, measured
from your Falcon process events) with the discovery run's resume state
and the Sentinel workspaces seen; the investigation notebook; your
runbooks; values you marked known-benign; the index or workspace
override and the Splunk app namespace; your settings (the Sentinel
panel preference, the dismissed onboarding card, the "offer the
exclusion in the editor" switch, the History control's two
preferences) and, only if you set them up, your VirusTotal API key, the
CIRCL and EPSS switches, and the origin, provider, token and writes
switch of a self-hosted enrichment server. A few working values (the
platform and theme shown, the navigation trail, pinned values, the
index scope, the Splunk base URL, the facts held for the current case,
the last event clicked) live in the `localStorage` and `sessionStorage`
of the extension's own pages: the side panel, the catalogue tab, the
popup and the options page. Reach writes no key of its own into a
Splunk or Azure page's storage; on an enabled page it only reads an
index scope an earlier version may have left there.

All of this stays inside your browser profile. Nothing is written to
`chrome.storage.sync`, so Chrome does not replicate it to your Google
account. It is not encrypted beyond what the browser provides: anyone
with your profile and its developer tools can read it, as with any
extension's local storage.

## Data sent to third parties, only on your explicit click

| Service | What is sent, and when | Whose credentials |
|---|---|---|
| Your Splunk instance | When you click a search button on an enabled Splunk page or in the catalogue, a search job is dispatched to the same Splunk origin the tab is on, through Splunk's own REST API, and its results are read back: a pivot's search, a workflow's or a hunt's search, the pattern builder's test search, the History control's search over your own search history, the Discover page's fixed discovery searches, the "Fleet corpus" search over your Falcon process events, and the advisor's read of a job you already ran. Full discovery runs a bounded, cancellable batch of the same discovery searches from one click. "Save as scheduled alert" writes the search into the open tab's search bar and nothing else; Reach saves no search, alert or other object in Splunk. | Your existing Splunk Web session, attached by the browser. Reach never sees or stores a password or token. |
| Your Sentinel workspace | Nothing is sent. Reach reads the Logs grid when you right-click, builds a KQL query as text, and either copies it, writes it into the blade's own editor, or, on your click, opens it in the Azure portal's own Logs blade through a "share link to query" URL. You run the query. A runbook's Sentinel task list goes to your clipboard or to a file on your computer, never to Azure. | Your existing portal sign-in. |
| VirusTotal (`www.virustotal.com`) | Only after you switch the VirusTotal module on in Settings, approve Chrome's permission prompt and paste your own API key: the one clicked value (a public IP address, a public hostname, or an MD5, SHA-1 or SHA-256 hash) is sent over HTTPS, without cookies, when you click "Check on VirusTotal" for that value. Internal addresses and internal names are never offered. No file is ever uploaded. | Your own VirusTotal key. VirusTotal's terms apply to what you submit. |
| CIRCL hashlookup (`hashlookup.circl.lu`) | Off by default. Once you switch it on in Settings and approve the permission prompt, a clicked file hash is sent, unkeyed, when you click its row. | No credentials. |
| EPSS (`api.first.org`) | Off by default. Once you switch it on in Settings and approve the permission prompt, a clicked CVE id is sent, unkeyed, when you click its row. | No credentials. |
| A self-hosted MISP or IntelOwl | Off until you switch the module on, type the server's origin in Settings and approve the permission prompt for exactly that origin. A clicked hash, IP address, hostname, URL or CVE id is sent to your instance when you click its row. | The token from your own account on that server, sent only to it. |
| Your self-hosted MISP, on click, writes | Off until you also turn on "Allow writes to MISP" in Settings. Then, and only on a click of its own: "Record sighting" adds a sighting (source "Reach") on the attribute that matched the clicked value; "Propose to MISP", offered for a value you have held that MISP has no record of, adds it as an attribute (to_ids false) to an event you pick from your instance's recent ones, with your Hold reason as its comment. Nothing else from the page, the notebook or the browser is written. | The same token from your own account on that server. |
| Sites a link opens | Some rows and citations are links: MITRE ATT&CK, CISA, GTFOBins, LOLDrivers, LOLRMM, detection.fyi, a GitHub code search for LOLBAS or HijackLibs, VirusTotal's own page, Splunk and Microsoft documentation, the Azure portal. Clicking one opens that site in a new tab with the value in the URL, as any link does. | None from Reach; whatever your browser already holds for that site. |

Every request above goes out one value per click, never for a whole
column or grid and never on a timer. Reach ships no key and no default
server for any of them. Switching a module off removes its host
permission. Reach's use of information received from the pages it runs
on adheres to the Chrome Web Store User Data Policy, including the
Limited Use requirements.

## Permissions and why

- `storage`: keeps the data listed above in `chrome.storage.local`.
- `scripting`: registers Reach's content scripts for one site at a
  time, after you enable it, instead of asking for every site up front.
- `activeTab`: lets the popup read the current tab's address so it can
  name the site you are about to enable.
- `sidePanel`: hosts the catalogue in Chrome's side panel.
- Optional host permission `*://*/*`: Splunk Web and self-hosted
  servers run on addresses only you know. Nothing is granted at
  install; one origin is granted per click, and only that origin. The
  Azure portal is the one pair: "Enable in the Azure portal" asks for
  `portal.azure.com` and the Logs blade's `*.reactblade.portal.azure.net`
  together, in one prompt, and removes both together.
- Optional host permissions for `www.virustotal.com`,
  `hashlookup.circl.lu` and `api.first.org`: requested only when you
  switch that module on, used only for the lookups described above.

## Your controls

Enable and disable Reach per site from the popup; disabling removes
that site's permission, and `chrome://extensions` can revoke any
permission too. Every module except the core ones has a switch in
Settings (the side panel's Settings fold and the options page show the
same list); switching a module off stops it, revokes its host
permission, and removes only a credential or a grant it holds (the
VirusTotal key, the self-hosted origin and token); everything else it
kept stays until you press Clear on that row. "Forget" under VirusTotal
deletes your key; "Forget" under the self-hosted relay deletes the
origin, provider and token and revokes that origin's permission.
"Clear all Reach data"
in Settings deletes everything listed above in one step, except the
History control's two preferences and the last Sentinel workspace seen,
which uninstalling removes, and can also revoke Splunk and Sentinel page
access. The notebook copies an
investigation to your clipboard as Markdown or plain text, imports one
back, and removes an entry or a whole investigation. Your annotations
and runbooks export to a JSON file on your computer and import from one
you pick; nothing is uploaded.

## Retention

We hold no data, so there is nothing for us to retain or delete. On
your device, data stays until you delete it or uninstall Reach, which
removes everything in the extension's own storage. A working value an
earlier version of Reach left in an enabled Splunk or Azure page's own
storage stays until you clear site data for that site. VirusTotal
answers are cached in the background worker's memory for ten minutes,
then dropped.

## Children

Reach is a tool for security analysts. It is not directed at children
and, since it collects nothing, collects nothing from them.

## Changes

A change to this policy changes the version and date at the top. A new
third-party recipient gets a new dated version before the Reach version
that sends to it ships. The current text is at https://elegint.dev/privacy.

## Contact

Questions about this policy or a request about your data: contact@readycheck.ai.

`SECURITY.md` in the repository documents each data flow above with the
file and symbol that enforces it.
