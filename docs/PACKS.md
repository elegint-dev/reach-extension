# Packs: the data dictionary

The pack format itself (version 2: a feed described once by concept,
with bindings per platform) is documented at the top of `app/lib/packs.js`,
and the concept model in `docs/NEXT-concept-model.md`. This page covers the
layer on top of a concept: what its values look like, what each one means,
where that was read, and how sure the pack is. The model is the AWS CLI
reference: the sourcetype page is the index (one line per field, grouped
by role, with the source's reference document), and the field page is the
operation page (description, format, values with a line each, examples,
gotchas, the citation).

## 1. Keys

Per concept, beside `label`, `description`, `decode` and the rest:

| key | type | meaning |
| --- | --- | --- |
| `format` | string | the synopsis, in words: "One fixed word, case-sensitive; AwsApiCall on most records." |
| `shape` | string | a `shapes.js` shape the values take (`arn`, `ip`, `guid`, ...). Accepted only when an example shows it: every example must satisfy `shapeOf(example.value).shape === shape`, so the vocabulary is the detectors, not a second list. |
| `examples` | `[{ value, note? }]` | real values with a word on when they appear |
| `values` | `{ literal: entry }` | the table; an entry is `{ meaning, cite?, provenance?, quote?, note? }` or a bare meaning string |
| `provenance` | `documented`, `observed`, `inferred` | the default for every value in the table |
| `cite` | `{ url, title, read_on }` | the document the entry was read from; `read_on` is `YYYY-MM-DD` |
| `quote` | string | at most twenty of the vendor's own words, only beside a cite |
| `closed` | boolean | the `values` table is the whole set, not a sample; default `false` (a list is examples unless the sidecar says otherwise) |

A clicked value's own line under Meaning reads a dictionary as closed, and
names a miss ("not one of N documented values"), when `closed` is `true`
or the concept's taxonomy type is `enum`; a `bitmask` concept never counts
here, since an unmatched literal there is an unseen flag combination, not
a rejected one. Anything else with only a `format` is open: no value line,
the format stays on the field entry alone (`bands/value.js dictionaryClosed`).

Per binding: `provenance: { kind, statement?, cite? }` with `kind` one of
`indexed`, `extracted`, `alias`, `calculated`, `lookup`, `connector`. It says
how the column comes to carry the concept on that platform: a TA field
alias (`FIELDALIAS eventType AS app`), a lookup output, a connector column
the platform's reference lists.

`decode.values` (a lookup's literal to meaning table) stays as it is. A
concept with a decode and no `values` entry gets the decode normalised into
the same shape (`source: "decode"`, no provenance claimed), so the field
page draws one table either way and nothing that read decodes changes.

A concept of type `bitmask` carries `decode.flags` beside `decode.values`:
`{ "0x<8 hex>": "<name>" }`, exactly one bit set per key. A clicked value
that is an exact `values` key reads `<name> (0x<hex>)`; otherwise the set
flags read ascending by mask joined by ` | `, with bits no flag covers
appended as ` +0x<hex>`; a value that sets no known flag reads no decode.
The rule lives once, in `values.decodeBitmask`, and `valueOn` applies it,
so the popup's value band, the field page and the value page agree; the
field page's title block, with one line to give, draws the value's own name
and the flag count (`PROCESS_ALL_ACCESS · 19 flags`) with the flag names
folded closed under it, and its chip reads `19 flags`. The
Falcon pack's `desired_access` (the nineteen Windows process access rights,
`2097151` reading `PROCESS_ALL_ACCESS (0x1FFFFF)`) is the shipped example;
the loader refuses `flags` on a concept whose type is not `bitmask`.

## 2. Rules the loader holds

`app/lib/values.js` validates every entry, inline in a pack (`packs.validate`
calls it) or in a sidecar (`validateDocument`):

- unknown keys are refused, at every level (an entry, a value, a cite, a
  binding provenance, the sidecar document), as are `__proto__` and its kin;
- `provenance: documented` needs a cite, on the value or inherited from the
  concept; a value may claim less than its concept (`inferred` under a
  documented concept) but a documented claim is never uncited;
- a `quote` needs a cite and is at most `QUOTE_MAX_WORDS` (20) words;
- a `shape` needs an example, and every example must be that shape;
- a sidecar entry must name a concept of its pack, and a sidecar binding
  provenance must name a binding the pack has;
- a cite given as a key must name a row of the sidecar's `cites` table.

## 3. Where the entries live

The bundled dictionaries are sidecars, one per pack:
`app/packs/<pack id>.values.json`, listed in `app/packs/index.json` under
`values` with the pack id, file, byte size and the containers it serves.
The pack loader (`packs.load`) does not read them: `values.loadFor(container)`
fetches the sidecars of every pack bound on that container the first time a
page needs them (the field and sourcetype pages call `catalogue.loadValues`
and redraw the block in place), so the eager pack load does not grow with
the dictionary. Each sidecar stays under `values.BUDGET_BYTES` (40 KB); the
converter refuses a larger one and `tests/values.test.js` checks the index
entry against the file.

```
{ "format": "reach-pack-values", "version": 1, "pack": "aws-cloudtrail",
  "licence": { "name", "url"?, "holder"?, "note"? },
  "cite": { url, title, read_on },              the feed's reference document (shown on the sourcetype page)
  "cites": { "<key>": { url, title, read_on } },  a table the entries cite by key
  "concepts": { "<concept id>": { format, shape, examples, values, provenance, cite, quote } },
  "bindings": [ { platform, container, column, provenance: { kind, statement, cite } } ] }
```

Inside a sidecar any `cite` (an entry's, a value's, a binding provenance's)
may be a string naming a row of `cites`; `values.resolveCites` puts the
objects back when the document is registered, so pages and `valueOn` only
ever see cite objects. The table is what keeps a full dictionary under the
budget: the CloudTrail one cites fifteen pages from 85 entries and would
carry 15 KB of repeated cite objects without it. The sidecar is written as
compact JSON for the same reason; the overlay stays indented.

A pack may also carry the same keys inline on its concepts (a small pack,
a test fixture). `values.dictionary(packId, conceptId)` reads the sidecar's
entry, else the inline one, else the decode.

Authoring: the sidecar is generated, never hand-edited. Write the overlay in
`tools/dev/pack-dict/<pack id>.json` (the sidecar's format, with cite
objects written out in full) and run `python3 tools/dev/convert-pack-v2.py`,
which checks it against the pack, tabulates the cites and writes both the
pack and the sidecar. An overlay concept the pack does not have fails the
run.

Research in batches lands through `tools/dev/pack-dict-merge.py <pack>
--allow allow.json [--pages dir] fragment.json ...`: each fragment is
`{ fetched: [url], concepts: { id: entry } }`, and an entry lands only when
its concept is in the pack, its cite url is in the allowlist and in the
fragment's own fetched list, a documented claim has a cite and an observed
or inferred one has none, a quote is at most twenty words and (with cached
page text) appears verbatim on the cited page, and no long dash or curly
quote appears anywhere. The tool prints what landed and what was rejected,
per fragment and per rule; the overlay's existing entries are never
overwritten.

## 3a. The fields sidecar

A pack whose feed comes with a vendor add-on's full field catalogue (the
CrowdStrike FDR add-on: 1,792 fields over 275 record types on five
sourcetypes, with a nine-edge join graph) keeps that catalogue in a second
sidecar, `app/packs/<pack id>.fields.json`, listed in `index.json` under
`fields` with the pack id, file, byte size and the containers it
describes. `app/lib/pack-fields.js` validates and holds it:

```
{ "format": "reach-pack-fields", "version": 1, "pack": "crowdstrike-falcon",
  "source": { "ta_version", "built_at" },
  "counts": { ... },                            the build's counts (docs/SPEC.md 10.1)
  "fields": { "<name>": FieldRecord },           layer, role, meaning, decode, events, route, ...
  "records": { "<event name>": EventRecord },    the record types, each on one container
  "edges": [ Edge ] }                            the join graph, in ledger order
```

The pack loader does not read it. The app's boot fetches the sidecars
describing a container this platform knows (`catalogue.loadFields()`,
`pack-fields.loadBound`); a popup fetches the ones describing the
container it was clicked in (`catalogue.loadFields(container)`,
`pack-fields.loadFor`). On a platform where none of a sidecar's containers
exist nothing is fetched: Sentinel never reads the Falcon catalogue unless
a Falcon table is declared or bound there. A field record's route
paragraph is composed on registration from its route class and its own
data (`reachability.routeExplain`); the shipped file carries one only
where the composer cannot make it. The sidecar is written compact by
`tools/dev/fdr-bundle-to-pack.mjs` from a reach-fdr build and stays under
`pack-fields.BUDGET_BYTES` (3 MB); `tests/pack-fields.test.js` checks the
index entry against the file.

## 4. The paraphrase and cite standard

- Own words, one or two sentences per value or concept. Vendor text is
  quoted only in `quote`, at most twenty words, and only beside a cite.
- Every documented item cites `{ url, title, read_on }`; `read_on` is the
  day the page was actually read, not a guess.
- `observed` is what the data showed; `inferred` is worked out from
  neither. Both are shown as such on the page, and neither needs a cite.
- The vendor's documentation licence is noted once per pack in `licence`.
  AWS documentation (the awsdocs repositories) is CC BY-SA 4.0: paraphrase
  plus attribution, which is what the entries do.

## 5. What the pages read

`catalogue.fieldOn` carries `dictionary` (the normalised entry, once the
sidecar is loaded; a decode-backed one from the start) and
`binding.provenance`. `catalogue.valueOn(sourcetype, field, value)` answers
for one value: the pack's table first, then the decode table discovery read
from the user's own lookup (`source: "discovered"`), else null; a known
values corpus (`source: "known"`) is the next layer and is not here yet.
`app/components/dictionary.js` draws the field page's block (format, the
values fold, examples, gotchas from the concept's hazards, the quote, the
provenance chip and reference, the binding's provenance line) and the
sourcetype page's reference line. `values.oneLiner(description)` is the
index page's one line per field: the first sentence, cut before a list.
