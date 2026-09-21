// popup-ui.js, the parts with no DOM in them.
//
// fieldHash(): the field route's hash for the in-page popups' "Open in
// Reach →" link (meaningBlock). Before this it dropped the clicked value
// and the index, so a tab opened from a value click landed on a bare field
// page instead of the value the click was actually about; the side panel
// got both because the click's whole selection travels there as a message
// (app.js showSelection). This is the tab path's equivalent: value and
// index ride in the URL, and field.js reads them back into
// investigation.js on load.
//
// patternModel(): the pure model behind patternBlock, tested after that.
//
// verdictInput(), verdictModel(): the pure pieces behind verdictBlock, the
// known-good row, tested at the end over the bundled macOS corpus.
//
// valueEntry(): the clicked value's own row, the model valueBlock and the
// value page's valueLine both draw. Precedence: the pack's values table,
// then the decode table the popup already holds, then, on a closed
// dictionary only, that the value misses it; an unknown value on an open
// dictionary (format alone) is null, since a format-only miss carries no
// information. Splunk here; the Sentinel table reads the same entry in
// popup-ui-sentinel.test.js.

import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as catalogue from "../app/lib/catalogue.js";
import * as values from "../app/lib/values.js";
import { readFile } from "node:fs/promises";
import { fieldHash, valueEntry, patternModel, verdictFields, verdictInput, platformBinaryOf, osBuildFor, linuxReleaseOf, macosEntry, verdictModel, verdictBlock, enrichModel, enrichBlock, PATTERN_CSS, POPUP_CSS, VERDICT_CSS, ENRICH_CSS } from "../app/lib/popup-ui.js";
import * as known from "../app/lib/known.js";
import * as enrich from "../app/lib/enrich.js";

await catalogue.load();

test("fieldHash: name only", () => {
  assert.equal(fieldHash("SHA256HashData", {}), "#/f/SHA256HashData");
});

test("fieldHash: sourcetype, value and index all carried", () => {
  const hash = fieldHash("SHA256HashData", { st: "crowdstrike:events:sensor", value: "abc123", index: "fdr_main" });
  assert.equal(hash, "#/f/SHA256HashData?st=crowdstrike%3Aevents%3Asensor&value=abc123&index=fdr_main");
});

test("fieldHash: undefined, null and empty-string params are dropped, not sent as blanks", () => {
  assert.equal(fieldHash("aid", { st: undefined, value: null, index: "" }), "#/f/aid");
});

test("fieldHash: name and values are percent-encoded, a Sentinel value included", () => {
  const hash = fieldHash("Target Process Id", { st: "SecurityEvent", value: "user@contoso.com" });
  assert.equal(hash, "#/f/Target%20Process%20Id?st=SecurityEvent&value=user%40contoso.com");
});

test("fieldHash: round-trips through the app router's own parser", async () => {
  const router = await import("../app/lib/router.js");
  const hash = fieldHash("CommandLine", { st: "ProcessRollup2", value: "powershell.exe -enc AB==", index: "main" });
  const { route, params } = router.parse(hash);
  assert.equal(route, "field");
  assert.equal(params.name, "CommandLine");
  assert.equal(params.st, "ProcessRollup2");
  assert.equal(params.value, "powershell.exe -enc AB==");
  assert.equal(params.index, "main");
});

test("valueEntry: the pack's values table wins, with provenance and cite, and the decode left aside", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const view = { decode: { source: "discovered", lookup: "mine.csv", values: { AwsApiCall: "my own words" } }, dictionary: { format: "One fixed word" } };
  const row = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "AwsApiCall", view });
  assert.equal(row.kind, "entry");
  assert.equal(row.source, "pack");
  assert.equal(row.meaning, "An API was called: the ordinary record, one per request.");
  assert.equal(row.provenance, "documented");
  assert.match(row.cite.title, /^CloudTrail record contents/);
  assert.equal(row.concept, "aws-cloudtrail/event_type");
  assert.equal(row.value, "AwsApiCall");
});

test("valueEntry: a value the pack does not list falls back to the decode table, discovered or bundled", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const discovered = { decode: { source: "discovered", lookup: "mine.csv", values: { Custom: "from my lookup" } } };
  const d = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "Custom", view: discovered });
  assert.equal(d.kind, "entry");
  assert.equal(d.source, "discovered");
  assert.equal(d.meaning, "from my lookup");
  assert.equal(d.provenance, "observed");
  assert.equal(d.lookup, "mine.csv");
  // The FDR bundle's decode tables sit outside the concept model: only the caller's decode reaches them.
  const bundled = catalogue.decodeOn("crowdstrike:events:sensor", "AllocationType");
  assert.equal(bundled.source, "pack");
  assert.equal(catalogue.valueOn("crowdstrike:events:sensor", "AllocationType", "4096"), null);
  const b = valueEntry({ catalogue, container: "crowdstrike:events:sensor", field: "AllocationType", value: 4096, view: { decode: bundled } });
  assert.equal(b.kind, "entry");
  assert.equal(b.source, "decode");
  assert.equal(b.meaning, "MEM_COMMIT");
  assert.equal(b.value, "4096");
  assert.equal(b.provenance, null);
});

test("valueEntry: a closed enumeration's miss is signal; an open field's format alone carries none", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  // eventType is type "enum": the values table is the whole set, so a
  // miss reads as one.
  const view = catalogue.fieldOn("aws:cloudtrail", "eventType");
  assert.equal(view.concept.type, "enum");
  const f = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "NotAType", view });
  assert.equal(f.kind, "closed");
  assert.equal(f.count, view.dictionary.count);
  assert.equal(f.value, "NotAType");
  // invoked_by is not an enum and carries no `closed` marker: its values
  // table is a sample, so a miss says nothing.
  const open = catalogue.fieldOn("aws:cloudtrail", "userIdentity.invokedBy");
  assert.notEqual(open.concept.type, "enum");
  assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "userIdentity.invokedBy", value: "unknown.amazonaws.com", view: open }), null);
  assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "NotAType", view: { decode: null, dictionary: null } }), null);
  assert.equal(valueEntry({ catalogue, container: "no:such", field: "x", value: "y", view: null }), null);
  assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: null, view }), null);
  assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "", value: "AwsApiCall", view }), null);
});

test("valueEntry: a user-supplied value rides as the raw string, is looked up as an own key only, and never reaches Object's prototype", async () => {
  await catalogue.loadValues("aws:cloudtrail");
  const hostile = '<img src=x onerror="alert(1)">';
  const view = { decode: { source: "discovered", lookup: "mine.csv", values: { [hostile]: "a row named by markup" } } };
  const row = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: hostile, view });
  assert.equal(row.value, hostile, "the literal is data: h.js renders it as a text node, so the markup never parses");
  assert.equal(row.meaning, "a row named by markup");
  assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "toString", view: { decode: { source: "pack", values: {} } } }), null, "an inherited key is not a row");
  for (const key of ["__proto__", "constructor", "prototype"]) {
    assert.equal(valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: key, view: { decode: { source: "pack", values: {} } } }), null, key);
  }
});

test("valueEntry: before the sidecar lands the pack's decode table answers; after, the same call reads the richer entry", async () => {
  values._reset();
  assert.equal(catalogue.valuesReady("aws:cloudtrail"), false);
  const early = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "AwsConsoleSignIn", view: catalogue.fieldOn("aws:cloudtrail", "eventType") });
  assert.equal(early.source, "pack");
  assert.equal(early.meaning, "A console sign-in");
  assert.equal(early.provenance, null);
  await catalogue.loadValues("aws:cloudtrail");
  const late = valueEntry({ catalogue, container: "aws:cloudtrail", field: "eventType", value: "AwsConsoleSignIn", view: catalogue.fieldOn("aws:cloudtrail", "eventType") });
  assert.match(late.meaning, /^A sign-in to the AWS Management Console/);
  assert.equal(late.provenance, "documented");
});

// patternModel(): the pure model behind patternBlock. A value cut by its
// shape, a state per segment that a tap cycles keep > any > like > keep,
// the ladder's rungs for those states cheapest first, and the offline
// preview counted over the discovered profile's top values (the fixture
// discovery.profile shape).

const profile = JSON.parse(await readFile(new URL("./fixtures/ladder-profile.json", import.meta.url), "utf8")).fields;

test("patternModel: a Windows path is cut into drive, dirs, basename, ext, every piece kept", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk" });
  assert.equal(m.shape, "path");
  assert.deepEqual(m.segments.map((g) => g.text), ["C:", "Windows", "System32", "cmd", "exe"]);
  assert.deepEqual(m.states(), ["keep", "keep", "keep", "keep", "keep"]);
  assert.equal(m.platform, "spl");
});

test("patternModel: cycle walks keep > any > like > keep and only the tapped piece moves", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk" });
  assert.equal(m.cycle(2), "any");
  assert.equal(m.cycle(2), "like");
  assert.equal(m.cycle(2), "keep");
  assert.equal(m.cycle(2), "any");
  assert.deepEqual(m.states(), ["keep", "keep", "any", "keep", "keep"]);
  assert.equal(m.cycle(9), undefined, "a piece that is not there");
  assert.equal(m.set(1, "sideways"), "keep", "an unknown state is refused and the piece keeps its state");
  m.reset();
  assert.deepEqual(m.states(), ["keep", "keep", "keep", "keep", "keep"]);
});

test("patternModel: mergeRuns groups adjacent same-kind any/like segments into one run; cycleRun moves the whole run, keep un-merges it", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk" });
  assert.deepEqual(m.mergeRuns(), [], "nothing open yet, no merge");
  m.set(1, "any");
  assert.deepEqual(m.mergeRuns(), [], "one open segment alone does not merge");
  m.set(2, "any");
  assert.deepEqual(m.mergeRuns(), [{ start: 1, end: 2, kind: "dir", state: "any" }], "two adjacent open directories merge into one run, its count derived as end - start + 1");
  assert.equal(m.cycleRun(1, 2), "like", "the run cycles keep > any > like > keep together");
  assert.deepEqual(m.states(), ["keep", "like", "like", "keep", "keep"], "both segments moved, not just the tapped one");
  assert.deepEqual(m.mergeRuns(), [{ start: 1, end: 2, kind: "dir", state: "like" }], "still one merged chip, now exactly-N");
  assert.equal(m.cheapest().construct, "regex", "exactly-N reaches the regex rung, never a wildcard");
  assert.equal(m.cycleRun(1, 2), "keep");
  assert.deepEqual(m.states(), ["keep", "keep", "keep", "keep", "keep"]);
  assert.deepEqual(m.mergeRuns(), [], "keep never merges: un-merging restores the individual chips");
});

test("patternModel: only mergeable kinds group; a basename and its extension open next to each other stay two chips", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk" });
  m.set(3, "any");
  m.set(4, "any");
  assert.deepEqual(m.mergeRuns(), [], "basename and ext are adjacent and both any, but not a mergeable kind");
});

test("patternModel: a domain's adjacent open labels merge (any labels), an IP's adjacent open octets merge and the ladder still prefers cidr once exactly-N", () => {
  const d = patternModel({ value: "a.b.c.example.com", field: "host", platform: "splunk", shape: "domain" });
  d.set(0, "any");
  d.set(1, "any");
  d.set(2, "any");
  assert.deepEqual(d.mergeRuns(), [{ start: 0, end: 2, kind: "label", state: "any" }]);

  const ip = patternModel({ value: "10.0.1.2", field: "src_ip", platform: "splunk", shape: "ip" });
  ip.set(2, "any");
  ip.set(3, "any");
  assert.deepEqual(ip.mergeRuns(), [{ start: 2, end: 3, kind: "octet", state: "any" }]);
  assert.equal(ip.cheapest().construct, "trailing_wildcard", "any depth still reads cheapest as a prefix match");
  ip.cycleRun(2, 3);
  assert.deepEqual(ip.states(), ["keep", "keep", "like", "like"]);
  assert.equal(ip.cheapest().construct, "cidr", "exactly-N on an IP run is expressed as a CIDR range, not a depth regex");
});

test("patternModel: the cheapest rung follows the states; all kept is the exact term, a dir opened is a wildcard", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk" });
  assert.equal(m.cheapest().construct, "literal");
  assert.equal(m.cheapest().text, 'Image="C:\\\\Windows\\\\System32\\\\cmd.exe"');
  m.cycle(1);
  m.cycle(2);
  assert.equal(m.cheapest().construct, "wildcard");
  assert.equal(m.cheapest().text, 'Image="C:\\\\*\\\\cmd.exe"');
  assert.equal(m.cheapest().form, "term");
  const costs = m.rungs().map((r) => r.cost);
  assert.deepEqual(costs, [...costs].sort((a, b) => a - b), "cheapest first");
  m.cycle(3);
  m.cycle(3);
  assert.equal(m.cheapest().construct, "regex", "like this on the basename needs a character class");
  assert.equal(m.cheapest().form, "stage");
  assert.match(m.cheapest().why, /character class/);
});

test("patternModel: the preview counts distinct sample values matched and the events behind them, from the fixture profile", () => {
  const m = patternModel({ value: "C:\\Windows\\System32\\cmd.exe", field: "Image", platform: "splunk", samples: profile.Image.profile.top });
  assert.equal(m.sampleValues, 6);
  assert.equal(m.sampleEvents, 86);
  assert.deepEqual(m.preview(m.cheapest()), { values: 1, ofValues: 6, events: 40, ofEvents: 86 });
  assert.equal(m.previewLine(m.cheapest()), "Matches 1 of 6 sample values (40 of 86 events profiled)");
  m.cycle(1);
  m.cycle(2);
  assert.deepEqual(m.preview(m.cheapest()), { values: 2, ofValues: 6, events: 50, ofEvents: 86 }, "C:\\*\\cmd.exe takes System32 and SysWOW64, not D:");
  m.cycle(0);
  assert.equal(m.preview(m.cheapest()).values, 3, "the drive opened too takes D:\\tools\\cmd.exe");
});

test("patternModel: no samples, no preview line; an empty or blank sample is not a value", () => {
  const m = patternModel({ value: "10.0.5.5", field: "src_ip", platform: "splunk" });
  assert.equal(m.previewLine(m.cheapest()), null);
  assert.equal(m.sampleValues, 0);
  const n = patternModel({ value: "10.0.5.5", field: "src_ip", platform: "splunk", samples: [{ value: "", count: 9 }, { value: null }, { value: "10.0.5.5", count: 2 }] });
  assert.equal(n.sampleValues, 1);
  assert.equal(n.previewLine(n.cheapest()), "Matches 1 of 1 sample value (2 of 2 events profiled)");
});

test("patternModel: TERM() only with an indexed or raw-token class", () => {
  const plain = patternModel({ value: "10.0.5.5", field: "src_ip", platform: "splunk" });
  assert.equal(plain.cheapest().construct, "literal");
  const indexed = patternModel({ value: "10.0.5.5", field: "src_ip", platform: "splunk", fieldClass: "raw_token" });
  assert.equal(indexed.cheapest().construct, "term");
  assert.equal(indexed.label(indexed.cheapest()), "TERM()");
});

test("patternModel: Sentinel builds KQL; a leading piece opened falls to endswith, never a leading wildcard", () => {
  const m = patternModel({ value: "jdoe@contoso.com", field: "UserPrincipalName", platform: "sentinel" });
  assert.equal(m.platform, "kql");
  assert.equal(m.cheapest().text, 'UserPrincipalName == "jdoe@contoso.com"');
  m.set(0, "any");
  assert.equal(m.cheapest().text, 'UserPrincipalName endswith "@contoso.com"');
  assert.equal(m.label(m.cheapest()), "endswith / contains");
  for (const r of m.rungs()) assert.ok(!/(^|[\s"(])\*/.test(r.text), r.text);
});

test("patternModel: nothing to cut is null; the rung text quotes the literal, so markup and quotes ride as data", () => {
  assert.equal(patternModel({ value: "", field: "x" }), null);
  assert.equal(patternModel({ value: "  ", field: "x" }), null);
  assert.equal(patternModel({ value: "x" }), null);
  const hostile = '<img src=x onerror="alert(1)">';
  const m = patternModel({ value: hostile, field: "eventType", platform: "splunk" });
  const rung = m.cheapest();
  assert.equal(rung.text, 'eventType="<img src=x onerror=\\"alert(1)\\">"', "spl.quote escapes the inner quotes; h.js renders the pieces as text nodes");
  assert.equal(m.error, null);
});

test("patternModel: a ladder refusal leaves rungs empty and the error readable, never thrown", () => {
  const m = patternModel({ value: "abc", field: "not a field name", platform: "splunk" });
  assert.deepEqual(m.rungs(), []);
  assert.equal(m.cheapest(), null);
  assert.match(String(m.error), /field/i);
});

test("PATTERN_CSS is self-contained on the --rc-* palette and travels inside POPUP_CSS", () => {
  assert.ok(POPUP_CSS.includes(".reach-pattern__chip"));
  assert.ok(PATTERN_CSS.includes(".reach-pattern__chips{display:flex;flex-wrap:wrap"), "chips wrap at panel width");
  assert.ok(!/var\(--(?!rc-)/.test(PATTERN_CSS), "no app token leaks into the popup stylesheet");
});

test("every verdict chip basis a tier can carry has its own coloured rule, not the default yellow", () => {
  // verdictModel's TIER_CHIP maps normal/consistent to green bases and
  // impersonation to "danger"; a basis with no rule here falls back to
  // .reach-chip's default (the same yellow a pending pivot uses), which is
  // how an impersonation verdict used to read as a caution instead of a
  // danger.
  assert.match(POPUP_CSS, /\[data-basis="confirmed"\][^{]*\{[^}]*--rc-ok/);
  assert.match(POPUP_CSS, /\[data-basis="validated"\][^{]*\{[^}]*--rc-ok/);
  assert.match(POPUP_CSS, /\[data-basis="danger"\][^{]*\{[^}]*--rc-err/);
});

test("the popup's width and height stay inside the viewport instead of a fixed 380-560px box", () => {
  assert.ok(!/\.reach-section\{[^}]*min-width:380px/.test(POPUP_CSS), "no fixed min-width wider than the 320px panel");
  assert.match(POPUP_CSS, /\.reach-section\{[^}]*width:min\(560px,\s*calc\(100vw - 32px\)\)/);
  assert.match(POPUP_CSS, /\.reach-section\{[^}]*max-height:70vh/);
  assert.match(POPUP_CSS, /\.reach-section\{[^}]*overflow-y:auto/);
});

// --- the known-good verdict ----------------------------------------------------
// verdictInput() gathers known.js's input off a Falcon row; verdictModel()
// turns the verdict into the one line per tier the row draws. The verdicts
// here are real: known.js over the bundled macOS corpus (app/data/known),
// the contactsd row exactly as the dev pull carries it.

const CONTACTSD = {
  event_platform: "Mac",
  event_simpleName: "ProcessRollup2",
  aid: "c26d2f327b6a49eebc1432e094ee4a84",
  ImageFileName: "/System/Library/Frameworks/Contacts.framework/Support/contactsd",
  SHA256HashData: "077fc5180ed67177cfdcad85cadc028f2466fa21db42ba8265ee2187b02114e9",
  SigningId: "com.apple.contactsd",
  TeamId: "-",
  CodeSigningFlags: "637618689",
  CsValidationCategory: "1",
};

async function modelFor(fields, { field = "SHA256HashData", value = fields[field], osBuild = null } = {}) {
  const ask = verdictInput(fields, { field, value });
  assert.ok(ask, "a verdict input");
  if (osBuild) ask.input.os_build = osBuild;
  const verdict = await known.verdict(ask.input);
  const loaded = verdict.corpus ? await known.loadMacos() : null;
  const entry = macosEntry(loaded, ask.input);
  return { ask, model: verdictModel({ verdict, input: ask.input, entry, buildBasis: osBuild ? "the one build in your crowdstrike:hosts inventory" : null }) };
}

test("verdictFields: only named columns with a value ride along, trimmed and bounded", () => {
  const row = { ...CONTACTSD, CommandLine: "contactsd", TeamId: "  -  ", aid_os_version: "" };
  const got = verdictFields((n) => row[n] ?? null);
  assert.equal(got.CommandLine, undefined, "not a verdict field");
  assert.equal(got.aid_os_version, undefined, "empty is absent");
  assert.equal(got.TeamId, "-");
  assert.equal(got.SigningId, "com.apple.contactsd");
  assert.deepEqual(verdictFields(() => { throw new Error("no row"); }), {});
});

test("verdictInput: the contactsd row reads as an Apple platform binary with no team, on macOS", () => {
  const ask = verdictInput(CONTACTSD, { field: "SHA256HashData", value: CONTACTSD.SHA256HashData });
  assert.equal(ask.platform, "macos");
  assert.equal(ask.clicked, "sha256");
  assert.equal(ask.input.team_id, null, "Falcon's '-' is no team, never a team called '-'");
  assert.equal(ask.input.cs_platform_binary, true, "CS_PLATFORM_BINARY (0x04000000) is set in 637618689");
  assert.equal(ask.input.sign_flags, 637618689);
  assert.equal(ask.input.signing_id, "com.apple.contactsd");
  assert.equal(ask.input.path, CONTACTSD.ImageFileName);
  assert.equal(ask.input.os_build, null, "a process event carries no build");
  // The Falcon sensor's own app: signed, not a platform binary, by a team.
  const falcon = { ...CONTACTSD, SigningId: "com.crowdstrike.falcon.App", TeamId: "X9E956P446", CodeSigningFlags: "570491393" };
  const f = verdictInput(falcon, { field: "SigningId", value: falcon.SigningId });
  assert.equal(f.input.cs_platform_binary, false);
  assert.equal(f.input.team_id, "X9E956P446");
});

test("verdictInput: nothing off a hash, signing id or path; nothing on a Windows or platform-less row", () => {
  assert.equal(verdictInput(CONTACTSD, { field: "CommandLine", value: "contactsd" }), null);
  assert.equal(verdictInput({ ...CONTACTSD, event_platform: "Win" }, { field: "SHA256HashData", value: CONTACTSD.SHA256HashData }), null);
  assert.equal(verdictInput({ SHA256HashData: CONTACTSD.SHA256HashData }, { field: "SHA256HashData", value: CONTACTSD.SHA256HashData }), null, "no platform, no signing facts: not known to be mac");
  // The concept type names the kind when the column does not: a file_hash click that is not a SHA-256 has no row in the corpus.
  assert.equal(verdictInput(CONTACTSD, { field: "MD5HashData", value: "e7264304ace76fb648d999049e350c6e", conceptType: "file_hash" }), null);
  assert.equal(verdictInput(CONTACTSD, { field: "SomePath", value: "/usr/bin/x", conceptType: "file_path" }).clicked, "path");
  // Sentinel spellings and a Linux row.
  assert.equal(verdictInput({ EventPlatform: "Lin", ImageFileName: "/usr/bin/bash" }, { field: "ImageFileName", value: "/usr/bin/bash" }).platform, "linux");
  // The clicked value fills the input when the row's own field is missing.
  const bare = verdictInput({ event_platform: "Mac" }, { field: "SigningId", value: "com.apple.bash" });
  assert.equal(bare.input.signing_id, "com.apple.bash");
  assert.equal(bare.input.cs_platform_binary, null, "the row does not say");
});

test("platformBinaryOf: the bitmask decides, the TA's flag names can only confirm, a flag column reads as a bool", () => {
  assert.equal(platformBinaryOf({ CodeSigningFlags: "637618689" }), true);
  assert.equal(platformBinaryOf({ CodeSigningFlags: "570491393", CodeSigningFlags_meaning: "CS_PLATFORM_BINARY" }), false, "the mask wins over a name");
  assert.equal(platformBinaryOf({ CodeSigningFlags_meaning: "CS_SIGNED" }), null, "one of several names may be all the popup saw");
  assert.equal(platformBinaryOf({ CodeSigningFlags_meaning: "CS_PLATFORM_BINARY" }), true);
  assert.equal(platformBinaryOf({ CS_PLATFORM_BINARY: "false" }), false);
  assert.equal(platformBinaryOf({}), null);
});

test("osBuildFor: the hosts inventory gives the build only when it reports exactly one; else a build-shaped aid_os_version; else null", () => {
  const one = { fieldOn: (st, f) => (st === "crowdstrike:hosts" && f === "os_build" ? { profile: { distinct: 1, top: [{ value: "25G83", count: 3 }] } } : null) };
  assert.deepEqual(osBuildFor({ catalogue: one, fields: CONTACTSD }), { build: "25G83", basis: "the one build in your crowdstrike:hosts inventory" });
  const two = { fieldOn: () => ({ profile: { distinct: 2, top: [{ value: "25G83", count: 3 }, { value: "24F74", count: 1 }] } }) };
  assert.equal(osBuildFor({ catalogue: two, fields: CONTACTSD }), null, "two builds cannot be joined from a profile");
  assert.deepEqual(osBuildFor({ catalogue: two, fields: { ...CONTACTSD, aid_os_version: "25G83" } }), { build: "25G83", basis: "aid_os_version on the event" });
  assert.equal(osBuildFor({ catalogue: null, fields: { aid_os_version: "Tahoe (26)" } }), null, "a version name is not a build");
  assert.equal(osBuildFor({ catalogue: { fieldOn: () => { throw new Error("not loaded"); } }, fields: {} }), null);
});

test("verdict: the demo contactsd event reads normal, naming the Apple platform binary, its path and the builds it was seen on", async () => {
  const { model } = await modelFor(CONTACTSD);
  assert.equal(model.tier, "normal");
  assert.equal(model.chip, "confirmed");
  assert.equal(model.headline, "Apple platform binary (contactsd daemon) at /System/Library/Frameworks/Contacts.framework/Support/contactsd, on macOS builds 25F71, 25G83, 26A5416b");
  assert.equal(model.detail, null, "no build on the event, nothing to say about one");
  assert.equal(model.corpus, "macOS builds 25F71, 25G83, 26A5416b");
  assert.equal(model.hint, null);
  // A click on the signing id or the path reads the same; the hash is not consulted on macOS.
  assert.equal((await modelFor(CONTACTSD, { field: "SigningId" })).model.tier, "normal");
  assert.equal((await modelFor({ ...CONTACTSD, SHA256HashData: "f".repeat(64) }, { field: "ImageFileName" })).model.tier, "normal");
});

test("verdict: normal with the build in hand says where the build came from and whether the corpus enumerated it", async () => {
  const known25 = await modelFor(CONTACTSD, { osBuild: "25G83" });
  assert.equal(known25.model.tier, "normal");
  assert.equal(known25.model.detail, "Build 25G83 from the one build in your crowdstrike:hosts inventory.");
  const other = await modelFor(CONTACTSD, { osBuild: "24G100" });
  assert.equal(other.model.tier, "normal", "a build the corpus lacks is not held against a binary the corpus knows");
  assert.equal(other.model.detail, "Build 24G100 from the one build in your crowdstrike:hosts inventory, not a build the corpus enumerated.");
});

test("verdict: a path with no signing facts on the row is normal on the path alone, and says so", async () => {
  const { model } = await modelFor({ event_platform: "Mac", ImageFileName: CONTACTSD.ImageFileName, SHA256HashData: CONTACTSD.SHA256HashData });
  assert.equal(model.tier, "normal");
  assert.equal(model.headline, "Apple platform binary (contactsd daemon) at /System/Library/Frameworks/Contacts.framework/Support/contactsd, on macOS builds 25F71, 25G83, 26A5416b");
  assert.equal(model.detail, "Matched on the path alone: this event carries no signing id to compare.");
});

test("verdict: a forged com.apple.contactsd (a team id, a path the corpus never saw it at) is impersonation, in red", async () => {
  const forged = { ...CONTACTSD, TeamId: "ABCDE12345", SHA256HashData: "f".repeat(64), ImageFileName: "/Users/me/Downloads/contactsd" };
  const { model } = await modelFor(forged, { field: "SigningId", osBuild: "25G83" });
  assert.equal(model.tier, "impersonation");
  assert.equal(model.chip, "danger");
  assert.match(model.headline, /^Disagrees with the corpus: /);
  assert.match(model.headline, /event reports team id ABCDE12345/);
  assert.match(model.headline, /never saw signing id com\.apple\.contactsd at path \/Users\/me\/Downloads\/contactsd/);
  // Apple's own path claimed under another name.
  const stolen = await modelFor({ ...CONTACTSD, SigningId: "com.evil.contactsd", TeamId: "ABCDE12345" }, { osBuild: "25G83" });
  assert.equal(stolen.model.tier, "impersonation");
  assert.match(stolen.model.headline, /path \/System\/Library\/Frameworks\/Contacts\.framework\/Support\/contactsd belongs to Apple platform binary com\.apple\.contactsd in the corpus, event claims signing id com\.evil\.contactsd/);
  // The path alone, on a binary whose flags say it is not Apple's.
  const unsigned = await modelFor({ event_platform: "Mac", ImageFileName: CONTACTSD.ImageFileName, CodeSigningFlags: "0" }, { field: "ImageFileName" });
  assert.equal(unsigned.model.tier, "impersonation");
});

test("linuxReleaseOf: the Ubuntu, RHEL and Amazon Linux forms name a bundled corpus key; anything else names none", () => {
  assert.deepEqual(linuxReleaseOf("Ubuntu 22.04"), { distro: "ubuntu", release: "22.04" });
  assert.deepEqual(linuxReleaseOf("ubuntu 24.04 LTS"), { distro: "ubuntu", release: "24.04" });
  assert.deepEqual(linuxReleaseOf("RHEL 9.4"), { distro: "rhel", release: "9" }, "the RHEL corpus is per major");
  assert.deepEqual(linuxReleaseOf("Red Hat Enterprise Linux 9"), { distro: "rhel", release: "9" });
  assert.deepEqual(linuxReleaseOf("Amazon Linux 2023"), { distro: "amazonlinux", release: "2023" });
  assert.equal(linuxReleaseOf("Debian 12"), null);
  assert.equal(linuxReleaseOf("25G83"), null, "a Darwin build is not a Linux release");
  assert.equal(linuxReleaseOf(""), null);
  assert.equal(linuxReleaseOf(undefined), null);
});

const CURL = { event_platform: "Lin", event_simpleName: "ProcessRollup2", aid: "0123456789abcdef0123456789abcdef", aid_os_version: "Ubuntu 22.04", ImageFileName: "/usr/bin/curl", SHA256HashData: "b1b4a0805c83790a5854ff58ed222cecebb40ce7f5daeca33878b47089e9c206" };

test("verdictInput: a Linux row's aid_os_version, in either platform's spelling, picks the distro and release; a mac row keeps none", () => {
  const ask = verdictInput(CURL, { field: "SHA256HashData", value: CURL.SHA256HashData });
  assert.equal(ask.platform, "linux");
  assert.equal(ask.input.distro, "ubuntu");
  assert.equal(ask.input.release, "22.04");
  assert.equal(ask.input.os_build, null, "an OS version string is not a Darwin build");
  const sentinel = verdictInput({ EventPlatform: "Lin", AidOsVersion: "RHEL 9.4", ImageFileName: "/usr/bin/curl" }, { field: "ImageFileName", value: "/usr/bin/curl" });
  assert.deepEqual([sentinel.input.distro, sentinel.input.release], ["rhel", "9"]);
  const none = verdictInput({ EventPlatform: "Lin", ImageFileName: "/usr/bin/curl" }, { field: "ImageFileName", value: "/usr/bin/curl" });
  assert.equal(none.input.distro, null, "no version on the row, no corpus to pick");
  const mac = verdictInput({ ...CONTACTSD, aid_os_version: "25G83" }, { field: "SigningId", value: CONTACTSD.SigningId });
  assert.equal(mac.input.distro, null);
  assert.equal(mac.input.os_build, "25G83");
  assert.equal(osBuildFor({ catalogue: null, fields: { AidOsVersion: "25G83" } }).build, "25G83", "the Sentinel spelling carries a build too");
});

test("verdict: a Linux hash the corpus for the row's release holds reads normal, naming the package; the path alone is consistent", async () => {
  const { model } = await modelFor(CURL);
  assert.equal(model.tier, "normal");
  assert.equal(model.corpus, "ubuntu 22.04");
  assert.equal(model.headline, "In the known-good corpus for ubuntu 22.04");
  assert.match(model.detail, /sha256 matches curl at \/usr\/bin\/curl/);
  const pathOnly = await modelFor({ ...CURL, SHA256HashData: undefined }, { field: "ImageFileName", value: CURL.ImageFileName });
  assert.equal(pathOnly.model.tier, "consistent");
  assert.equal(pathOnly.model.headline, "Path known to the ubuntu 22.04 corpus");
  const noRelease = await modelFor({ ...CURL, aid_os_version: "Debian 12" });
  assert.equal(noRelease.model.tier, "unknown");
  assert.equal(noRelease.model.detail, "no distro/release given");
});

test("verdict: unknown says so, why, and what to do next", async () => {
  const { model } = await modelFor({ ...CONTACTSD, SigningId: "com.crowdstrike.falcon.App", TeamId: "X9E956P446", CodeSigningFlags: "570491393", SHA256HashData: "e8182b0d0af9cdeb9d05bfb6205fbbd02949d25112cb7af1a05fa50a5145ffd6", ImageFileName: "/Applications/Falcon.app/Contents/MacOS/Falcon" }, { osBuild: "25G83" });
  assert.equal(model.tier, "unknown");
  assert.equal(model.chip, "pack");
  assert.equal(model.headline, "Not in any known-good corpus");
  assert.equal(model.detail, "signing id com.crowdstrike.falcon.App not in the corpus, nor path /Applications/Falcon.app/Contents/MacOS/Falcon");
  assert.match(model.hint, /VirusTotal/);
  const noHash = await modelFor({ event_platform: "Mac", SigningId: "com.example.tool" }, { field: "SigningId", value: "com.example.tool" });
  assert.match(noHash.model.hint, /SHA256HashData/);
  const hashOnly = await modelFor({ event_platform: "Mac", SHA256HashData: CONTACTSD.SHA256HashData, CodeSigningFlags: "637618689" });
  assert.equal(hashOnly.model.tier, "unknown", "a hash alone says nothing on macOS");
  assert.match(hashOnly.model.detail, /not hashes/);
});

test("VERDICT_CSS colours the normal and consistent tiers green and impersonation red", () => {
  assert.match(VERDICT_CSS, /\.reach-verdict\[data-tier="normal"\][^{]*\{[^}]*--rc-ok/);
  assert.match(VERDICT_CSS, /\.reach-verdict\[data-tier="consistent"\][^{]*\{[^}]*--rc-ok/);
  assert.match(VERDICT_CSS, /\.reach-verdict\[data-tier="impersonation"\]\{[^}]*--rc-err/);
  assert.ok(!VERDICT_CSS.includes('data-tier="exact"'), "no exact tier remains");
});

test("VERDICT_CSS wraps the hash and the path, stays on the --rc-* palette and travels inside POPUP_CSS", () => {
  assert.ok(POPUP_CSS.includes(".reach-verdict__line"));
  assert.ok(VERDICT_CSS.includes("overflow-wrap:anywhere"));
  assert.ok(!/var\(--(?!rc-)/.test(VERDICT_CSS), "no app token leaks into the popup stylesheet");
});

test("ENRICH_CSS stays on the --rc-* palette and travels inside POPUP_CSS", () => {
  assert.ok(POPUP_CSS.includes(".reach-enrich__body"));
  assert.ok(!/var\(--(?!rc-)/.test(ENRICH_CSS), "no app token leaks into the popup stylesheet");
});

// enrichModel(): the pure decision behind enrichBlock (app/lib/enrich.js
// offers a { source, kind, id, allowed, why } row per registered source;
// this is what says whether that row draws inline, as a live button, or as
// a gated/refused explanation, per mode).

function offer(source, { allowed = true, why } = {}) {
  return { source, kind: source.kinds[0], id: "x", allowed, why };
}

test("enrichModel: a bundle source (KEV) is always allowed, no gate involved", () => {
  const kev = { id: "kev", label: "CISA KEV", kinds: ["cve"], mode: "bundle" };
  assert.deepEqual(enrichModel([offer(kev)]), [{ id: "kev", label: "CISA KEV", mode: "bundle", allowed: true, why: null }]);
});

test("enrichModel: a deeplink source is always allowed", () => {
  const link = { id: "tria.ge", label: "triage", kinds: ["hash"], mode: "deeplink" };
  assert.deepEqual(enrichModel([offer(link)]), [{ id: "tria.ge", label: "triage", mode: "deeplink", allowed: true, why: null }]);
});

test("enrichModel: a fetch source enabled in Settings renders as a live row", () => {
  const vt = { id: "virustotal", label: "VirusTotal", kinds: ["ip"], mode: "fetch" };
  assert.deepEqual(enrichModel([offer(vt, { allowed: true })]), [{ id: "virustotal", label: "VirusTotal", mode: "fetch", allowed: true, why: null }]);
});

test("enrichModel: a fetch source not configured in Settings is gated, with the gate's why", () => {
  const vt = { id: "virustotal", label: "VirusTotal", kinds: ["ip"], mode: "fetch" };
  const why = "VirusTotal is not configured. Set it up in Reach's settings before anything is sent to it.";
  assert.deepEqual(enrichModel([offer(vt, { allowed: false, why })]), [{ id: "virustotal", label: "VirusTotal", mode: "fetch", allowed: false, why }]);
});

test("enrichModel: a shaped-but-refused value (private IP) is not-allowed with its own reason, same shape as a Settings gate", () => {
  const vt = { id: "virustotal", label: "VirusTotal", kinds: ["ip"], mode: "fetch" };
  const why = "Not sent: a private address: inside your network, not something VirusTotal has seen.";
  assert.deepEqual(enrichModel([offer(vt, { allowed: false, why })]), [{ id: "virustotal", label: "VirusTotal", mode: "fetch", allowed: false, why }]);
});

test("enrichModel: several offers keep their own mode and order", () => {
  const kev = { id: "kev", label: "CISA KEV", kinds: ["cve"], mode: "bundle" };
  const stream = { id: "stream-src", label: "Stream Co", kinds: ["cve"], mode: "stream" };
  const rows = enrichModel([offer(kev), offer(stream, { allowed: false, why: "Stream Co is off." })]);
  assert.deepEqual(rows.map((r) => r.mode), ["bundle", "stream"]);
  assert.equal(rows[1].allowed, false);
});

test("enrichModel: an empty offers list is an empty model", () => {
  assert.deepEqual(enrichModel([]), []);
  assert.deepEqual(enrichModel(undefined), []);
});

// ---------------------------------------------------------------------------
// The Hold action (pinFrom, hold, heldPin, recordPivot): the pin carries
// its whole provenance, a scope key is never held, the app's held store
// is written through onHeld, a pivot from a held value is one edge
// however often it is taken, and one from a value not held is nothing.

const notebook = await import("../app/lib/notebook.js");
const investigation = await import("../app/lib/investigation.js");
const { pinFrom, hold, heldPin, recordPivot, eventSummary } = await import("../app/lib/popup-ui.js");

const CLICK = {
  field: "sourceIPAddress",
  value: " 203.0.113.9 ",
  container: "aws:cloudtrail",
  platform: "splunk",
  scope: "main",
  event: { id: "12:345", time: "2026-09-18T14:03:11Z", summary: "aws:cloudtrail · ConsoleLogin event at 9/18/26 2:03:11 PM" },
  search: { text: "index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin", sid: "1758204120.123" },
};

test("pinFrom: value, field, platform, container, scope, event and search all ride on the pin, trimmed, the event time parsed", () => {
  const pin = pinFrom({ ...CLICK, reason: "on the alert" });
  assert.deepEqual(pin, {
    field: "sourceIPAddress",
    value: "203.0.113.9",
    from: {
      platform: "splunk",
      column: "sourceIPAddress",
      container: "aws:cloudtrail",
      scope: "main",
      event: { id: "12:345", time: Date.UTC(2026, 8, 18, 14, 3, 11), summary: "aws:cloudtrail · ConsoleLogin event at 9/18/26 2:03:11 PM" },
      search: { text: "index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin", sid: "1758204120.123" },
    },
    reason: "on the alert",
  });
  assert.doesNotThrow(() => notebook.checkPin(pin));
});

test("pinFrom: a Sentinel click keeps its platform, an unparseable time is left out, an absent search is absent", () => {
  const pin = pinFrom({ field: "UserPrincipalName", value: "bob@corp.example", container: "SigninLogs", platform: "sentinel", scope: "soc-prod", event: { time: "not a time", summary: "SigninLogs event" }, search: null });
  assert.equal(pin.from.platform, "sentinel");
  assert.deepEqual(pin.from.event, { summary: "SigninLogs event" });
  assert.equal(pin.from.search, undefined);
  assert.equal(pin.reason, undefined);
});

test("pinFrom: the index and the workspace are scope, never a pin; an empty value or field is nothing", () => {
  assert.equal(pinFrom({ field: "index", value: "main", platform: "splunk" }), null);
  assert.equal(pinFrom({ field: "Workspace", value: "soc", platform: "sentinel" }), null);
  assert.equal(pinFrom({ field: "user", value: "  ", platform: "splunk" }), null);
  assert.equal(pinFrom({ field: "", value: "x", platform: "splunk" }), null);
});

test("eventSummary: the container and record type, then the row's time", () => {
  assert.equal(eventSummary({ container: "aws:cloudtrail", discriminator: "ConsoleLogin", time: "9/18/26 2:03 PM" }), "aws:cloudtrail · ConsoleLogin event at 9/18/26 2:03 PM");
  assert.equal(eventSummary({ container: "SigninLogs" }), "SigninLogs event");
  assert.equal(eventSummary({}), "");
});

test("hold: records the pin in the current investigation, reads the search on the click, and writes the held store through onHeld", async () => {
  await notebook.load({ force: true });
  let asked = 0;
  const search = async () => {
    asked += 1;
    return CLICK.search;
  };
  const { pin, entry } = await hold({ ...CLICK, search, reason: "on the alert", onHeld: (p) => investigation.set(p.field, p.value) });
  assert.equal(asked, 1);
  assert.equal(entry.kind, "pin");
  assert.equal(entry.from.search.sid, "1758204120.123");
  assert.equal(entry.reason, "on the alert");
  assert.equal(investigation.get("sourceIPAddress"), "203.0.113.9", "the value pivots bind, in this tab");
  const inv = notebook.current();
  assert.ok(inv, "the first hold started the implicit investigation");
  assert.equal(inv.entries[0].id, entry.id);
  assert.equal(inv.trigger, "sourceIPAddress = 203.0.113.9 on aws:cloudtrail");
  assert.equal(heldPin({ field: "SourceIPAddress", value: "203.0.113.9", container: "aws:cloudtrail" }).id, entry.id, "found by field and value, case aside");
  assert.equal(heldPin({ field: "sourceIPAddress", value: "198.51.100.1" }), null);
  assert.equal(pin.from.column, "sourceIPAddress");
});

test("hold: a scope key rejects before anything is written", async () => {
  const before = notebook.current().entries.length;
  await assert.rejects(hold({ field: "index", value: "main", platform: "splunk" }), /scope/);
  assert.equal(notebook.current().entries.length, before);
});

test("recordPivot: an edge from the held pin, one entry however often the same search is taken; nothing from a value not held", async () => {
  const q = 'index=main sourcetype=aws:cloudtrail sourceIPAddress="203.0.113.9" | stats count by eventName';
  const first = await recordPivot({ field: "sourceIPAddress", value: "203.0.113.9", container: "aws:cloudtrail", platform: "splunk", query: q, name: "what this reaches" });
  assert.equal(first.kind, "pivot");
  assert.equal(first.origin, heldPin({ field: "sourceIPAddress", value: "203.0.113.9" }).id);
  assert.deepEqual(first.query, { text: q, language: "SPL" });
  assert.equal(first.name, "what this reaches");
  const again = await recordPivot({ field: "sourceIPAddress", value: "203.0.113.9", container: "aws:cloudtrail", platform: "splunk", query: q, name: "what this reaches" });
  assert.equal(again.id, first.id);
  const none = await recordPivot({ field: "user", value: "nobody", container: "aws:cloudtrail", platform: "splunk", query: "index=main user=nobody" });
  assert.equal(none, null);
  assert.equal(notebook.current().entries.filter((e) => e.kind === "pivot").length, 1);
  assert.match(notebook.exportText(), /From sourceIPAddress = 203\.0\.113\.9, pivoted to what this reaches with index=main/);
});

// Both verdictBlock (the known-good corpus check) and a bundle-mode
// enrichment source (LOLDrivers, on a hash) fetch and render on their own,
// no click needed. Neither may turn that into a notebook write: only an
// explicit Hold or Attach click records a pin. h() only needs
// createElement/createTextNode and something children can be instanceof;
// nothing built here is ever clicked.
class FakeNode {}
function fakeElement(tag) {
  return Object.assign(new FakeNode(), {
    tagName: String(tag).toUpperCase(),
    className: "",
    dataset: {},
    style: {},
    hidden: false,
    children: [],
    setAttribute() {},
    addEventListener() {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    append(...items) {
      for (const item of items) this.appendChild(item);
    },
    replaceChildren(...items) {
      this.children = [];
      for (const item of items) this.appendChild(item);
    },
  });
}

test("viewing a popup writes no pin: verdictBlock and a bundle enrichment source both auto-fetch without recording a hold", async () => {
  const savedDocument = globalThis.document;
  const savedNode = globalThis.Node;
  globalThis.Node = FakeNode;
  globalThis.document = {
    createElement: fakeElement,
    createTextNode: (text) => Object.assign(new FakeNode(), { textContent: String(text) }),
  };
  try {
    await notebook.load({ force: true });
    const value = CONTACTSD.SHA256HashData;
    const field = "SHA256HashData";
    const container = "crowdstrike:events:sensor";
    assert.equal(heldPin({ field, value, container }), null, "not held before the popup renders");
    const pinsBefore = notebook.list().reduce((n, inv) => n + inv.entries.filter((e) => e.kind === "pin").length, 0);
    const holdCtx = { field, value, container, platform: "splunk", scope: "main", event: { summary: `${container} · ProcessRollup2 event` } };
    const offers = enrich.offersFor(value, { fieldName: field, enabledIds: [] });
    enrichBlock({ value, offers, ask: async () => null, settingsUrl: "options.html#virustotal", hold: holdCtx });
    verdictBlock({ field, value, container, platform: "splunk", event: CONTACTSD, catalogue: null, view: null, hold: holdCtx });
    // Give the verdict's corpus lookup and LOLDrivers' bundle fetch a turn
    // to resolve and redraw in place.
    await new Promise((resolve) => setTimeout(resolve, 50));
    const pinsAfter = notebook.list().reduce((n, inv) => n + inv.entries.filter((e) => e.kind === "pin").length, 0);
    assert.equal(pinsAfter, pinsBefore, "opening the popup records no pin");
    assert.equal(heldPin({ field, value, container }), null, "still not held; only an explicit Hold or Attach click may record one");
  } finally {
    globalThis.document = savedDocument;
    globalThis.Node = savedNode;
  }
});
