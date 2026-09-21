// The known-benign set (app/lib/benign.js): one entry per (field, value,
// container), expiry, the exclusion forms on both platforms as golden
// strings, quoting, the fold through the ladder and the leading wildcard
// it never emits, the size bounds, export and import, and the notebook
// attach that never throws. Runs on store.js's memory backend.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

const store = await import("../app/lib/store.js");
const benign = await import("../app/lib/benign.js");
const notebook = await import("../app/lib/notebook.js");
const spl = await import("../app/lib/spl.js");
const kql = await import("../app/lib/kql.js");
assert.equal(store.backend(), "memory");

const R = String.raw;
const T = Date.UTC(2026, 8, 18, 14, 0, 0);
const min = (n) => T + n * 60_000;
const from = (over = {}) => ({ platform: "splunk", container: "crowdstrike:events:sensor", column: "ImageFileName", scope: "main", event: { id: "ev-1", time: min(-1) }, search: { text: "index=main sourcetype=crowdstrike:events:sensor", sid: "1758204120.1" }, ...over });
const SVCHOST = R`C:\Windows\System32\svchost.exe`;
const LSASS = R`C:\Windows\System32\lsass.exe`;

function lintClean(ex) {
  if (ex.platform === "splunk") {
    const v = spl.lint(`search index=main ${ex.text}`, { commands: ["regex", "rex"] });
    assert.ok(v.ok, `${ex.form}: ${v.violations.join("; ")}: ${ex.text}`);
  } else {
    const v = kql.lint(ex.place === "stage" ? `Table ${ex.text}` : `Table | where ${ex.text}`);
    assert.ok(v.ok, `${ex.form}: ${v.violations.join("; ")}: ${ex.text}`);
  }
}

beforeEach(async () => {
  await store.remove(benign.KEY);
  await benign.load({ force: true });
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

// ---- store ----------------------------------------------------------------

test("marking the same value on the same field and container again keeps one entry with its id", async () => {
  const a = await benign.add({ value: SVCHOST, field: "ImageFileName", container: "crowdstrike:events:sensor", platform: "splunk", reason: "fleet standard", from: from() });
  const b = await benign.add({ value: SVCHOST, field: "ImageFileName", container: "crowdstrike:events:sensor", platform: "splunk", reason: "signed by Microsoft" });
  assert.equal(b.id, a.id);
  assert.equal(b.reason, "signed by Microsoft");
  assert.equal(b.added_at, a.added_at);
  assert.deepEqual(b.from, a.from, "provenance kept when the second mark carries none");
  assert.equal(benign.list().length, 1);
  await benign.add({ value: SVCHOST, field: "ImageFileName", container: "Falcon_CL", platform: "sentinel" });
  await benign.add({ value: SVCHOST, field: "ParentImageFileName", container: "crowdstrike:events:sensor" });
  assert.equal(benign.list().length, 3, "another container or field is another entry");
  assert.equal(benign.list({ container: "crowdstrike:events:sensor", field: "ImageFileName" }).length, 1);
});

test("an entry needs a value and a field; the raw document is under reach.benign", async () => {
  await assert.rejects(() => benign.add({ field: "x", container: "c" }), /needs a value/);
  await assert.rejects(() => benign.add({ value: "v", container: "c" }), /needs a value/);
  const e = await benign.add({ value: "v", field: " f ", container: " c " });
  assert.equal(e.field, "f");
  assert.equal(e.container, "c");
  const raw = await store.get(benign.KEY);
  assert.equal(raw.v, benign.VERSION);
  assert.equal(raw.entries[0].id, e.id);
});

test("list is newest first; remove works by id and by key; subscribe reports each change", async () => {
  const seen = [];
  const off = benign.subscribe((ev) => seen.push(ev.type));
  const a = await benign.add({ value: "a", field: "f", container: "c", reason: "r" });
  const b = await benign.add({ value: "b", field: "f", container: "c" });
  assert.deepEqual(benign.list().map((e) => e.value), ["b", "a"]);
  assert.equal((await benign.remove(a.id)).value, "a");
  assert.equal((await benign.remove({ field: "f", value: "b", container: "c" })).id, b.id);
  assert.equal(await benign.remove("nope"), null);
  assert.deepEqual(benign.list(), []);
  assert.deepEqual(seen, ["change", "change", "change", "change"]);
  off();
});

test("purge clears a container, a field, or everything", async () => {
  await benign.add({ value: "a", field: "f", container: "c1" });
  await benign.add({ value: "b", field: "g", container: "c1" });
  await benign.add({ value: "c", field: "f", container: "c2" });
  assert.equal(await benign.purge({ container: "c1", field: "f" }), 1);
  assert.equal(await benign.purge({ container: "c1" }), 1);
  assert.equal(await benign.purge(), 1);
  assert.deepEqual(benign.list(), []);
});

// ---- expiry ---------------------------------------------------------------

test("an entry past expires_at is out of list and of the exclusion, and expire() removes it", async () => {
  await benign.add({ value: "temp", field: "f", container: "c", expires_at: min(10) });
  await benign.add({ value: "keep", field: "f", container: "c" });
  assert.deepEqual(benign.list({ now: min(5) }).map((e) => e.value).sort(), ["keep", "temp"]);
  assert.deepEqual(benign.list({ now: min(10) }).map((e) => e.value), ["keep"]);
  assert.equal(benign.list({ now: min(10), includeExpired: true }).length, 2);
  assert.equal(benign.exclusion("f", "c", "splunk", { now: min(10) }).text, 'NOT f="keep"');
  assert.equal(benign.exclusion("f", "c", "splunk", { now: min(5) }).count, 2);
  const gone = await benign.expire({ now: min(10) });
  assert.deepEqual(gone.map((e) => e.value), ["temp"]);
  assert.equal(benign.list({ includeExpired: true }).length, 1);
  assert.equal(benign.exclusion("g", "c", "splunk"), null, "nothing marked on that field: nothing to offer");
});

test("marking a lapsed value again clears its expiry; expires_at null clears it explicitly", async () => {
  const a = await benign.add({ value: "v", field: "f", container: "c", expires_at: 1 });
  assert.equal(a.expires_at, 1);
  const b = await benign.add({ value: "v", field: "f", container: "c" });
  assert.equal(b.expires_at, undefined);
  await benign.add({ value: "v", field: "f", container: "c", expires_at: min(99) });
  assert.equal(benign.get(a.id).expires_at, min(99));
  await benign.add({ value: "v", field: "f", container: "c", expires_at: null });
  assert.equal(benign.get(a.id).expires_at, undefined);
});

// ---- exclusion forms --------------------------------------------------------

test("one value: NOT field=\"v\" on Splunk, not(field == \"v\") on Sentinel, with the null note in why", () => {
  const s = benign.exclusion("process", "c", "splunk", { values: ["svchost.exe"] });
  assert.equal(s.text, 'NOT process="svchost.exe"');
  assert.equal(s.form, "not");
  assert.equal(s.place, "term");
  assert.equal(s.count, 1);
  assert.equal(s.exact, true);
  assert.match(s.why, /NOT keeps events that lack the field, where field!= would drop them/);
  assert.deepEqual(s.apply, { text: s.text, form: "term", field: "process", mode: "append", platform: "splunk", trace: { origin: "exclusion", container: s.container } });
  lintClean(s);
  const k = benign.exclusion("process", "c", "sentinel", { values: ["svchost.exe"] });
  assert.equal(k.text, 'not(process == "svchost.exe")');
  assert.equal(k.form, "not");
  assert.match(k.why, /string column is never null/);
  assert.equal(k.apply.platform, "sentinel");
  lintClean(k);
});

test("a small set: NOT field IN (...) and not(field in (...)), each value quoted", () => {
  const values = ["svchost.exe", 'say "hi"', R`c:\temp`];
  const s = benign.exclusion("process", "c", "splunk", { values });
  assert.equal(s.text, R`NOT process IN ("svchost.exe", "say \"hi\"", "c:\\temp")`);
  assert.equal(s.form, "not_in");
  assert.equal(s.count, 3);
  lintClean(s);
  const k = benign.exclusion("process", "c", "sentinel", { values });
  assert.equal(k.text, R`not(process in ("svchost.exe", "say \"hi\"", "c:\\temp"))`);
  assert.equal(k.form, "not_in");
  lintClean(k);
  assert.ok(!/!=/.test(s.text) && !/!=/.test(k.text), "never != : it would drop events without the field");
});

test("Windows paths compare case-insensitively on Sentinel (in~, =~); a dynamic path is tostring()ed", () => {
  assert.equal(benign.exclusion("ImageFileName", "c", "sentinel", { values: [SVCHOST, LSASS] }).text, R`not(ImageFileName in~ ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\lsass.exe"))`);
  assert.equal(benign.exclusion("ImageFileName", "c", "sentinel", { values: [SVCHOST] }).text, R`not(ImageFileName =~ "C:\\Windows\\System32\\svchost.exe")`);
  assert.equal(benign.exclusion("ImageFileName", "c", "sentinel", { values: [SVCHOST], ci: false }).text, R`not(ImageFileName == "C:\\Windows\\System32\\svchost.exe")`);
  assert.equal(benign.exclusion("Props.path", "c", "sentinel", { values: ["/usr/bin/a"] }).text, 'not(tostring(Props.path) == "/usr/bin/a")');
  assert.equal(benign.exclusion("userIdentity.arn", "c", "splunk", { values: ["arn:aws:iam::123456789012:user/a"] }).text, 'NOT userIdentity.arn="arn:aws:iam::123456789012:user/a"');
});

test("a Splunk value holding * moves the set to a where stage that keeps null fields and compares whole strings", () => {
  const s = benign.exclusion("cmd", "c", "splunk", { values: ["a*b", "plain"] });
  assert.equal(s.text, '| where isnull(cmd) OR NOT in(cmd, "a*b", "plain")');
  assert.equal(s.form, "where");
  assert.equal(s.place, "stage");
  assert.equal(s.apply.form, "stage");
  assert.match(s.why, /reads as a wildcard/);
  assert.ok(s.caveats.some((c) => /case-sensitive/.test(c)));
  lintClean(s);
  assert.equal(benign.exclusion("user.name", "c", "splunk", { values: ["a*"] }).text, `| where isnull('user.name') OR NOT in('user.name', "a*")`);
  const k = benign.exclusion("cmd", "c", "sentinel", { values: ["a*b", "plain"] });
  assert.equal(k.text, 'not(cmd in ("a*b", "plain"))', "KQL in compares literally: no special form");
  lintClean(k);
});

test("past the threshold with no shared pattern: one negated term per value", () => {
  const s = benign.exclusion("f", "c", "splunk", { values: ["a", "b", "c"], threshold: 2 });
  assert.equal(s.text, 'NOT f="a" NOT f="b" NOT f="c"');
  assert.equal(s.form, "chain");
  assert.match(s.why, /past the 2-value bound/);
  lintClean(s);
  const k = benign.exclusion("f", "c", "sentinel", { values: ["a", "b", "c"], threshold: 2 });
  assert.equal(k.text, 'not(f == "a") and not(f == "b") and not(f == "c")');
  assert.equal(k.form, "chain");
  lintClean(k);
  assert.equal(benign.exclusion("f", "c", "splunk", { values: ["a", "b"], threshold: 2 }).form, "not_in", "the threshold is inclusive");
  assert.equal(benign.THRESHOLD, 50);
  const many = Array.from({ length: 51 }, (_, i) => `v${i}`);
  assert.equal(benign.exclusion("f", "c", "splunk", { values: many }).form, "chain");
  assert.equal(benign.exclusion("f", "c", "splunk", { values: many.slice(0, 50) }).form, "not_in");
});

test("values that share a directory fold to one wildcard through the ladder, wider and said so", () => {
  const s = benign.exclusion("ImageFileName", "c", "splunk", { values: [SVCHOST, LSASS], fold: true });
  assert.equal(s.text, R`NOT ImageFileName="C:\\Windows\\System32\\*.exe"`);
  assert.equal(s.form, "wildcard");
  assert.equal(s.exact, false);
  assert.match(s.why, /2 values fold to one pattern, 1 piece opened/);
  assert.ok(s.caveats.some((c) => /wider than the 2 marked values/.test(c)));
  assert.equal(s.alternative.form, "not_in");
  assert.equal(s.alternative.alternative, undefined);
  lintClean(s);
  const k = benign.exclusion("ImageFileName", "c", "sentinel", { values: [SVCHOST, LSASS], fold: true });
  assert.equal(k.text, R`not(ImageFileName startswith "C:\\Windows\\System32\\" and ImageFileName endswith ".exe" and strlen(ImageFileName) >= 24)`);
  assert.equal(k.form, "wildcard");
  lintClean(k);
  const users = benign.exclusion("ImageFileName", "c", "splunk", { values: [R`C:\Users\bob\AppData\x.exe`, R`C:\Users\alice\AppData\x.exe`], fold: true });
  assert.equal(users.text, R`NOT ImageFileName="C:\\Users\\*\\AppData\\x.exe"`);
  const arn = benign.exclusion("userIdentity.arn", "c", "sentinel", { values: ["arn:aws:iam::123456789012:user/a", "arn:aws:iam::123456789012:user/b"], fold: true });
  assert.equal(arn.text, 'tostring(userIdentity.arn) !startswith "arn:aws:iam::123456789012:user/"', "a single startswith takes its native negation");
});

test("fold auto: the literal form wins under the threshold with the fold as the alternative, the fold wins past it", () => {
  const under = benign.exclusion("ImageFileName", "c", "splunk", { values: [SVCHOST, LSASS] });
  assert.equal(under.form, "not_in");
  assert.equal(under.alternative.form, "wildcard");
  assert.equal(under.alternative.text, R`NOT ImageFileName="C:\\Windows\\System32\\*.exe"`);
  const over = benign.exclusion("ImageFileName", "c", "splunk", { values: [SVCHOST, LSASS], threshold: 1 });
  assert.equal(over.form, "wildcard");
  assert.equal(over.alternative.form, "chain");
  const never = benign.exclusion("ImageFileName", "c", "splunk", { values: [SVCHOST, LSASS], fold: false });
  assert.equal(never.form, "not_in");
  assert.equal(never.alternative, undefined);
});

test("a leading wildcard is never emitted: values that differ at the start stay literal", () => {
  for (const platform of ["splunk", "sentinel"]) {
    for (const values of [["cdn1.example.com", "cdn2.example.com"], ["a1.exe", "b2.exe"], [R`C:\a\x.exe`, R`D:\a\x.exe`], ["alpha", "alphabet"]]) {
      const ex = benign.exclusion("f", "c", platform, { values, fold: true });
      assert.equal(ex.form, "not_in", `${platform} ${values.join(" ")}: ${ex.text}`);
      assert.equal(ex.alternative, undefined);
      assert.ok(!/["(]\*/.test(ex.text), ex.text);
    }
  }
});

test("with samples, a fold that would also catch an unmarked value is withheld", () => {
  const values = [SVCHOST, LSASS];
  const clean = [{ value: SVCHOST, count: 90 }, { value: LSASS, count: 9 }, { value: R`C:\Temp\evil.exe`, count: 1 }];
  const folded = benign.exclusion("ImageFileName", "c", "splunk", { values, fold: true, samples: clean });
  assert.equal(folded.form, "wildcard");
  assert.ok(folded.caveats.some((c) => /no other sampled value matches it/.test(c)));
  const stray = [...clean, { value: R`C:\Windows\System32\dropper.exe`, count: 1 }];
  const held = benign.exclusion("ImageFileName", "c", "splunk", { values, fold: true, samples: stray });
  assert.equal(held.form, "not_in");
  assert.equal(held.alternative, undefined);
});

test("the exclusion reads the live set for the field on the container; platform picks the language only", async () => {
  await benign.add({ value: SVCHOST, field: "ImageFileName", container: "crowdstrike:events:sensor", platform: "splunk", from: from() });
  await benign.add({ value: LSASS, field: "ImageFileName", container: "crowdstrike:events:sensor", platform: "splunk" });
  await benign.add({ value: "other.exe", field: "ImageFileName", container: "Falcon_CL", platform: "sentinel" });
  const s = benign.exclusion("ImageFileName", "crowdstrike:events:sensor", "splunk");
  assert.equal(s.count, 2);
  assert.deepEqual(s.values, [LSASS, SVCHOST]);
  assert.equal(s.container, "crowdstrike:events:sensor");
  const k = benign.exclusion("ImageFileName", "crowdstrike:events:sensor", "kql");
  assert.equal(k.platform, "sentinel");
  assert.equal(k.count, 2);
  assert.equal(benign.exclusion("ImageFileName", "Falcon_CL", "sentinel").text, 'not(ImageFileName == "other.exe")');
  assert.equal(benign.exclusion("ImageFileName", "nothing", "splunk"), null);
  assert.throws(() => benign.exclusion("ImageFileName", "c", "elastic", { values: ["a"] }), /platform must be splunk or sentinel/);
  assert.throws(() => benign.exclusion("bad field", "c", "splunk", { values: ["a"] }), /bad_field|field/);
});

test("every form lints clean on both platforms", () => {
  const sets = [["one"], ["a", "b"], [SVCHOST, LSASS], ["a*b"], Array.from({ length: 5 }, (_, i) => `v${i}`), ['q"uote', R`back\slash`, "new\nline"]];
  for (const platform of ["splunk", "sentinel"]) {
    for (const values of sets) {
      for (const fold of [true, false]) {
        const ex = benign.exclusion("f", "c", platform, { values, fold, threshold: 3 });
        lintClean(ex);
        if (ex.alternative) lintClean(ex.alternative);
      }
    }
  }
});

// ---- size bound -------------------------------------------------------------

test("past MAX_BYTES the oldest entries are pruned first and the newest is kept", async () => {
  const big = "x".repeat(benign.MAX_VALUE);
  const n = Math.ceil(benign.MAX_BYTES / benign.MAX_VALUE) + 2;
  const seen = [];
  const off = benign.subscribe((ev) => ev.type === "pruned" && seen.push(ev));
  let last = null;
  for (let i = 0; i < n; i++) last = await benign.add({ value: `${i}:${big}`, field: "f", container: "c" });
  off();
  assert.ok(benign.bytes() <= benign.MAX_BYTES);
  assert.ok(seen.length >= 1);
  assert.match(seen[0].warning, /over its 500 KB bound/);
  const values = benign.list().map((e) => e.value.split(":")[0]);
  assert.ok(values.includes(String(n - 1)), "the newest entry survives");
  assert.ok(!values.includes("0"), "the oldest went first");
  assert.equal(benign.get(last.id).value.slice(0, 4), `${n - 1}:${big}`.slice(0, 4));
  const value = "y".repeat(benign.MAX_VALUE + 10);
  const e = await benign.add({ value, field: "f", container: "c" });
  assert.equal(e.value.length, benign.MAX_VALUE, "a value is cut at MAX_VALUE");
});

// ---- export and import --------------------------------------------------------

test("export and import round-trip; a newer copy of an entry wins on merge; replace drops the rest", async () => {
  const a = await benign.add({ value: "a", field: "f", container: "c", reason: "one", from: from() });
  await benign.add({ value: "b", field: "f", container: "c", expires_at: Date.now() + 60_000 });
  const text = benign.exportJSON();
  const doc = JSON.parse(text);
  assert.equal(doc.v, benign.VERSION);
  assert.equal(doc.entries.length, 2);
  await benign.purge();
  assert.deepEqual(await benign.importJSON(text), { added: 2, updated: 0, kept: 0 });
  assert.equal(benign.get(a.id).reason, "one");
  assert.deepEqual(benign.get(a.id).from, a.from);
  assert.deepEqual(await benign.importJSON(text), { added: 0, updated: 0, kept: 2 });
  const newer = { entries: [{ ...doc.entries.find((e) => e.value === "a"), reason: "two", added_at: a.added_at + 1 }] };
  assert.deepEqual(await benign.importJSON(newer), { added: 0, updated: 1, kept: 0 });
  assert.equal(benign.get(a.id).reason, "two");
  assert.deepEqual(await benign.importJSON([{ value: "z", field: "f", container: "c" }], { replace: true }), { added: 1, updated: 0, kept: 0 });
  assert.deepEqual(benign.list().map((e) => e.value), ["z"]);
  await assert.rejects(() => benign.importJSON("not json"), /Not a JSON document/);
  assert.deepEqual(await benign.importJSON({ entries: [{ id: "__proto__", value: "p", field: "f" }, { value: "", field: "f" }, 7] }), { added: 0, updated: 0, kept: 0 });
});

// ---- notebook ---------------------------------------------------------------

test("attach records a benign entry in the current investigation with the mark's provenance", async () => {
  const pin = await notebook.record({ field: "ImageFileName", value: SVCHOST, from: from() });
  const e = await benign.add({ value: SVCHOST, field: "ImageFileName", container: "crowdstrike:events:sensor", platform: "splunk", reason: "fleet standard", from: from() });
  const res = await benign.attach(e.id, { on: pin.id });
  assert.equal(res.ok, true);
  assert.equal(res.entry.kind, "benign");
  assert.equal(res.entry.on, pin.id);
  assert.equal(res.entry.reason, "fleet standard");
  assert.equal(res.entry.value, SVCHOST);
  assert.equal(res.entry.from.container, "crowdstrike:events:sensor");
  assert.equal(res.entry.from.column, "ImageFileName");
  const inv = notebook.current();
  assert.equal(inv.entries.filter((x) => x.kind === "benign").length, 1);
  assert.match(notebook.exportMarkdown(), /known benign/);
  const bare = await benign.attach({ value: "x.exe", field: "ImageFileName", container: "Falcon_CL", platform: "sentinel" }, { on: "e_not_there" });
  assert.equal(bare.ok, true);
  assert.equal(bare.entry.on, undefined, "an on that is not in the investigation is dropped, not thrown");
  assert.deepEqual(bare.entry.from, { platform: "sentinel", container: "Falcon_CL", column: "ImageFileName" });
});

test("attach never throws: an unknown id, a bad entry, or a notebook that cannot load come back as ok false", async () => {
  assert.deepEqual(await benign.attach("b_missing"), { ok: false, reason: "No known-benign entry b_missing." });
  assert.equal((await benign.attach({ field: "f" })).ok, false);
  const broken = { add: async () => { throw new Error("storage refused"); }, load: async () => {}, current: () => null, get: () => null };
  const res = await benign.attach({ value: "v", field: "f", container: "c" }, { notebook: broken });
  assert.deepEqual(res, { ok: false, reason: "storage refused" });
  const none = await benign.attach({ value: "v", field: "f", container: "c" }, { notebook: {} });
  assert.equal(none.ok, false);
  assert.match(none.reason, /not available/);
});
