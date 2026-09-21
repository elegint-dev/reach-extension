// The investigation notebook (app/lib/notebook.js, app/lib/notebook-md.js):
// a pin needs provenance, the first record starts the implicit current
// investigation, rename / close / reopen, the thread level, the Markdown
// export against a golden file and its round trip through import, the
// plain-text variant, pruning past the size bound with a warning, unsafe
// keys on import, the event API, and the memory and localStorage backends
// of store.js. The chrome.storage backend is tests/notebook-chrome.test.js
// (its fake must be installed before store.js loads, so it has its own
// process).
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const store = await import("../app/lib/store.js");
const notebook = await import("../app/lib/notebook.js");
const md = await import("../app/lib/notebook-md.js");
assert.equal(store.backend(), "memory");

const T = Date.UTC(2026, 8, 18, 14, 0, 0); // 2026-09-18 14:00:00 UTC
const min = (n) => T + n * 60_000;

const splunk = (over = {}) => ({ platform: "splunk", container: "aws:cloudtrail", scope: "main", event: { id: "ev-1", time: min(-1) + 55_000 }, search: { text: 'index=main sourcetype=aws:cloudtrail eventName=ConsoleLogin', sid: "1758204120.123" }, ...over });
const sentinel = (over = {}) => ({ platform: "sentinel", container: "SigninLogs", scope: "soc-prod", event: { id: "row-7", time: min(11) }, search: { text: "SigninLogs | where UserPrincipalName == 'bob@corp.example'" }, ...over });

// A fixed investigation: every kind, both platforms, two days, a parked
// thread and a pin nobody followed up. ids and times are fixed so the
// export is the same on every run.
function fixture() {
  return {
    id: "inv_fixture",
    title: "ConsoleLogin from a new ASN",
    created: min(0),
    updated: min(60 * 24 + 5),
    trigger: "Alert: AWS console login from an ASN not seen in 90 days",
    status: "open",
    from: { platform: "splunk", container: "aws:cloudtrail", scope: "main" },
    entries: [
      { id: "e1", kind: "pin", at: min(2), field: "userIdentity.arn", value: "arn:aws:iam::123456789012:user/bob", from: splunk({ column: "userIdentity.arn" }), reason: "the principal on the alert" },
      { id: "e2", kind: "pin", at: min(3), field: "sourceIPAddress", value: "203.0.113.9", from: splunk({ column: "sourceIPAddress" }) },
      { id: "e3", kind: "enrichment", at: min(4), on: "e2", source: "VirusTotal", summary: "0 of 94 engines flag it; AS64496 (Example Hosting), first seen 2026-09-01", result: { malicious: 0, harmless: 94, asn: 64496 } },
      { id: "e4", kind: "pivot", at: min(6), origin: "e1", target: "e5", query: { text: 'index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/bob" | stats count by eventName', language: "SPL" }, name: "aws:cloudtrail", found: "14 events, 3 event names", from: splunk({ column: "eventName", event: null }) },
      { id: "e5", kind: "pin", at: min(6), field: "eventName", value: "CreateAccessKey", from: splunk({ column: "eventName", event: { id: "ev-9", time: min(5) }, search: { text: 'index=main sourcetype=aws:cloudtrail userIdentity.arn="arn:aws:iam::123456789012:user/bob"' } }), reason: "a new key minted four minutes after the login" },
      { id: "e6", kind: "note", at: min(8), on: "e5", finding: true, text: "The access key was created from the same IP as the console login, then used from a different one." },
      { id: "e7", kind: "parked", at: min(9), field: "userAgent", value: "aws-cli/2.15.0", from: splunk({ column: "userAgent", event: null, search: null }), why: "worth checking whether this CLI version is in the fleet; not on the path to the key" },
      { id: "e8", kind: "pin", at: min(12), field: "UserPrincipalName", value: "bob@corp.example", from: sentinel({ column: "UserPrincipalName" }), reason: "the same person on the Entra side" },
      { id: "e9", kind: "pivot", at: min(14), origin: "e8", query: { text: "SigninLogs | where UserPrincipalName == 'bob@corp.example' | summarize count() by IPAddress, bin(TimeGenerated, 1h)", language: "KQL" }, name: "SigninLogs", found: "2 IPs" },
      { id: "e10", kind: "verdict", at: min(15), on: "e2", verdict: "not a known scanner or VPN exit", source: "known corpus" },
      { id: "e11", kind: "note", at: min(60 * 24 + 5), text: "Handed to IR; key disabled at 14:40 the day before.", finding: true },
      { id: "e12", kind: "pin", at: min(60 * 24 + 6), field: "accessKeyId", value: "AKIAIOSFODNN7EXAMPLE", from: splunk({ column: "accessKeyId", event: { id: "ev-12", time: min(60 * 24 + 4) }, search: { text: 'index=main sourcetype=aws:cloudtrail eventName=CreateAccessKey' } }) },
      { id: "e13", kind: "benign", at: min(60 * 24 + 7), on: "e7", reason: "aws-cli/2.15.0 is the fleet standard" },
    ],
  };
}

const GOLDEN = fileURLToPath(new URL("./fixtures/notebook-export.md", import.meta.url));

beforeEach(async () => {
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

test("stamp() carries seconds, the same shared format the provenance line and the benign row read", () => {
  assert.equal(md.stamp(T), "2026-09-18 14:00:00 UTC");
});

test("a pin needs provenance: value, field and platform; the container may be unknown", async () => {
  await assert.rejects(notebook.record({ value: "bob" }), /missing field, from/);
  await assert.rejects(notebook.record({ field: "user", value: "bob", from: { container: "aws:cloudtrail" } }), /missing from\.platform/);
  await assert.rejects(notebook.record({ field: "user", from: splunk() }), /missing value/);
  assert.throws(() => notebook.checkPin(null), /needs a value/);
  const e = await notebook.record({ field: "user", value: "bob", from: { platform: "splunk", search: { text: "index=main bob" } } });
  assert.equal(e.kind, "pin");
  assert.equal(e.from.column, "user", "the column is filled from the field");
  assert.equal(typeof e.from.at, "number");
  assert.equal(e.from.search.text, "index=main bob");
  const fromColumn = await notebook.record({ value: "x", from: { platform: "sentinel", container: "SigninLogs", column: "IPAddress" } });
  assert.equal(fromColumn.field, "IPAddress", "the field is filled from the column");
});

test("the first record starts the implicit current investigation; close leaves nothing current; reopen brings it back", async () => {
  assert.equal(notebook.current(), null);
  const e = await notebook.record({ field: "user", value: "bob", from: splunk() });
  const inv = notebook.current();
  assert.ok(inv, "started on first record");
  assert.equal(inv.title, null);
  assert.equal(inv.trigger, "user = bob on aws:cloudtrail");
  assert.deepEqual(inv.from, { platform: "splunk", container: "aws:cloudtrail", scope: "main" });
  assert.deepEqual(inv.entries.map((x) => x.id), [e.id]);
  assert.match(md.displayTitle(inv), /^Untitled investigation \(\d{4}-\d{2}-\d{2}\)$/);

  await notebook.rename(inv.id, "  Bob's console login  ");
  assert.equal(notebook.get(inv.id).title, "Bob's console login");
  await notebook.setTrigger(inv.id, "Alert 42");
  assert.equal(notebook.get(inv.id).trigger, "Alert 42");

  await notebook.close(inv.id);
  assert.equal(notebook.currentId(), null);
  assert.equal(notebook.get(inv.id).status, "closed");
  assert.equal(typeof notebook.get(inv.id).closed, "number");
  assert.deepEqual(notebook.list({ status: "closed" }).map((x) => x.id), [inv.id]);

  await notebook.record({ field: "host", value: "h1", from: splunk() });
  const next = notebook.current();
  assert.notEqual(next.id, inv.id, "a record after close starts a new investigation");
  assert.equal(notebook.list().length, 2);

  await notebook.reopen(inv.id);
  assert.equal(notebook.currentId(), inv.id);
  assert.equal(notebook.get(inv.id).status, "open");
  assert.equal(notebook.get(inv.id).closed, undefined);

  await notebook.setCurrent(next.id);
  assert.equal(notebook.currentId(), next.id);
  await notebook.remove(next.id);
  assert.equal(notebook.currentId(), null);
  assert.equal(notebook.get(next.id), null);
  await assert.rejects(notebook.rename("nope", "x"), /No investigation nope/);
});

test("start() names an investigation up front; record() can target one by id", async () => {
  const a = await notebook.start({ title: "A", trigger: "ticket 1" });
  const b = await notebook.start({ title: "B" });
  assert.equal(notebook.currentId(), b.id);
  await notebook.record({ field: "user", value: "bob", from: splunk() }, { investigation: a.id });
  assert.equal(notebook.get(a.id).entries.length, 1);
  assert.equal(notebook.get(b.id).entries.length, 0);
  assert.equal(notebook.get(a.id).trigger, "ticket 1", "an explicit trigger is not overwritten by the first pin");
});

test("entries: every kind, links between them, thread() walks the connections", async () => {
  const p1 = await notebook.record({ field: "user", value: "bob", from: splunk() });
  const p2 = await notebook.record({ field: "ip", value: "203.0.113.9", from: splunk() });
  const p3 = await notebook.record({ field: "eventName", value: "CreateAccessKey", from: splunk() });
  const pv = await notebook.pivot({ origin: p1.id, target: p3.id, query: { text: "index=main user=bob | stats count by eventName", language: "SPL" }, found: 14 });
  const n = await notebook.note("new key after login", { on: p3.id, finding: true });
  const en = await notebook.enrich({ on: p2.id, source: "VirusTotal", summary: "clean", result: { malicious: 0 } });
  const pk = await notebook.park({ field: "userAgent", value: "aws-cli/2.15.0", why: "later", from: splunk() });
  const v = await notebook.add({ kind: "verdict", on: p2.id, verdict: "not a scanner", source: "known corpus" });
  const b = await notebook.add({ kind: "benign", on: pk.id, reason: "fleet standard" });
  await assert.rejects(notebook.add({ kind: "glance", value: "x" }), /Not an entry kind/);
  await assert.rejects(notebook.note("dangling", { on: "nope" }), /Entry nope is not in/);

  const inv = notebook.current();
  assert.deepEqual(inv.entries.map((e) => e.kind), ["pin", "pin", "pin", "pivot", "note", "enrichment", "parked", "verdict", "benign"]);
  assert.equal(pv.found, 14);
  assert.deepEqual(en.result, { malicious: 0 });
  assert.equal(pk.state, "parked");

  assert.deepEqual(notebook.thread(p1.id).map((e) => e.id), [p1.id, p3.id, pv.id, n.id], "bob's thread: the pivot, what it surfaced, the note on it");
  assert.deepEqual(notebook.thread(p2.id).map((e) => e.id), [p2.id, en.id, v.id]);
  assert.deepEqual(notebook.thread(pk.id).map((e) => e.id), [pk.id, b.id]);
  assert.deepEqual(notebook.thread("nope"), []);

  await notebook.link(p2.id, p1.id, "same session");
  assert.deepEqual(notebook.thread(p2.id).map((e) => e.id), [p1.id, p2.id, p3.id, pv.id, n.id, en.id, v.id]);
  await notebook.link(p2.id, p1.id, "same session");
  assert.equal(notebook.get(inv.id).entries.find((e) => e.id === p2.id).links.length, 1, "a link is not doubled");

  await notebook.resume(pk.id);
  assert.equal(notebook.get(inv.id).entries.find((e) => e.id === pk.id).state, "resumed");
  await notebook.update(n.id, { text: "new key four minutes after login" });
  assert.equal(notebook.get(inv.id).entries.find((e) => e.id === n.id).text, "new key four minutes after login");
  await assert.rejects(notebook.update(p1.id, { value: "" }), /missing value/, "a pin cannot lose its provenance");

  await notebook.removeEntry(p3.id);
  const after = notebook.get(inv.id).entries;
  assert.ok(!after.some((e) => e.id === p3.id));
  assert.equal(after.find((e) => e.id === pv.id).target, undefined, "references to a removed entry are dropped");
  assert.equal(after.find((e) => e.id === n.id).on, undefined);
  assert.deepEqual(notebook.thread(p1.id).map((e) => e.id), [p1.id, p2.id, pv.id, en.id, v.id]);
});

test("model round trip: exportJSON → importDoc keeps every entry, under a fresh id when the id is taken", async () => {
  const p1 = await notebook.record({ field: "user", value: "bob", from: splunk(), reason: "on the alert" });
  await notebook.pivot({ origin: p1.id, query: { text: "index=main user=bob", language: "SPL" }, found: "3 events" });
  await notebook.note("looks fine", { on: p1.id });
  await notebook.rename(notebook.currentId(), "Round trip");
  const inv = notebook.current();
  const doc = notebook.exportJSON();
  assert.equal(doc.kind, "reach-notebook");
  assert.equal(doc.v, 1);

  const back = await notebook.importDoc(JSON.parse(JSON.stringify(doc)));
  assert.notEqual(back.id, inv.id, "the id was taken");
  assert.deepEqual({ ...back, id: inv.id }, inv);
  assert.equal(notebook.list().length, 2);
  assert.equal(notebook.currentId(), inv.id, "an import is not made current unless asked");

  await notebook.remove(inv.id);
  const again = await notebook.importDoc(JSON.stringify(doc), { makeCurrent: true });
  assert.equal(again.id, inv.id, "a free id is kept");
  assert.equal(notebook.currentId(), inv.id);
  assert.deepEqual(notebook.get(inv.id), inv);
});

test("Markdown export matches the golden file", async () => {
  const inv = await notebook.importDoc({ kind: "reach-notebook", v: 1, investigation: fixture() });
  const text = notebook.exportMarkdown(inv.id);
  if (process.env.UPDATE_GOLDEN) writeFileSync(GOLDEN, text);
  assert.equal(text, readFileSync(GOLDEN, "utf8"));
  assert.ok(!text.includes(String.fromCharCode(8212)), "plain punctuation only");
});

test("an investigation with no entries exports one line, no empty section headers", async () => {
  const inv = await notebook.start({ title: "test", trigger: "idk" });
  const mdText = notebook.exportMarkdown(inv.id);
  assert.match(mdText, /Nothing held yet\. Hold a value from a popup to start the timeline\./);
  assert.ok(!/## Timeline|## Findings|## Open threads|## Appendix/.test(mdText), "no empty section headers");
  const txt = notebook.exportText(inv.id);
  assert.match(txt, /Nothing held yet\. Hold a value from a popup to start the timeline\./);
  assert.ok(!/TIMELINE|FINDINGS|OPEN THREADS|VALUES/.test(txt), "no empty section headers");
});

test("Markdown export → importDoc is a lossless round trip; plain Markdown without the machine copy is refused", async () => {
  const inv = await notebook.importDoc({ kind: "reach-notebook", v: 1, investigation: fixture() });
  const text = notebook.exportMarkdown(inv.id);
  await notebook.remove(inv.id);
  const back = await notebook.importDoc(text);
  const canonical = md.sanitize(fixture()); // the fixture's null event and search keys are dropped on the way in
  assert.equal(canonical.entries.length, 13);
  assert.deepEqual(back, canonical);
  await assert.rejects(notebook.importDoc("# Just a heading\n\nSome prose.\n"), /No machine copy/);
  await assert.rejects(notebook.importDoc("```json reach-notebook\n{}"), /cut off/);
  await assert.rejects(notebook.importDoc({ kind: "reach-notebook", v: 2, investigation: fixture() }), /version 2/);
  await assert.rejects(notebook.importDoc({ hello: "world" }), /Not a Reach notebook/);
  await assert.rejects(notebook.importDoc({ kind: "reach-notebook", v: 1, investigation: { entries: [] } }), /needs an id/);
  const bare = await notebook.importDoc({ id: "bare", entries: [{ id: "x", kind: "note", text: "hi" }] });
  assert.equal(bare.entries.length, 1, "a bare investigation object imports too");
});

test("the thread level exports one thread; the text variant carries no Markdown syntax", async () => {
  const inv = await notebook.importDoc({ kind: "reach-notebook", v: 1, investigation: fixture() });
  const thread = notebook.exportMarkdown(inv.id, { thread: "e8" });
  assert.match(thread, /bob@corp\.example/);
  assert.ok(!thread.includes("CreateAccessKey"), "the AWS thread is not in the Entra thread");
  const back = await notebook.importDoc(thread);
  assert.deepEqual(back.entries.map((e) => e.id), ["e8", "e9"]);

  const text = notebook.exportText(inv.id);
  assert.ok(!/^#|`|^\|/m.test(text), "no headings, code spans or table rows (the pipe inside an SPL query is the query's)");
  assert.ok(!text.includes("reach-notebook"), "no machine copy in a notes box");
  assert.match(text, /^CONSOLELOGIN FROM A NEW ASN\n/);
  assert.match(text, /\n14:02  Pinned userIdentity\.arn = arn:aws:iam::123456789012:user\/bob on aws:cloudtrail \(index main, Splunk\) from event ev-1 at 13:59:55 in search index=main/);
  assert.match(text, /OPEN THREADS\n\n- userAgent = aws-cli\/2\.15\.0: worth checking[^\n]*\n- accessKeyId = AKIAIOSFODNN7EXAMPLE on aws:cloudtrail \(index main, Splunk\), not followed up/);
  assert.match(text, /14:07  Marked userAgent = aws-cli\/2\.15\.0 known benign\. Reason: aws-cli\/2\.15\.0 is the fleet standard\./);
  const one = notebook.exportText(inv.id, { thread: "e2" });
  assert.match(one, /VirusTotal on sourceIPAddress = 203\.0\.113\.9/);
  assert.ok(!one.includes("bob@corp"));
});

test("import: unsafe keys are dropped, oversized fields are cut, unknown kinds are skipped", async () => {
  const doc = {
    kind: "reach-notebook",
    v: 1,
    investigation: {
      id: "safe",
      title: "x".repeat(600),
      entries: [
        { id: "__proto__", kind: "note", text: "nope" },
        { id: "ok", kind: "note", text: "yes", on: "constructor", links: [{ to: "__proto__", rel: "r" }, { to: "ok2", rel: "prototype" }], polluted: true },
        { id: "ok2", kind: "glance", value: "unknown kind" },
        { id: "ok3", kind: "pin", field: "f", value: "v", from: { platform: "splunk", event: { id: "e", summary: "s".repeat(5000), raw: "dropped" }, search: { text: "t".repeat(9000), extra: 1 } } },
      ],
    },
  };
  const inv = await notebook.importDoc(doc);
  assert.deepEqual(inv.entries.map((e) => e.id), ["ok", "ok3"]);
  assert.equal(inv.title.length, 500);
  assert.equal(inv.entries[0].polluted, undefined);
  assert.deepEqual(inv.entries[0].links, [{ to: "ok2", rel: "prototype" }]);
  assert.equal(inv.entries[1].from.event.summary.length, 2000);
  assert.equal(inv.entries[1].from.event.raw, undefined);
  assert.equal(inv.entries[1].from.search.text.length, 4000);
  assert.equal(inv.entries[1].from.search.extra, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  await assert.rejects(notebook.importDoc({ id: "__proto__", entries: [] }), /needs an id/);
  const stored = await store.get(notebook.KEY);
  assert.equal(Object.keys(stored.investigations[0].entries[0]).includes("polluted"), false);
});

test("a damaged stored document loads as an empty notebook; a stray investigation is dropped", async () => {
  await store.set(notebook.KEY, { v: 1, current: "ghost", investigations: [{ id: "a", entries: [] }, "junk", { id: "a", entries: [{ id: "dup" }] }, { title: "no id" }] });
  const doc = await notebook.load({ force: true });
  assert.deepEqual(doc.investigations.map((i) => i.id), ["a"]);
  assert.equal(doc.current, null, "a current id that names nothing is cleared");
  await store.set(notebook.KEY, "not an object");
  assert.deepEqual(await notebook.load({ force: true }), { v: 1, current: null, investigations: [] });
});

test("subscribe: a change event per write, unsubscribe stops them", async () => {
  const events = [];
  const off = notebook.subscribe((ev) => events.push(ev.type));
  await notebook.record({ field: "user", value: "bob", from: splunk() });
  await notebook.rename(notebook.currentId(), "T");
  assert.deepEqual(events, ["change", "change"]);
  off();
  await notebook.note("x");
  assert.deepEqual(events, ["change", "change"]);
});

test("writes are serialised: concurrent records all land", async () => {
  const pins = await Promise.all([1, 2, 3, 4, 5].map((i) => notebook.record({ field: "n", value: String(i), from: splunk() })));
  assert.equal(new Set(pins.map((p) => p.id)).size, 5);
  assert.deepEqual(notebook.current().entries.map((e) => e.value), ["1", "2", "3", "4", "5"]);
  assert.equal(notebook.list().length, 1, "one implicit investigation, not five");
});

test("pruning: past the bound the oldest closed investigations go first, then the oldest open, never the current; a warning says so", async () => {
  const big = "x".repeat(20_000);
  async function fill(title, notes, { close = false } = {}) {
    const inv = await notebook.start({ title });
    for (let i = 0; i < notes; i += 1) await notebook.note(big + i, { investigation: inv.id });
    if (close) await notebook.close(inv.id);
    return inv.id;
  }
  const events = [];
  const off = notebook.subscribe((ev) => ev.type === "pruned" && events.push(ev));
  // ~300 KB each: three fit under 1 MB, the fourth does not.
  const oldClosed = await fill("Old closed", 15, { close: true });
  const oldOpen = await fill("Old open", 15);
  const newerOpen = await fill("Newer open", 15);
  assert.ok(notebook.bytes() < notebook.MAX_BYTES);
  assert.equal(events.length, 0);

  const cur = await fill("Current", 15);
  assert.equal(events.length, 1);
  assert.deepEqual(events[0].pruned.map((p) => p.id), [oldClosed]);
  assert.match(events[0].warning, /over its 1000 KB bound: the oldest investigation \(Old closed\) was removed/);
  assert.deepEqual(notebook.list().map((i) => i.title).sort(), ["Current", "Newer open", "Old open"]);
  assert.ok(notebook.bytes() <= notebook.MAX_BYTES);

  // Grow the current one: the open ones go oldest first; the current never.
  for (let i = 0; i < 30; i += 1) await notebook.note(big + i, { investigation: cur });
  const gone = events.slice(1).flatMap((ev) => ev.pruned.map((p) => p.id));
  assert.deepEqual(gone, [oldOpen, newerOpen]);
  assert.deepEqual(notebook.list().map((i) => i.id), [cur]);

  // Over the bound alone: nothing to prune, the warning names the case.
  for (let i = 0; i < 10; i += 1) await notebook.note(big + i, { investigation: cur });
  const last = events[events.length - 1];
  assert.deepEqual(last.pruned, []);
  assert.match(last.warning, /current investigation alone is over the bound/);
  assert.equal(notebook.get(cur).entries.length, 55, "the current investigation is never cut");
  const before = events.length;
  const explicit = await notebook.prune();
  assert.deepEqual(explicit.pruned, []);
  assert.match(explicit.warning, /alone is over/);
  assert.equal(events.length, before + 1, "an explicit prune emits once");
  off();
});

// The served app: no chrome.storage, so store.js writes localStorage. The
// double is installed after the memory-backend tests, and store.js checks
// for it on every call, so the same module instance switches over.
test("localStorage backend: the notebook is written under reach.notebook and read back on a fresh load", async () => {
  const m = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    value: { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) },
    configurable: true,
    writable: true,
  });
  try {
    assert.equal(store.backend(), "local");
    await notebook.load({ force: true });
    assert.equal(notebook.current(), null);
    const e = await notebook.record({ field: "user", value: "bob", from: sentinel(), reason: "held" });
    const raw = JSON.parse(m.get("reach.notebook"));
    assert.equal(raw.investigations[0].entries[0].id, e.id);
    assert.equal(raw.investigations[0].entries[0].from.container, "SigninLogs");
    assert.equal(raw.investigations[0].entries[0].from.scope, "soc-prod");
    const events = [];
    const off = notebook.subscribe((ev) => events.push(ev.type));
    await notebook.note("from the app");
    assert.deepEqual(events, ["change"]);
    off();
    const again = await notebook.load({ force: true });
    assert.equal(again.investigations[0].entries.length, 2);
    assert.equal(again.current, raw.current);
    assert.match(notebook.exportMarkdown(), /Pinned `user` = `bob` on SigninLogs \(workspace soc-prod, Sentinel\)/);
  } finally {
    delete globalThis.localStorage;
  }
});
