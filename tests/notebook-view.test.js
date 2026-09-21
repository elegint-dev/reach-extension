// The notebook view's pure half (app/views/notebook.js): entries joined by
// their references are one thread, threads come in the order they
// started, a parked thread is folded everywhere and every thread is folded
// in the panel, the timeline keeps the entries' order one line each, and
// the held-facts terms the insert shortcut will offer (app/lib/held.js
// termsFor) are per platform and never a scope key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { threads, threadTitle, model, foldState } from "../app/views/notebook.js";
import { termsFor } from "../app/lib/held.js";

const T = Date.UTC(2026, 8, 18, 14, 0, 0);
const min = (n) => T + n * 60_000;
const from = (over = {}) => ({ platform: "splunk", container: "aws:cloudtrail", column: "x", scope: "main", ...over });

function fixture() {
  return {
    id: "inv_view",
    title: null,
    created: min(0),
    updated: min(30),
    trigger: "",
    status: "open",
    entries: [
      { id: "p1", kind: "pin", at: min(1), field: "sourceIPAddress", value: "203.0.113.9", from: from({ column: "sourceIPAddress" }) },
      { id: "p2", kind: "pin", at: min(2), field: "userIdentity.arn", value: "arn:aws:iam::1:user/bob", from: from({ column: "userIdentity.arn" }) },
      { id: "e1", kind: "enrichment", at: min(3), on: "p1", source: "VirusTotal", summary: "clean" },
      { id: "v1", kind: "pivot", at: min(4), origin: "p2", target: "p3", query: { text: "index=main", language: "SPL" }, name: "aws:cloudtrail" },
      { id: "p3", kind: "pin", at: min(4), field: "eventName", value: "CreateAccessKey", from: from({ column: "eventName" }) },
      { id: "k1", kind: "parked", at: min(5), field: "userAgent", value: "aws-cli/2.15.0", why: "later", from: from({ column: "userAgent" }) },
      { id: "n1", kind: "note", at: min(6), text: "loose note" },
      { id: "n2", kind: "note", at: min(7), on: "p3", text: "attached", finding: true },
      { id: "l1", kind: "note", at: min(8), text: "linked in", links: [{ to: "p1", rel: "related" }] },
      { id: "k2", kind: "parked", at: min(9), on: "p1", why: "park the ip", state: "resumed" },
    ],
  };
}

test("threads: entries joined by on, origin, target and links are one thread, in the order they started", () => {
  const ts = threads(fixture());
  assert.deepEqual(
    ts.map((t) => t.entries.map((e) => e.id)),
    [
      ["p1", "e1", "l1", "k2"],
      ["p2", "v1", "p3", "n2"],
      ["k1"],
      ["n1"],
    ],
  );
  assert.deepEqual(ts.map((t) => t.root.id), ["p1", "p2", "k1", "n1"]);
  assert.deepEqual(ts.map((t) => t.id), ["p1", "p2", "k1", "n1"]);
});

test("threads: parked is a parked entry not picked up again; a resumed one is not parked", () => {
  const ts = threads(fixture());
  assert.deepEqual(ts.map((t) => t.parked), [false, false, true, false]);
});

test("threadTitle: the root's field = value, else its sentence", () => {
  const inv = fixture();
  const ts = threads(inv);
  assert.equal(threadTitle(ts[0], inv), "sourceIPAddress = 203.0.113.9");
  assert.equal(threadTitle(ts[2], inv), "userAgent = aws-cli/2.15.0");
  assert.equal(threadTitle(ts[3], inv), "Note: loose note");
});

test("fold state: open on the wide and narrow surfaces, closed in the panel, closed for a parked thread everywhere", () => {
  const live = { parked: false };
  const parked = { parked: true };
  assert.equal(foldState(live, "wide"), true);
  assert.equal(foldState(live, "narrow"), true);
  assert.equal(foldState(live, "panel"), false);
  assert.equal(foldState(parked, "wide"), false);
  assert.equal(foldState(parked, "panel"), false);
  const m = model(fixture(), { surface: "panel" });
  assert.deepEqual(m.threads.map((t) => m.open(t)), [false, false, false, false]);
  const w = model(fixture(), { surface: "wide" });
  assert.deepEqual(w.threads.map((t) => w.open(t)), [true, true, false, true]);
});

test("model: the timeline is the narrative, one line per entry in entry order, each line carrying its entry", () => {
  const inv = fixture();
  const m = model(inv);
  assert.equal(m.days.length, 1);
  assert.equal(m.days[0].day, "2026-09-18");
  const lines = m.days[0].lines;
  assert.deepEqual(lines.map((l) => l.entry.id), inv.entries.map((e) => e.id));
  assert.equal(lines[0].time, "14:01");
  assert.match(lines[0].text, /^Pinned sourceIPAddress = 203\.0\.113\.9 on aws:cloudtrail \(index main, Splunk\)\.$/);
  assert.match(lines[3].text, /^From userIdentity\.arn = arn:aws:iam::1:user\/bob, pivoted to aws:cloudtrail with index=main \(SPL\), which surfaced eventName = CreateAccessKey\.$/);
  assert.match(lines[9].text, /Picked up again later\.$/);
  assert.equal(m.untitled, true);
  assert.equal(m.title, "Untitled investigation (2026-09-18)");
  assert.equal(m.status, "open");
});

test("model: a closed investigation says when; two days are two groups", () => {
  const inv = fixture();
  inv.status = "closed";
  inv.closed = min(60 * 24 + 1);
  inv.entries.push({ id: "n3", kind: "note", at: min(60 * 24), text: "next day" });
  const m = model(inv);
  assert.equal(m.status, "closed 2026-09-19 14:01:00 UTC");
  assert.deepEqual(m.days.map((d) => [d.day, d.lines.length]), [["2026-09-18", 10], ["2026-09-19", 1]]);
  assert.equal(model(null), null);
});

test("termsFor: held facts as SPL terms and KQL terms through the platform's quote, never a scope key", () => {
  const facts = { AID: "abc123", index: "main", cmd: 'a "b"', empty: "", workspace: "soc" };
  const q = (v) => `"${String(v).replace(/"/g, '\\"')}"`;
  assert.deepEqual(termsFor(facts, "splunk", q), [
    { key: "aid", value: "abc123", text: 'aid="abc123"' },
    { key: "cmd", value: 'a "b"', text: 'cmd="a \\"b\\""' },
  ]);
  assert.deepEqual(termsFor(facts, "sentinel", q).map((t) => t.text), ['aid == "abc123"', 'cmd == "a \\"b\\""']);
  assert.deepEqual(termsFor({}, "splunk"), []);
});
