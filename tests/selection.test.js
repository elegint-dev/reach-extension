// app/lib/selection.js: a SIEM click landing in the panel. The click's
// value rides in the field route and in this tab's last event; no store
// that means "held" or "pinned" is written by a click.
import "./_splunk.js";
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), keys: () => [...m.keys()] };
}
Object.defineProperty(globalThis, "localStorage", { value: memoryStorage(), configurable: true, writable: true });
Object.defineProperty(globalThis, "sessionStorage", { value: memoryStorage(), configurable: true, writable: true });

const selection = await import("../app/lib/selection.js");
const investigation = await import("../app/lib/investigation.js");
const pinned = await import("../app/lib/pinned.js");
const lastEvent = await import("../app/lib/last-event.js");
const scope = await import("../app/lib/scope.js");
const notebook = await import("../app/lib/notebook.js");
const store = await import("../app/lib/store.js");
const router = await import("../app/lib/router.js");

const HASH = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";
const click = {
  platform: "splunk",
  kind: "value",
  name: "SHA256HashData",
  value: HASH,
  sourcetype: "crowdstrike:events:sensor",
  index: "fdr",
  discriminator: { field: "event_simpleName", value: "ProcessRollup2" },
  event: { event_platform: "Mac", SHA256HashData: HASH, ImageFileName: "/usr/bin/ssh" },
  provenance: { event: { id: "e1" }, search: { text: "index=fdr" }, scope: "fdr" },
};

beforeEach(async () => {
  investigation.clear();
  pinned.clear();
  lastEvent.clear();
  await store.remove(notebook.KEY);
  await notebook.load({ force: true });
});

const pinsInNotebook = () => {
  const inv = notebook.current();
  return inv ? inv.entries.filter((e) => e.kind === "pin") : [];
};

test("a value click lands as the field route with the value, sets the last event, and writes no held, pinned or notebook store", () => {
  const landed = selection.land(click);
  assert.deepEqual(landed, { platform: "splunk", route: "field", params: { name: "SHA256HashData", st: "crowdstrike:events:sensor", on: "ProcessRollup2", value: HASH }, hop: selection.hopKey(click) });
  assert.equal(router.build(landed.route, landed.params), `#/f/SHA256HashData?st=crowdstrike%3Aevents%3Asensor&on=ProcessRollup2&value=${HASH}`);
  assert.deepEqual(investigation.all(), {}, "the tab's held facts");
  assert.deepEqual(pinned.all(), {}, "the browser's pins");
  assert.deepEqual(pinsInNotebook(), [], "the notebook");
  assert.equal(globalThis.sessionStorage.getItem("reach.investigation"), null);
  assert.equal(globalThis.localStorage.getItem("reach.pinned"), null);
  assert.deepEqual(lastEvent.clicked("crowdstrike:events:sensor"), { field: "SHA256HashData", value: HASH });
  assert.deepEqual(lastEvent.recall("crowdstrike:events:sensor"), click.event);
  assert.deepEqual(lastEvent.provenance("crowdstrike:events:sensor"), click.provenance);
  assert.equal(scope.remembered("crowdstrike:events:sensor"), "fdr", "the index is learned as scope for the sourcetype");
});

test("a field click (no value) lands the bare field route, with nothing clicked on the last event", () => {
  const landed = selection.land({ ...click, kind: "field", value: "" });
  assert.deepEqual(landed.params, { name: "SHA256HashData", st: "crowdstrike:events:sensor", on: "ProcessRollup2" });
  assert.equal(lastEvent.clicked("crowdstrike:events:sensor"), null);
  assert.deepEqual(investigation.all(), {});
});

test("a click on the other platform keeps its platform for the switch, and a click with no name lands nowhere", () => {
  assert.equal(selection.land({ ...click, platform: "sentinel", sourcetype: "ReachCrowdStrike_CL" }).platform, "sentinel");
  assert.equal(selection.land({ ...click, name: "" }), null);
  assert.equal(selection.land(null), null);
});

test("a clicked index is scope, not a value: it is learned for the sourcetype and never lands in a store", () => {
  selection.land({ ...click, name: "index", value: "fdr", event: {} });
  assert.deepEqual(investigation.all(), {});
  assert.equal(lastEvent.clicked("crowdstrike:events:sensor").field, "index");
});

// The hop key: the row a click was in, for the trail (navstack.js). Same
// row, same key, whatever the field or value clicked.

test("clicks on different fields and values of one row share a hop key; another row, search, record type, container or platform is another key", () => {
  const k = selection.hopKey(click);
  assert.equal(selection.hopKey({ ...click, name: "ImageFileName", value: "/usr/bin/ssh" }), k, "another field of the row");
  assert.equal(selection.hopKey({ ...click, kind: "field", value: "" }), k, "a key-name click in the row");
  assert.notEqual(selection.hopKey({ ...click, provenance: { ...click.provenance, event: { id: "e2" } } }), k, "another event");
  assert.notEqual(selection.hopKey({ ...click, provenance: { ...click.provenance, search: { text: "index=fdr aid=abc" } } }), k, "the same event in another search's results");
  assert.notEqual(selection.hopKey({ ...click, discriminator: { field: "event_simpleName", value: "DnsRequest" } }), k, "another record type");
  assert.notEqual(selection.hopKey({ ...click, sourcetype: "stash" }), k, "another container");
  assert.notEqual(selection.hopKey({ ...click, platform: "sentinel" }), k, "the other platform");
});

test("a row without an event id is known by its time and sibling fields, and a click with no row at all is the search itself", () => {
  const noId = { ...click, provenance: { ...click.provenance, event: { id: null, time: "2026-09-17 16:11:23.443" } } };
  const k = selection.hopKey(noId);
  assert.equal(selection.hopKey({ ...noId, name: "aid", value: "f07" }), k, "another field of the same row");
  assert.notEqual(selection.hopKey({ ...noId, provenance: { ...noId.provenance, event: { id: null, time: "2026-09-17 16:11:23.407" } } }), k, "a row at another time");
  assert.notEqual(selection.hopKey({ ...noId, event: { ...click.event, SHA256HashData: "ffff" } }), k, "a row at the same time with other fields");
  const bare = { platform: "splunk", kind: "field", name: "aid", sourcetype: "crowdstrike:events:sensor", provenance: { event: {}, search: { text: "index=fdr" } } };
  assert.equal(selection.hopKey({ ...bare, name: "ComputerName" }), selection.hopKey(bare), "the sidebar's field clicks on one search share a hop");
  assert.notEqual(selection.hopKey({ ...bare, provenance: { event: {}, search: { text: "index=fdr aid=abc" } } }), selection.hopKey(bare));
});
