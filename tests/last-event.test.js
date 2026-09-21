// app/lib/last-event.js: the last clicked row's sibling fields, kept per
// tab for the value page's known-good verdict, answered only for the
// container the row was on, and harmless with no storage at all.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as lastEvent from "../app/lib/last-event.js";

function fakeStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), size: () => m.size };
}

beforeEach(() => {
  globalThis.sessionStorage = fakeStorage();
});

test("remember then recall, for the same container only; strings only ride", () => {
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: { SigningId: "com.apple.contactsd", TeamId: "-", n: 5, empty: "" } });
  assert.deepEqual(lastEvent.recall("crowdstrike:events:sensor"), { SigningId: "com.apple.contactsd", TeamId: "-" });
  assert.deepEqual(lastEvent.recall(undefined), { SigningId: "com.apple.contactsd", TeamId: "-" }, "no container asked: the last row");
  assert.equal(lastEvent.recall("aws:cloudtrail"), null, "another container's page gets nothing");
  lastEvent.clear();
  assert.equal(lastEvent.recall("crowdstrike:events:sensor"), null);
});

test("the clicked field and value ride with the row, answered for the same container only, and a click with no value clears them", () => {
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: { SigningId: "com.apple.contactsd" }, clicked: { field: "SigningId", value: "com.apple.contactsd" } });
  assert.deepEqual(lastEvent.clicked("crowdstrike:events:sensor"), { field: "SigningId", value: "com.apple.contactsd" });
  assert.equal(lastEvent.clicked("aws:cloudtrail"), null);
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: { SigningId: "x" } });
  assert.equal(lastEvent.clicked("crowdstrike:events:sensor"), null, "a field click carries no value");
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: {}, clicked: { field: "aid", value: "abc" } });
  assert.deepEqual(lastEvent.clicked("crowdstrike:events:sensor"), { field: "aid", value: "abc" }, "a click with no sibling fields still rides");
  assert.equal(lastEvent.recall("crowdstrike:events:sensor"), null);
});

test("a selection with no row fields forgets the previous row", () => {
  lastEvent.remember({ platform: "splunk", container: "crowdstrike:events:sensor", fields: { SigningId: "com.apple.contactsd" } });
  lastEvent.remember({ platform: "splunk", container: "aws:cloudtrail", fields: {} });
  assert.equal(lastEvent.recall("crowdstrike:events:sensor"), null);
  assert.equal(globalThis.sessionStorage.size(), 0);
});

test("with storage blocked or garbage in it, nothing throws and nothing is recalled", () => {
  globalThis.sessionStorage = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
  lastEvent.remember({ platform: "splunk", container: "x", fields: { a: "b" } });
  assert.equal(lastEvent.recall("x"), null);
  globalThis.sessionStorage = fakeStorage();
  globalThis.sessionStorage.setItem("reach.lastEvent", "{not json");
  assert.equal(lastEvent.recall("x"), null);
  delete globalThis.sessionStorage;
  lastEvent.remember({ platform: "splunk", container: "x", fields: { a: "b" } });
  assert.equal(lastEvent.recall("x"), null);
});
