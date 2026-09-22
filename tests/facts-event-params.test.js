// facts.eventParams: the one binder that reads a pivot's window and host
// off the clicked event itself, before a view or the drawer add their own.
import { test } from "node:test";
import assert from "node:assert/strict";
import { eventParams } from "../app/lib/facts.js";

test("a real _time brackets earliest/latest around the event, not around now", () => {
  const out = eventParams({ time: "2022-07-27T10:42:40.312+00:00", read: () => null });
  assert.equal(out.earliest, "2022-07-26T10:42:40.312Z");
  assert.equal(out.latest, "2022-07-27T10:47:40.312Z");
});

test("aid comes off the row's own aid (or Aid) field", () => {
  const rowA = { aid: "f0778584e83c4efc9cf026bc1e7f0489" };
  const rowB = { Aid: "f0778584e83c4efc9cf026bc1e7f0489" };
  assert.equal(eventParams({ read: (n) => rowA[n] ?? null }).aid, rowA.aid);
  assert.equal(eventParams({ read: (n) => rowB[n] ?? null }).aid, rowB.Aid);
});

test("no time and no read leaves the pivot's own placeholder default in charge", () => {
  assert.deepEqual(eventParams(), {});
  assert.deepEqual(eventParams({}), {});
});

test("an unparseable time binds nothing rather than a garbage window", () => {
  assert.deepEqual(eventParams({ time: "not a date" }), {});
});

test("never binds index or any other scope fact", () => {
  const out = eventParams({ time: "2022-07-27T10:42:40.312+00:00", read: (n) => (n === "index" ? "fdr" : n === "aid" ? "abc" : null) });
  assert.equal(out.index, undefined);
  assert.equal(Object.keys(out).sort().join(","), "aid,earliest,latest");
});
