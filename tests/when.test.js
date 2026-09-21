// app/lib/when.js: the shared timestamp formatter, on the three inputs the
// app hands it (epoch seconds, epoch milliseconds, an ISO string) and its
// empty answer for what it cannot read.
import { test } from "node:test";
import assert from "node:assert/strict";

const { when, toMillis } = await import("../app/lib/when.js");

const MS = Date.UTC(2026, 8, 17, 20, 58, 59); // 2026-09-17T20:58:59Z

test("when() formats epoch milliseconds as an ISO date and 24-hour UTC clock", () => {
  assert.equal(when(MS), "2026-09-17 20:58:59 UTC");
});

test("when() reads a ten-digit number as epoch seconds, not milliseconds", () => {
  assert.equal(when(Math.floor(MS / 1000)), "2026-09-17 20:58:59 UTC");
});

test("when() reads an ISO string the same as its millisecond equivalent", () => {
  assert.equal(when("2026-09-17T20:58:59.000Z"), when(MS));
});

test("when() reads a numeric string the same as the number", () => {
  assert.equal(when(String(MS)), when(MS));
});

test("when() answers empty for null, undefined, empty string and unparseable input", () => {
  assert.equal(when(null), "");
  assert.equal(when(undefined), "");
  assert.equal(when(""), "");
  assert.equal(when("not a date"), "");
});

test("when() leaves a host page's own locale text alone rather than reading it as local time", () => {
  // No zone stated: Date.parse would read this as local time and answer a
  // different instant on every machine, so it is left for the caller's own
  // fallback instead of silently reformatted.
  assert.equal(when("9/18/26 2:03 PM"), "");
});

test("toMillis() answers undefined, not NaN, for input when() cannot read", () => {
  assert.equal(toMillis("not a date"), undefined);
  assert.equal(toMillis(NaN), undefined);
});

test("when() pads single-digit month, day, hour, minute and second", () => {
  assert.equal(when(Date.UTC(2026, 0, 5, 3, 4, 5)), "2026-01-05 03:04:05 UTC");
});
