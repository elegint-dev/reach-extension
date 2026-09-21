// advisor.js's Advise click: adviseText() is the pure decision behind it
// (the rest of advisorSection touches the DOM, exercised through the
// chrome harness, not here). A live read that answered, even with blank
// text, wins over the box; no read at all falls back to what was pasted.

import { test } from "node:test";
import assert from "node:assert/strict";

const { adviseText } = await import("../app/components/advisor.js");

test("adviseText: a live read that found text wins over the pasted/carried box", () => {
  assert.equal(adviseText({ live: { ok: true, text: "index=main sourcetype=x" }, input: "index=old" }), "index=main sourcetype=x");
});

test("adviseText: no live read (tab relay found nothing to ask, or answered ok: false) falls back to the box", () => {
  assert.equal(adviseText({ live: null, input: "index=old" }), "index=old");
  assert.equal(adviseText({ live: { ok: false, reason: "no search bar on this page" }, input: "index=old" }), "index=old");
});

test("adviseText: a live search bar that is there but empty still falls back, since blank text advises nothing", () => {
  assert.equal(adviseText({ live: { ok: true, text: "" }, input: "index=old" }), "index=old");
  assert.equal(adviseText({ live: { ok: true, text: "   " }, input: "index=old" }), "index=old");
});

test("adviseText: no box either is the empty string, never undefined", () => {
  assert.equal(adviseText({ live: null }), "");
  assert.equal(adviseText(), "");
});
