// The heading registry: one entry per meaning, resolved under either
// platform's words, never a question and never a pronoun.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { HEADINGS, ENTITY_ORDER, TOOL_ORDER, heading, matcher, get } from "../app/lib/headings.js";
import { termsFor } from "../app/lib/platform.js";

const PLATFORMS = ["splunk", "sentinel"];
const BAD_START = /^(what|where|when|how|it|its|this|that|these|those|they|them|you|your|we|our)\b/i;

test("every entry has an id, a level of h2, h3 or summary, and a text function", () => {
  assert.ok(Object.isFrozen(HEADINGS));
  const ids = new Set();
  for (const e of HEADINGS) {
    assert.match(e.id, /^[a-z][a-z0-9-]*$/, `id ${e.id}`);
    assert.ok(!ids.has(e.id), `id ${e.id} listed twice`);
    ids.add(e.id);
    assert.ok(["h2", "h3", "summary"].includes(e.level), `${e.id}: level ${e.level}`);
    assert.equal(typeof e.text, "function", `${e.id}: text`);
  }
});

test("every heading resolves to a non-empty string under both platforms' words, with and without a count", () => {
  for (const platform of PLATFORMS) {
    const T = termsFor(platform);
    for (const e of HEADINGS) {
      for (const n of [undefined, 0, 1, 1204]) {
        const s = e.text(T, n);
        assert.equal(typeof s, "string", `${e.id} on ${platform}`);
        assert.ok(s.trim().length, `${e.id} on ${platform}: empty`);
        assert.doesNotMatch(s, /undefined|null|NaN/, `${e.id} on ${platform}: ${s}`);
        assert.doesNotMatch(s, /\u2014/, `${e.id} on ${platform}: U+2014`);
      }
      assert.match(e.text(T, 1204), /\(1,204\)$|^[^()]*$/, `${e.id}: a count is written (N) at the end`);
    }
  }
});

test("no two ids resolve to one string on one platform", () => {
  for (const platform of PLATFORMS) {
    const T = termsFor(platform);
    const seen = new Map();
    for (const e of HEADINGS) {
      const s = e.text(T, 3);
      assert.ok(!seen.has(s), `${platform}: ${e.id} and ${seen.get(s)} both read "${s}"`);
      seen.set(s, e.id);
    }
  }
});

test("no heading starts with a pronoun or with What, Where, When or How, and none ends in a question mark", () => {
  for (const platform of PLATFORMS) {
    const T = termsFor(platform);
    for (const e of HEADINGS) {
      const s = e.text(T, 2);
      assert.doesNotMatch(s, BAD_START, `${e.id} on ${platform}: "${s}"`);
      assert.doesNotMatch(s, /\?$/, `${e.id} on ${platform}: "${s}"`);
    }
  }
});

test("the platform's nouns come from TERMS: the sourcetype, field and environment headings read table, column and workspace on Sentinel", () => {
  const S = termsFor("sentinel");
  assert.equal(heading("other-sourcetypes", 2, S), "Other tables (2)");
  assert.equal(heading("fields", 30, S), "Columns (30)");
  assert.equal(heading("field-changes", 1, S), "Column changes (1)");
  assert.equal(heading("environment", undefined, S), "Workspace");
  assert.equal(heading("sourcetypes", 64, S), "Tables (64)");
  const P = termsFor("splunk");
  assert.equal(heading("other-sourcetypes", 2, P), "Other sourcetypes (2)");
  assert.equal(heading("fields", 30, P), "Fields (30)");
  assert.equal(heading("environment", undefined, P), "Splunk instance");
});

test("the master orders name registry h2 entries only, each once", () => {
  for (const order of [ENTITY_ORDER, TOOL_ORDER]) {
    assert.ok(Object.isFrozen(order));
    assert.equal(new Set(order).size, order.length);
    for (const id of order) assert.equal(get(id).level, "h2", `${id} is not an h2`);
  }
});

test("a rendered heading resolves back to its entry, with any count, and a string outside the list resolves to nothing", () => {
  for (const platform of PLATFORMS) {
    const T = termsFor(platform);
    const m = matcher(T);
    for (const e of HEADINGS) {
      assert.equal(m(e.text(T, 12)), e, `${e.id} on ${platform}`);
      assert.equal(m(e.text(T)), e, `${e.id} on ${platform}, no count`);
    }
    assert.equal(m("Where it comes from"), null);
    assert.equal(m("What are you holding?"), null);
    assert.equal(m("Reaches (1)"), null);
    assert.equal(m("Here"), null);
  }
});

test("an unknown id throws rather than drawing a heading of its own", () => {
  assert.throws(() => heading("no-such-heading"), /no heading/);
});
