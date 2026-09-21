// classify()'s value-kind rules: app/views/value.js branches on c.kind ===
// "name" for the title-only page, so every rule here is also a routing
// decision, not only a label.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, KINDS } from "../app/lib/search.js";

test("classify: a CVE id is its own kind, not a name, mirroring shapes.js detectCve", () => {
  const c = classify("CVE-2025-39964");
  assert.equal(c.kind, "cve");
  assert.equal(c.value, "CVE-2025-39964");
  assert.equal(c.candidates.length, 1);
  assert.equal(c.candidates[0].kind, "cve");
  assert.ok(KINDS.includes("cve"));
});

test("classify: a CVE id normalises case and reads longer digit runs, like detectCve", () => {
  assert.equal(classify("cve-2025-39964").kind, "cve");
  assert.equal(classify("CVE-2024-123456").kind, "cve");
  assert.equal(classify("  CVE-2025-39964  ").kind, "cve");
});

test("classify: a string only shaped like a CVE (short year or digit run) stays a name", () => {
  assert.equal(classify("CVE-2021-442").kind, "name");
  assert.equal(classify("CVE-99-44228").kind, "name");
  assert.equal(classify("NOT-A-CVE-2021-44228").kind, "name");
});

test("classify: an exact catalogue name wins over the CVE reading", () => {
  const idx = { fields: ["CVE-2025-39964"], events: [] };
  const c = classify("CVE-2025-39964", idx);
  assert.equal(c.kind, "name");
});
