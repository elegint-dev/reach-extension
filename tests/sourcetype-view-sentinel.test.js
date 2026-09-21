// The sourcetype page on Sentinel: the same template with the platform's
// words: Columns (N) beside Bind columns, no event links because the
// event route is not mounted, and every heading resolving under
// Sentinel's TERMS.
import "./_sentinel.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as fields from "../app/lib/pack-fields.js";
import * as modules from "../app/lib/modules.js";
import { matcher } from "../app/lib/headings.js";
import { PLATFORM, termsFor } from "../app/lib/platform.js";
import { render } from "../app/views/sourcetype.js";

globalThis.matchMedia = (q) => ({ matches: q.includes("599"), addEventListener() {} });

assert.equal(PLATFORM, "sentinel");
await catalogue.load();

const TABLE = "ReachCrowdStrike_CL";
const resolve = matcher(termsFor("sentinel"));

function ctx(params) {
  return { fields, catalogue, route: "sourcetype", params, navigate() {}, href: () => "#", setUrl() {}, goBack() {}, modules };
}

test("the Sentinel table page draws Columns (N) beside Bind columns, the scope line in columns, and every heading resolves under Sentinel's words", () => {
  const restore = dom.install();
  try {
    assert.ok(catalogue.sourcetype(TABLE), "the sample pack knows the table");
    const el = render(ctx({ name: TABLE }));
    const title = el.children[0];
    assert.ok(title.classList.contains("r-title"));
    assert.match(dom.text(title.querySelector(".r-scope")), /^\d+ columns · record type EventSimpleName · \d+ described/);
    assert.deepEqual(title.querySelector(".r-actions").children.map(dom.text), ["Describe", "Discover", "Bind columns", "Baseline: what my fleet runs"], "ReachCrowdStrike_CL is the sample table the fleet baseline query reads");
    const h2s = el.querySelectorAll("h2").map(dom.text);
    for (const t of h2s) assert.ok(resolve(t), `"${t}" is not in the heading registry`);
    const fields = h2s.find((t) => /^Columns \(\d+\)$/.test(t));
    assert.ok(fields, `Columns (N) among ${h2s.join(", ")}`);
    assert.equal(h2s.some((t) => /^Fields/.test(t)), false);
    assert.equal(dom.text(el.querySelector(".r-rolelist__bind")), "Bind columns");
    // The FDR five are Splunk knowledge; the pack hunt runs on the sample table and is listed here.
    assert.ok(h2s.includes("Workflows"), h2s.join(", "));
    const listed = el.querySelector(".r-workflows--hunts").querySelectorAll("a").map((a) => a.getAttribute("href"));
    assert.deepEqual(listed, ["#/w/hunt_mac_signing"]);
    assert.equal(el.querySelector(".r-workflows--pivots"), null);
  } finally {
    restore();
  }
});

test("no record type links to an event page on Sentinel: the route is not mounted there", () => {
  const restore = dom.install();
  try {
    assert.equal(modules.routes().includes("event"), false);
    const el = render(ctx({ name: TABLE }));
    const links = el.querySelectorAll("a").map((a) => a.getAttribute("href") || "");
    assert.equal(links.some((href) => href.startsWith("#/e/")), false);
    const wrap = el.querySelector(".r-typelist__wrap");
    if (wrap) assert.match(dom.text(wrap.querySelector("summary")), /^Record types \(\d+\)$/);
  } finally {
    restore();
  }
});

test("the table page reads in Sentinel's words throughout: no 'sourcetype' in its text, and an undescribed table's block says table", async () => {
  const restore = dom.install();
  try {
    const el = render(ctx({ name: TABLE }));
    assert.doesNotMatch(dom.text(el), /sourcetype/i, "the other platform's noun never reaches the page");
    const { sourcetypeAnnotation } = await import("../app/components/annotation.js");
    const block = sourcetypeAnnotation({ record: { name: "Fresh_CL", description: null, tags: [] }, catalogue, onSaved() {} });
    assert.match(dom.text(block), /No description for this table yet\./);
    assert.deepEqual(block.querySelectorAll("button").map(dom.text), ["Describe this table"]);
  } finally {
    restore();
  }
});
