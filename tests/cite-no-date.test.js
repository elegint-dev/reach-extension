// A cite's read_on is provenance data, not analyst copy: every surface
// that renders a reference (the field page's dictionary block and
// reference line, the popup's value band, the value page's value line)
// keeps the source title as the link and drops the date. citeWords, the
// shared formatter, is covered directly.
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as values from "../app/lib/values.js";
import { dictionaryBlock, referenceLine } from "../app/components/dictionary.js";
import { valueBlock } from "../app/lib/popup-ui.js";
import { valueLine } from "../app/views/value.js";

await catalogue.load();

const ST = "aws:cloudtrail";
const PACK = "aws-cloudtrail";
const FIELD = "eventType";
const VALUE = "AwsApiCall";
const DATE_RE = /\d{4}-\d{2}-\d{2}/;

test("citeWords: the source title only, no read_on in the words", () => {
  const cite = { url: "https://example.test/doc", title: "Example reference", read_on: "2026-09-18" };
  assert.equal(values.citeWords(cite), "Example reference");
  assert.ok(!DATE_RE.test(values.citeWords(cite)));
  assert.equal(values.citeWords(null), "");
});

test("field page: dictionaryBlock's reference line carries the cite's title, not its read_on", async () => {
  await catalogue.loadValues(ST);
  const restore = dom.install();
  try {
    const view = catalogue.fieldOn(ST, FIELD);
    assert.ok(view.dictionary && view.dictionary.cite && view.dictionary.cite.read_on, "fixture carries a dated cite");
    const section = dictionaryBlock({ view, sourcetype: ST, name: FIELD, catalogue });
    assert.ok(section, "block drawn");
    const joined = section.textContent;
    assert.match(joined, /CloudTrail record contents/);
    assert.ok(!DATE_RE.test(joined), joined);
  } finally {
    restore();
  }
});

test("sourcetype page: referenceLine carries the feed's reference title, not its read_on", async () => {
  await catalogue.loadValues(ST);
  const restore = dom.install();
  try {
    const el = referenceLine({ sourcetype: ST, packId: PACK, catalogue });
    assert.ok(el, "reference line drawn");
    const text = el.textContent;
    assert.match(text, /CloudTrail record contents/);
    assert.ok(!DATE_RE.test(text), text);
  } finally {
    restore();
  }
});

test("popup value band: the cite line carries the source title, not its read_on", async () => {
  await catalogue.loadValues(ST);
  const restore = dom.install();
  try {
    const view = catalogue.fieldOn(ST, FIELD);
    const band = valueBlock({ field: FIELD, value: VALUE, container: ST, platform: "splunk", catalogue, view });
    const cite = band.querySelector(".reach-value__cite");
    assert.ok(cite, "cite line drawn");
    assert.match(cite.textContent, /CloudTrail record contents/);
    assert.ok(!DATE_RE.test(cite.textContent), cite.textContent);
  } finally {
    restore();
  }
});

test("value page: valueLine's reference carries the source title, not its read_on", async () => {
  await catalogue.loadValues(ST);
  const restore = dom.install();
  try {
    const body = valueLine({ catalogue, container: ST, field: FIELD, value: VALUE });
    assert.ok(body, "value line drawn");
    const ref = body.querySelector(".r-dict__ref");
    assert.ok(ref, "reference line drawn");
    assert.match(ref.textContent, /CloudTrail record contents/);
    assert.ok(!DATE_RE.test(ref.textContent), ref.textContent);
  } finally {
    restore();
  }
});
