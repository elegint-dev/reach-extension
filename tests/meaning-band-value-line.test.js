// The Meaning band under one heading: the field's own entry (label,
// description, provenance chip, taxonomy, the Format line once) always
// draws first; the value's own line, when it has one, draws under it, in
// one of three states, and is silent otherwise. The owner's MachineDomain
// screenshot (0.5.67) is the fourth state: an open, format-only field
// draws no value line at all, so Format is never printed twice.
import "./_splunk.js";
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as dom from "./_dom.js";
import * as catalogue from "../app/lib/catalogue.js";
import { h } from "../app/components/h.js";
import { meaningBlock, valueBlock } from "../app/lib/popup-ui.js";
import { walkBands } from "../app/lib/bands/band.js";
import { valueEntry } from "../app/lib/bands/value.js";
import * as packs from "../app/lib/packs.js";

await catalogue.load();
const restore = dom.install();
test.after(() => restore());

async function drawMeaning({ container, field, value }) {
  await catalogue.loadValues(container);
  const view = catalogue.fieldOn(container, field);
  const parts = walkBands(
    ["meaning", "value"],
    (id) => {
      if (id === "meaning") return { el: meaningBlock({ view, sourcetype: container, name: field, catalogue, appUrl: null, value, editable: false }) };
      if (id === "value") return { el: valueBlock({ field, value, container, platform: "splunk", catalogue, view }) };
      return null;
    },
    { platform: "splunk" },
  );
  assert.equal(parts.length, 1, "value and meaning share one Meaning band");
  return parts[0];
}

test("a listed value draws its own dictionary meaning under the field's entry", async () => {
  const band = await drawMeaning({ container: "aws:cloudtrail", field: "eventType", value: "AwsApiCall" });
  const line = dom.text(band.querySelector(".reach-value__body"));
  assert.match(line, /^AwsApiCall: An API was called/);
  assert.equal((dom.text(band).match(/Format/g) || []).length, 1, "Format prints exactly once");
});

test("a decodable concept's value reads the decode under the field's entry", async () => {
  const ST = "crowdstrike:events:sensor";
  const band = await drawMeaning({ container: ST, field: "TemplateDisposition", value: "30" });
  const line = dom.text(band.querySelector(".reach-value__body"));
  assert.match(line, /^30: TEMPLATE_DISPOSITION_PREVENT/);
});

test("a closed enumeration's miss is signal: not one of the N documented values", async () => {
  const band = await drawMeaning({ container: "aws:cloudtrail", field: "eventType", value: "NotAType" });
  const line = dom.text(band.querySelector(".reach-value__body"));
  assert.equal(line, "NotAType: not one of the 6 documented values");
});

test("MachineDomain = corp.example: an open, format-only field draws the field's meaning alone, no value line, Format not repeated", async () => {
  const band = await drawMeaning({ container: "crowdstrike:inventory:aidmaster", field: "MachineDomain", value: "corp.example" });
  assert.equal(band.querySelector(".reach-value"), null, "no value row at all");
  const text = dom.text(band);
  assert.match(text, /Host domain/);
  assert.match(text, /on this sourcetype MachineDomain/);
  assert.match(text, /The Active Directory domain the host is joined to\./);
  assert.match(text, /A DNS-style Active Directory domain name\./);
  assert.equal((text.match(/Format/g) || []).length, 1, "Format prints exactly once, on the field entry");
  assert.doesNotMatch(text, /corp\.example/, "the unlisted value itself is never echoed back with no information to add");
});

// The loader/builder marker (values.js `closed`) has one live path today,
// concept.type "enum"; this proves the sidecar's own `closed: true` also
// reaches valueEntry, through the real pack-registration path a sidecar
// takes (packs.register, catalogue.fieldOn), not a hand-built view.
test("a concept's own closed: true (not an enum type) also makes an unlisted value read as a documented miss", () => {
  const pack = {
    format: "reach-pack",
    version: 2,
    id: "closed-marker-test",
    name: "Closed marker test",
    feed: { id: "closed_marker_test", label: "Closed marker test" },
    concepts: {
      status: {
        label: "Status",
        description: "One fixed word naming the outcome.",
        type: "outcome",
        format: "One fixed word: ok or error.",
        closed: true,
        provenance: "observed",
        values: { ok: "The call succeeded.", error: "The call failed." },
      },
    },
    containers: { "closed:test": { platform: "splunk" } },
    bindings: [{ platform: "splunk", container: "closed:test", column: "Status", concept: "status" }],
  };
  assert.deepEqual(packs.validate(pack), []);
  packs.register(pack);
  try {
    const view = catalogue.fieldOn("closed:test", "Status");
    assert.equal(view.concept.type, "outcome", "closed here, deliberately, is not carried by the type");
    assert.equal(view.dictionary.closed, true);
    const hit = valueEntry({ catalogue, container: "closed:test", field: "Status", value: "timeout", view });
    assert.equal(hit.kind, "closed");
    assert.equal(hit.count, 2);
  } finally {
    packs.remove("closed-marker-test");
  }
});
