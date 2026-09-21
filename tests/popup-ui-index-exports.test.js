// popup-ui.js is the index the popups, the Sentinel grid and the value page
// import from: every name it ever exported, by name and in the default
// object, resolves through it, whichever band or shell module owns it now.
import "./_splunk.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as ui from "../app/lib/popup-ui.js";

const NAMED = [
  "ALERT_FIELDS", "BAND_HEADING", "BENIGN_CSS", "ENRICH_CSS", "HOLD_CSS", "MISSING_PARAM_META", "PATTERN_CSS", "POPUP_CSS",
  "SENTINEL_NO_PIVOTS_NOTE", "SENTINEL_PIVOTS_LINE", "SENTINEL_PIVOTS_LINE_PAGE", "VERDICT_CSS", "VERDICT_FIELDS",
  "alertFields", "anchoredPanel", "attachButton", "band", "bandTitle", "benignBlock", "closePanel", "enrichBlock", "enrichModel",
  "eventSummary", "everywhereBlock", "exclusionOffer", "exclusionStrip", "fieldHash", "fleetLine", "foldBlock", "heldPin", "hold",
  "holdBlock", "hostTheme", "linuxReleaseOf", "macosEntry", "meaningBlock", "missingParamInputs", "missingParamMeta", "noteSearch", "offerToPanel", "osBuildFor", "panelLine",
  "patternBlock", "patternModel", "pinFrom", "plan", "platformBinaryOf", "recordPivot", "runbookBlock", "scopeLine", "valueBlock", "valueEntry",
  "verdictBlock", "verdictFields", "verdictInput", "verdictModel", "walkBands", "whenValuesLand", "workflowsBlock",
];

// The default object carries the same names it always did, the band
// assembly (BAND_HEADING, band, plan, walkBands, the Sentinel lines) excepted.
const DEFAULT = NAMED.filter((n) => !["BAND_HEADING", "SENTINEL_NO_PIVOTS_NOTE", "SENTINEL_PIVOTS_LINE", "SENTINEL_PIVOTS_LINE_PAGE", "band", "bandTitle", "plan", "walkBands"].includes(n));

test("the index exports every name the popups and the value page import, and nothing is undefined", () => {
  assert.deepEqual(Object.keys(ui).filter((k) => k !== "default").sort(), NAMED);
  for (const n of NAMED) assert.notEqual(ui[n], undefined, n);
});

test("the default object keeps its keys, each the same binding as the named export", () => {
  assert.deepEqual(Object.keys(ui.default).sort(), DEFAULT);
  for (const n of DEFAULT) assert.equal(ui.default[n], ui[n], n);
});

test("each band owns its stylesheet and the shell composes them: the index hands out the same strings", async () => {
  const shell = await import("../app/lib/popup-shell.js");
  const pattern = await import("../app/lib/bands/pattern.js");
  const verdict = await import("../app/lib/bands/verdict.js");
  const enrich = await import("../app/lib/bands/enrich.js");
  const holdBenign = await import("../app/lib/bands/hold-and-benign.js");
  assert.equal(ui.POPUP_CSS, shell.POPUP_CSS);
  assert.equal(ui.PATTERN_CSS, pattern.PATTERN_CSS);
  assert.equal(ui.VERDICT_CSS, verdict.VERDICT_CSS);
  assert.equal(ui.ENRICH_CSS, enrich.ENRICH_CSS);
  assert.equal(ui.HOLD_CSS, holdBenign.HOLD_CSS);
  assert.equal(ui.BENIGN_CSS, holdBenign.BENIGN_CSS);
});
