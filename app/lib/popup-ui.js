// The one import every popup surface uses: the section shell
// (popup-shell.js) and the bands (bands/*.js) under their own names. The
// two in-Splunk popups, the Sentinel grid and the app's value page import
// from here so the wording, the chips and the CSS never drift apart.
//
// DOM module. Never fetches.

export { POPUP_CSS, scopeLine, MISSING_PARAM_META, missingParamMeta, missingParamInputs, fieldHash, offerToPanel, panelLine, hostTheme, anchoredPanel, closePanel } from "./popup-shell.js";
export { BAND_HEADING, SENTINEL_PIVOTS_LINE, SENTINEL_PIVOTS_LINE_PAGE, SENTINEL_NO_PIVOTS_NOTE, bandTitle, band, plan, walkBands, foldBlock } from "./bands/band.js";
export { valueEntry, whenValuesLand, valueBlock } from "./bands/value.js";
export { VERDICT_CSS, VERDICT_FIELDS, ALERT_FIELDS, verdictFields, alertFields, runbookBlock, platformBinaryOf, verdictInput, osBuildFor, fleetLine, linuxReleaseOf, macosEntry, verdictModel, verdictBlock } from "./bands/verdict.js";
export { PATTERN_CSS, patternModel, patternBlock } from "./bands/pattern.js";
export { meaningBlock } from "./bands/meaning.js";
export { everywhereBlock, workflowsBlock } from "./bands/workflows.js";
export { ENRICH_CSS, enrichModel, enrichBlock } from "./bands/enrich.js";
export { HOLD_CSS, BENIGN_CSS, pinFrom, eventSummary, heldPin, hold, holdBlock, recordPivot, noteSearch, attachButton, exclusionOffer, benignBlock, exclusionStrip } from "./bands/hold-and-benign.js";

import { POPUP_CSS, scopeLine, MISSING_PARAM_META, missingParamMeta, missingParamInputs, fieldHash, offerToPanel, panelLine, hostTheme, anchoredPanel, closePanel } from "./popup-shell.js";
import { foldBlock } from "./bands/band.js";
import { valueEntry, whenValuesLand, valueBlock } from "./bands/value.js";
import { VERDICT_CSS, VERDICT_FIELDS, ALERT_FIELDS, verdictFields, alertFields, runbookBlock, platformBinaryOf, verdictInput, osBuildFor, fleetLine, linuxReleaseOf, macosEntry, verdictModel, verdictBlock } from "./bands/verdict.js";
import { PATTERN_CSS, patternModel, patternBlock } from "./bands/pattern.js";
import { meaningBlock } from "./bands/meaning.js";
import { everywhereBlock, workflowsBlock } from "./bands/workflows.js";
import { ENRICH_CSS, enrichModel, enrichBlock } from "./bands/enrich.js";
import { HOLD_CSS, BENIGN_CSS, pinFrom, eventSummary, heldPin, hold, holdBlock, recordPivot, noteSearch, attachButton, exclusionOffer, benignBlock, exclusionStrip } from "./bands/hold-and-benign.js";
export default { POPUP_CSS, PATTERN_CSS, VERDICT_CSS, ENRICH_CSS, HOLD_CSS, BENIGN_CSS, VERDICT_FIELDS, ALERT_FIELDS, alertFields, runbookBlock, pinFrom, eventSummary, heldPin, hold, holdBlock, recordPivot, noteSearch, attachButton, benignBlock, exclusionOffer, exclusionStrip, scopeLine, MISSING_PARAM_META, missingParamMeta, missingParamInputs, meaningBlock, valueEntry, valueBlock, whenValuesLand, verdictFields, verdictInput, platformBinaryOf, osBuildFor, linuxReleaseOf, macosEntry, verdictModel, fleetLine, verdictBlock, foldBlock, patternModel, patternBlock, everywhereBlock, workflowsBlock, enrichModel, enrichBlock, offerToPanel, panelLine, hostTheme, anchoredPanel, closePanel, fieldHash };
