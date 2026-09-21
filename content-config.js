// What Reach registers on an approved origin: the one list the popup uses
// when the user clicks enable and the worker uses at startup and on a
// permission grant. popup.html loads it as a plain script and reads the
// names below as globals; the module worker imports it and reads
// globalThis.REACH_CONTENT_CONFIG, published at the end, so one file
// serves both loaders and a change here reaches every registration path.

const CONTENT_SCRIPT_ID_PREFIX = "reach-json-tree-";
const CONTENT_SCRIPTS = ["json-tree-fields.js", "value-popup.js", "field-info-popup.js", "discovery-agent.js", "search-history.js"];

// Microsoft Sentinel: the Logs blade is an iframe from a second origin
// (docs/SENTINEL.md §5.6), so the portal origin stands for the pair of
// match patterns, and the blade script runs in every frame.
const SENTINEL = {
  origin: "https://portal.azure.com",
  patterns: ["https://portal.azure.com/*", "https://*.reactblade.portal.azure.net/*"],
  entries: [
    { id: "reach-sentinel-portal", matches: ["https://portal.azure.com/*"], js: ["sentinel-workspace.js"], runAt: "document_idle" },
    { id: "reach-sentinel-blade", matches: ["https://*.reactblade.portal.azure.net/*"], js: ["sentinel-grid.js"], runAt: "document_idle", allFrames: true },
  ],
};

globalThis.REACH_CONTENT_CONFIG = Object.freeze({ CONTENT_SCRIPT_ID_PREFIX, CONTENT_SCRIPTS, SENTINEL });
