// The share envelope: one file carrying the user layer (catalogue.js
// exportUser, format reach-catalogue) and the runbooks (runbooks-store.js,
// format reach-runbooks) together, so a teammate's export brings both
// back. Each section keeps its own format and its own import checks; this
// module only joins and splits them.
//
//   build({ catalogue, runbooks })  → the catalogue document with a runbooks list on it (absent when empty)
//   read(doc)                       → { catalogue: doc | null, runbooks: [] | null }
//                                     catalogue: the reach-catalogue document without its runbooks key
//                                     runbooks: the list from a reach-catalogue, reach-runbooks or one reach-runbook file
//
// Plain ES module. No DOM, no storage.

import { runbooksIn } from "./runbooks-store.js";

export const CATALOGUE_FORMAT = "reach-catalogue";

export function build({ catalogue = null, runbooks = [] } = {}) {
  const out = catalogue && typeof catalogue === "object" ? { ...catalogue } : { format: CATALOGUE_FORMAT, version: 2, exported_at: new Date().toISOString(), sourcetypes: {}, concepts: {}, bindings: [] };
  delete out.runbooks;
  if (Array.isArray(runbooks) && runbooks.length) out.runbooks = JSON.parse(JSON.stringify(runbooks));
  return out;
}

export function read(raw) {
  const doc = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!doc || typeof doc !== "object") return { catalogue: null, runbooks: null };
  const runbooks = runbooksIn(doc);
  if (doc.format !== CATALOGUE_FORMAT) return { catalogue: null, runbooks };
  const { runbooks: _dropped, ...catalogue } = doc;
  return { catalogue, runbooks };
}

export default { CATALOGUE_FORMAT, build, read };
