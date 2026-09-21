// Share: #/share
// Export the user layer as a file, import someone else's. Merge keeps the
// newer of two notes on the same field; replace throws yours away. The
// runbooks ride in the same file (app/lib/share.js joins and splits the
// envelope) when the runbooks module is on, merged by rule with the newer
// one winning; a file holding one runbook imports on its own. Nothing
// leaves the browser except as the file you download.
//
//   importWords(result, mode) -> "Imported: bindings 10 added ...; notes 1 kept (yours newer or the same)."
//     exported so tests/coverage-view.test.js can hold the sentence without a DOM
//   runbookWords(result, mode) -> "; runbooks 2 added, 0 updated, 1 skipped; 1 rejected (why)"

import { h } from "../components/h.js";
import { plural } from "../components/links.js";
import { TERMS } from "../lib/platform.js";
import { callout } from "../components/callout.js";
import { titleBlock } from "../components/titleBlock.js";
import { headingNode } from "../lib/headings.js";
import { download } from "../components/download.js";
import * as modules from "../lib/modules.js";
import * as share from "../lib/share.js";
import * as runbooksStore from "../lib/runbooks-store.js";

// The import result in one sentence, per kind: what merged in, what was
// skipped because yours was newer or the same.
export function importWords(r, mode = "merge") {
  const b = r.bindings || { added: 0, updated: 0, kept: 0 };
  const n = r.notes || { added: 0, updated: 0, kept: 0 };
  if (mode === "replace") return `Replaced: ${plural(b.added, "binding", "bindings")} and ${plural(n.added, "note", "notes")} now in your catalogue, across ${plural(r.sourcetypes, TERMS.sourcetype, TERMS.sourcetypes)} and ${plural(r.concepts, "concept", "concepts")}.`;
  const part = (k, label) => `${label} ${k.added} added, ${k.updated} updated, ${k.kept} skipped`;
  const nothing = !b.added && !b.updated && !n.added && !n.updated;
  return `Imported: ${part(b, "bindings")}; ${part(n, "notes")}${b.kept || n.kept ? " (skipped: yours were newer or the same)" : ""}.${nothing ? " Nothing changed." : ""}`;
}

// The runbooks part of the import sentence, empty when the file carried none.
export function runbookWords(r, mode = "merge") {
  if (!r) return "";
  const rejected = r.rejected && r.rejected.length ? ` ${plural(r.rejected.length, "runbook", "runbooks")} rejected (${r.rejected.map((x) => `${x.id}: ${x.why}`).join("; ")}).` : "";
  if (mode === "replace") return ` Runbooks replaced: ${r.added} now kept.${rejected}`;
  return ` Runbooks ${r.added} added, ${r.updated} updated, ${r.kept} skipped.${rejected}`;
}

// The last import's words, kept across the re-render that follows the
// write (app.js redraws this route on any store change, and the import
// navigates here again to refresh the counts): a status line set before
// either would be gone before anyone read it.
let lastImport = null;

export function render(ctx) {
  const { catalogue } = ctx;
  const el = h("div", { class: "r-view r-view--share" });
  const user = catalogue.userLayer();
  const counts = catalogue.noteCount(); // notes by (sourcetype, field) and by concept, bindings by triple
  const sts = Object.keys(user.sourcetypes);
  const notes = counts.notes;
  const bindings = counts.bindings || 0;

  const status = h("p", { class: "r-secondary" }, lastImport ? lastImport.words : "");
  const withRunbooks = modules.on("runbooks");
  let runbooks = withRunbooks ? runbooksStore.list() : [];
  const runbookScope = withRunbooks ? h("span", null, plural(runbooks.length, "runbook", "runbooks")) : null;

  const exportBtn = h(
    "button",
    {
      type: "button",
      class: "r-btn r-btn--primary",
      disabled: !notes && !sts.length && !bindings && !runbooks.length,
      onClick: () => {
        runbooks = withRunbooks ? runbooksStore.list() : [];
        const doc = share.build({ catalogue: catalogue.exportUser(), runbooks });
        const stamp = new Date().toISOString().slice(0, 10);
        download(`reach-catalogue-${stamp}.json`, JSON.stringify(doc, null, 2));
        lastImport = null;
        status.textContent = `Exported ${plural(notes, "note", "notes")} (${counts.concepts} on shared concepts, which show on both SIEMs; ${notes - counts.concepts} on ${plural(sts.length, TERMS.sourcetype, TERMS.sourcetypes)}) and ${plural(bindings, "binding", "bindings")}${counts.setAside ? ` with ${counts.setAside} set aside` : ""}${withRunbooks ? ` and ${plural(runbooks.length, "runbook", "runbooks")}` : ""}.`;
      },
    },
    "Export",
  );

  // The store answers empty until its first load; the count and the
  // Export button catch up once it has.
  if (withRunbooks) {
    runbooksStore.load().then(() => {
      runbooks = runbooksStore.list();
      runbookScope.textContent = plural(runbooks.length, "runbook", "runbooks");
      if (runbooks.length) exportBtn.disabled = false;
    }).catch(() => {});
  }

  const file = h("input", { type: "file", accept: "application/json,.json", class: "r-share__file" });
  const mode = h(
    "select",
    { class: "r-input r-share__mode" },
    h("option", { value: "merge" }, "merge: newer note wins on a conflict"),
    h("option", { value: "replace" }, "replace: discard my notes, take theirs"),
  );
  const importBtn = h(
    "button",
    {
      type: "button",
      class: "r-btn",
      onClick: async () => {
        const f = file.files && file.files[0];
        if (!f) {
          status.textContent = "Pick a file first.";
          return;
        }
        if (mode.value === "replace" && !window.confirm("Replace every note, binding and runbook you have with the file's? This cannot be undone.")) return;
        try {
          const parts = share.read(JSON.parse(await f.text()));
          if (!parts.catalogue && !parts.runbooks) throw new Error("Not a Reach export (expected format reach-catalogue, reach-runbooks or reach-runbook).");
          let words = "";
          if (parts.catalogue) words += importWords(await catalogue.importUser(parts.catalogue, { mode: mode.value }), mode.value);
          if (parts.runbooks) {
            if (!withRunbooks) words += " The file's runbooks were left out: the Runbooks module is off.";
            else words += runbookWords(await runbooksStore.importDoc({ runbooks: parts.runbooks }, { mode: mode.value }), mode.value);
          }
          lastImport = { at: Date.now(), words: words.trim() };
          status.textContent = lastImport.words;
          ctx.navigate("share", { done: lastImport.at });
        } catch (err) {
          status.textContent = err && err.message ? err.message : String(err);
        }
      },
    },
    "Import",
  );

  // The action row: Export downloads; Import opens the file picker under
  // Import notes, where the merge mode sits.
  el.appendChild(
    titleBlock({
      kind: "page",
      h1: "Share",
      scope: [plural(notes, "note", "notes"), plural(bindings, "binding", "bindings"), plural(sts.length, TERMS.sourcetype, TERMS.sourcetypes), runbookScope, user.updated_at ? `last change ${new Date(user.updated_at).toLocaleString()}` : null],
      actions: [exportBtn, h("button", { type: "button", class: "r-btn", onClick: () => { file.scrollIntoView({ block: "center" }); file.click(); } }, "Import")],
    }),
  );
  el.appendChild(status);

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("export-notes"),
      h("p", { class: "r-secondary" }, `A JSON file of every note you have written (descriptions, roles, tags, sensitivity, owners, keyed by ${TERMS.sourcetype} and ${TERMS.field} or by concept) and every ${TERMS.field} you bound to a concept or set aside${withRunbooks ? ", with your runbooks (seeded and edited alike, one per rule)" : ""}. Packs and discovered facts are not in it. They are reproducible; your notes${withRunbooks ? ", bindings and runbooks" : " and bindings"} are not. Export, above, downloads it.`),
    ),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("import-notes"),
      h("p", { class: "r-secondary" }, `A teammate's export. Merge is per ${TERMS.field}: a note or binding only one of you made is kept, and where you both did, the newer one wins.${withRunbooks ? " Runbooks merge per rule the same way; a file with one runbook (Export runbook on its page) imports here too." : ""}`),
      h("div", { class: "r-share__box" }, file, mode, h("div", null, importBtn)),
      callout({
        kind: "note",
        label: "Team sync",
        body: `A shared store in your own ${TERMS.env} (a watchlist or a custom table, so nothing leaves your environment) is the next step; export/import is the same document, moved by hand.`,
      }),
    ),
  );

  return el;
}

export default { render, importWords, runbookWords };
