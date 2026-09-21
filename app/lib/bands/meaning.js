// The field's meaning with where it came from, and the inline editor that
// writes the catalogue's user layer. Its rules live in popup-shell.js
// POPUP_CSS (.reach-meaning, .reach-form, .reach-profile).
//
//   meaningBlock({ view, sourcetype, name, catalogue, appUrl, scopeEl, value, index, editable, fieldHref }) → Element
//       view: catalogue.fieldOn() result or null (nothing known yet)
//       renders the concept line, description + source chip, notes, format,
//       taxonomy, discovery's numbers and the edit toggle; the editor saves
//       via catalogue.annotate() and re-renders in place
//
// DOM module (uses h.js). Never fetches.

import { h } from "../../components/h.js";
import { measuredLine } from "../../components/profile.js";
import { ageLabel, STALE_PROFILE_SECONDS } from "../discovery.js";
import { PLATFORM, TERMS, isSentinel } from "../platform.js";
import { fieldHash } from "../popup-shell.js";

// After a save, "not catalogued" is no longer true. The popups pass their
// scope line element so it can be corrected in place.
function refreshScope(scopeEl, sourcetype, v) {
  if (!scopeEl || !sourcetype) return;
  const text = scopeEl.textContent;
  if (v && v.user && !v.pack && /not catalogued/.test(text)) scopeEl.textContent = text.replace("not catalogued", "your catalogue");
  else if (!(v && v.user) && !(v && v.pack) && /your catalogue/.test(text)) scopeEl.textContent = text.replace("your catalogue", "not catalogued");
}

const SENSITIVITIES = ["", "public", "internal", "confidential", "pii"];

const PLATFORM_WORD = { splunk: "Splunk", sentinel: "Sentinel" };

function sourceChip(source, view) {
  if (source === "user") {
    // A note made on the other SIEM (or another column of this one) is still yours; say where it was written.
    const wo = view && view.meaning && view.meaning.writtenOn;
    const where = wo ? (PLATFORM_WORD[wo.platform] || wo.platform) + (wo.container ? ` · ${wo.container} ${wo.column}` : "") : null;
    const from = wo ? (wo.platform === PLATFORM ? wo.container : PLATFORM_WORD[wo.platform] || wo.platform) : null; // name the table on this platform, the platform on the other
    return h("span", { class: "reach-chip", dataset: { basis: "user" }, title: where ? `Written on ${where}` : "" }, from ? `yours · from ${from}` : "yours");
  }
  if (source === "pack") {
    const basis = view && view.meaning && view.meaning.basis;
    const label = basis === "enrichment" ? `pack · AI-enriched${view.meaning.confidence ? " · " + view.meaning.confidence : ""}` : basis === "curated" ? "pack · curated" : "pack";
    return h("span", { class: "reach-chip", dataset: { basis: basis === "curated" ? "confirmed" : "pack" } }, label);
  }
  return null;
}

// Renders (and re-renders, after a save) the meaning for one field on one
// sourcetype. `catalogue` is the loaded catalogue module; `appUrl(path)`
// turns an app hash route into an absolute URL (content scripts pass
// chrome.runtime.getURL).
// `fieldHref` names the field page: the field's name in the first line
// becomes the link (the value page's Meaning band); `editable: false`
// leaves the note's editor to the field page.
export function meaningBlock({ view, sourcetype, name, catalogue, appUrl, scopeEl, value, index, editable = true, fieldHref = null }) {
  const root = h("div", { class: "reach-meaning" });
  let editing = false;

  function draw(v) {
    root.replaceChildren();
    if (editing) {
      root.appendChild(form(v));
      return;
    }
    const m = v && v.meaning;
    const nameEl = fieldHref ? h("a", { href: fieldHref, class: "reach-meaning__field" }, h("code", null, name)) : h("code", null, name);
    // The concept first, in plain words: "Principal ARN; on this table PrincipalArn".
    const c = v && v.concept;
    if (c) {
      const b = v.binding;
      root.appendChild(
        h(
          "div",
          { class: "reach-meaning__concept" },
          h("b", null, c.label),
          `; on this ${TERMS.sourcetype} `,
          nameEl,
          b && b.alias_of ? [" (alias of ", h("code", null, b.alias_of), ")"] : null,
        ),
      );
      if (b && b.note) root.appendChild(h("div", { class: "reach-meaning__notes" }, b.note));
    } else if (fieldHref) {
      root.appendChild(h("div", { class: "reach-meaning__concept" }, nameEl, ` on this ${TERMS.sourcetype}`));
    }
    if (m && m.description) {
      root.appendChild(h("div", { class: "reach-meaning__text" }, m.description, " ", sourceChip(m.source, v)));
    } else {
      root.appendChild(
        h("div", { class: "reach-row__body reach-row__body--muted" }, v && v.pack ? "In the catalogue, but no description yet." : sourcetype ? `Not described on ${sourcetype} yet.` : "Not described yet."),
      );
    }
    // The notes, under a description or alone; a note of yours under the pack's description says so.
    if (m && m.notes) root.appendChild(h("div", { class: "reach-meaning__notes" }, m.notes, m.notesSource === "user" ? [" ", sourceChip("user", v)] : null));
    // The values' format, in the pack's words (values.js): the synopsis line of the field's dictionary entry.
    const dict = v && v.dictionary;
    if (dict && dict.format) root.appendChild(h("div", { class: "reach-meaning__tags reach-meaning__format" }, "Format ", h("span", { class: "reach-meaning__formatText" }, dict.format)));
    const t = v && v.taxonomy;
    const bits = [];
    if (t && t.role) bits.push(h("span", null, "role ", h("code", null, t.role)));
    if (t && t.tags && t.tags.length) bits.push(h("span", null, "tags ", ...t.tags.flatMap((x, i) => [i ? ", " : "", h("code", null, x)])));
    if (t && t.sensitivity) bits.push(h("span", null, "sensitivity ", h("code", null, t.sensitivity)));
    if (t && t.owner) bits.push(h("span", null, "owner ", h("code", null, t.owner)));
    const cim = v && v.cim && !isSentinel() ? v.cim : null; // CIM is Splunk's; a concept carries it for the Splunk bindings
    if (cim && cim.data_models && cim.data_models.length) bits.push(h("span", null, "CIM ", cim.data_models.join(", ")));
    else if (cim && cim.targets && cim.targets.length) bits.push(h("span", null, "CIM as ", ...cim.targets.flatMap((x, i) => [i ? ", " : "", h("code", null, x)])));
    if (bits.length) root.appendChild(h("div", { class: "reach-meaning__tags" }, ...bits.flatMap((b, i) => [i ? " · " : "", b])));

    // Discovery's numbers for this field on this sourcetype, when measured.
    // Every top value carries its count and share, and the line says when
    // and over what sample it was measured: a bare ranked list reads as a
    // verdict ("this value is rare"), and these are counts, not verdicts.
    // A numeric range is only meaningful for a quantity; for an identifier
    // (PIDs, hashes, ids, high-cardinality numerics) it is noise.
    const p = v && v.profile;
    if (p) {
      const fill = p.fill === null ? "" : `${Math.round(p.fill * 100)}% fill · `;
      const role = (v.taxonomy && v.taxonomy.role) || "";
      const quantity = p.numeric && p.min !== null && !/id|identifier|hash|pid|thread|tree|agent|customer|register/i.test(role) && p.distinct <= 1000;
      const top = (p.top || []).slice(0, 3);
      root.appendChild(
        h(
          "div",
          { class: "reach-meaning__tags" },
          `${fill}${p.distinct} distinct${p.distinct_exact ? "" : " (approx.)"}`,
          quantity ? ` · ${p.min}–${p.max}` : "",
        ),
      );
      if (top.length) {
        root.appendChild(
          h(
            "div",
            { class: "reach-meaning__tags reach-profile__top" },
            "top ",
            ...top.flatMap((t, i) => [
              i ? " " : "",
              h("span", { class: "reach-profile__val", title: t.value }, h("code", null, t.value.length > 28 ? t.value.slice(0, 27) + "…" : t.value), h("span", { class: "reach-profile__n" }, ` ${t.count.toLocaleString()}${p.count ? ` · ${Math.round((t.count / p.count) * 100)}%` : ""}`)),
            ]),
          ),
        );
      }
      const age = p.measured_at ? Math.round((Date.now() - new Date(p.measured_at).getTime()) / 1000) : null;
      const old = age !== null && age >= STALE_PROFILE_SECONDS;
      root.appendChild(h("div", { class: `reach-meaning__tags reach-profile__when${old ? " reach-profile__when--old" : ""}` }, measuredLine(p), old ? `; ${ageLabel(age)}, re-profile for current numbers` : ""));
    }
    // The feed itself: not in the last inventory that covered its index.
    const stRec = sourcetype && catalogue && catalogue.sourcetype ? catalogue.sourcetype(sourcetype) : null;
    if (stRec && stRec.missingSince) {
      root.appendChild(h("div", { class: "reach-row__body reach-row__body--warn" }, `${sourcetype} was not in the last inventory; nothing arrived in its window since ${new Date(stRec.missingSince).toLocaleDateString()}.`));
    }

    const actions = h("div", { class: "reach-form__row" });
    if (sourcetype && editable) {
      actions.appendChild(
        h(
          "button",
          {
            type: "button",
            class: "reach-edit",
            onClick: (e) => {
              e.preventDefault();
              e.stopPropagation();
              editing = true;
              draw(v);
            },
          },
          v && v.user ? "✎ edit your note" : m && m.description ? "✎ override" : "＋ describe this field",
        ),
      );
    }
    if (appUrl) {
      actions.appendChild(h("a", { class: "reach-link", href: appUrl(fieldHash(name, { st: sourcetype, value, index })), target: "_blank", rel: "noopener" }, "Open in Reach →"));
    }
    if (actions.childElementCount) root.appendChild(actions);
  }

  function form(v) {
    const ann = (v && v.user) || {};
    const desc = h("textarea", { placeholder: `What this ${TERMS.field} means on this ${TERMS.sourcetype}`, value: ann.description || "" });
    const notes = h("input", { type: "text", placeholder: "notes (optional)", value: ann.notes || "" });
    const tags = h("input", { type: "text", placeholder: "tags, comma-separated", value: (ann.tags || []).join(", ") });
    const role = h("input", { type: "text", placeholder: "role (e.g. ip, hash, user_id)", value: ann.role || "" });
    const sens = h("select", null, SENSITIVITIES.map((s) => h("option", { value: s, selected: (ann.sensitivity || "") === s }, s || "sensitivity")));
    const owner = h("input", { type: "text", placeholder: "owner", value: ann.owner || "" });
    const status = h("span", { class: "reach-row__body--muted" });
    const stop = (e) => e.stopPropagation();
    const save = h("button", { type: "button", class: "reach-btn reach-btn--primary" }, "Save");
    const cancel = h("button", { type: "button", class: "reach-btn" }, "Cancel");
    const clear = ann.updated_at ? h("button", { type: "button", class: "reach-btn" }, "Remove note") : null;

    save.addEventListener("click", async (e) => {
      e.stopPropagation();
      save.disabled = true;
      try {
        await catalogue.annotate(sourcetype, name, {
          description: desc.value.trim(),
          notes: notes.value.trim(),
          tags: tags.value.split(",").map((s) => s.trim()).filter(Boolean),
          role: role.value.trim(),
          sensitivity: sens.value,
          owner: owner.value.trim(),
        });
        editing = false;
        const next = catalogue.fieldOn(sourcetype, name);
        refreshScope(scopeEl, sourcetype, next);
        draw(next);
      } catch (err) {
        status.textContent = err && err.message ? err.message : String(err);
        save.disabled = false;
      }
    });
    cancel.addEventListener("click", (e) => {
      e.stopPropagation();
      editing = false;
      draw(v);
    });
    if (clear) {
      clear.addEventListener("click", async (e) => {
        e.stopPropagation();
        await catalogue.annotate(sourcetype, name, { description: null, notes: null, tags: null, role: null, sensitivity: null, owner: null });
        editing = false;
        const next = catalogue.fieldOn(sourcetype, name);
        refreshScope(scopeEl, sourcetype, next);
        draw(next);
      });
    }

    const f = h(
      "div",
      { class: "reach-form", onClick: stop, onKeydown: stop, onKeyup: stop, onMousedown: stop },
      h("label", null, `${name} on ${sourcetype}`),
      desc,
      notes,
      h("div", { class: "reach-form__row" }, role, sens),
      h("div", { class: "reach-form__row" }, tags, owner),
      h("div", { class: "reach-form__actions" }, save, cancel, clear, status),
    );
    setTimeout(() => desc.focus(), 0);
    return f;
  }

  draw(view);
  // The format line waits on the pack's values sidecar; redraw once it
  // lands, unless the editor is open. The block may still be detached
  // then (the popups append their section last), so no connectivity check.
  if (sourcetype && catalogue && typeof catalogue.valuesReady === "function" && !catalogue.valuesReady(sourcetype)) {
    catalogue.loadValues(sourcetype).then(() => {
      if (editing) return;
      const next = catalogue.fieldOn(sourcetype, name);
      if (next) draw(next);
    });
  }
  return root;
}
