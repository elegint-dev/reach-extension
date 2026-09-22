// annotation: the app-side view/editor for what the catalogue says about
// one field on one sourcetype (or about a sourcetype itself). The in-Splunk
// popups have their own compact version in app/lib/popup-ui.js; this one
// uses the app's design tokens and shows every layer that contributed.
//
//   annotation({ view, sourcetype, name, catalogue, onSaved, typeHead })
//   sourcetypeAnnotation({ record, catalogue, onSaved })
//   typeHead { kind, label, body }: the field page's own taxonomy-type
//   callout (SPEC 6.4), drawn first, above the description. Nothing else
//   passes it, so no other caller of annotation() draws it.
//   Both return an element that carries edit(), which opens the form.

import { h } from "./h.js";
import { chip } from "./chip.js";
import { callout } from "./callout.js";
import { PLATFORM, TERMS } from "../lib/platform.js";
import { heading } from "../lib/headings.js";

const SENSITIVITIES = ["", "public", "internal", "confidential", "pii"];

const PLATFORM_WORD = { splunk: "Splunk", sentinel: "Sentinel" };

// Where a note keyed by concept was written, when not here: the table on
// this platform, or the other platform's name with its table.
export function writtenOnWords(wo) {
  if (!wo) return "";
  return wo.platform === PLATFORM ? String(wo.container) : `${PLATFORM_WORD[wo.platform] || wo.platform} ${wo.container}`;
}

function sourceChip(source, view) {
  if (source === "user") {
    // A note keyed by concept may have been written on the other SIEM, or on another column of this one.
    const wo = view && view.meaning && view.meaning.writtenOn;
    return chip({ kind: "trust", value: "confirmed", text: wo ? `yours · from ${writtenOnWords(wo)}` : "yours", title: wo ? `Written on ${wo.container} ${wo.column}` : undefined });
  }
  if (source === "pack") {
    const basis = view && view.meaning && view.meaning.basis;
    if (basis === "enrichment") return chip({ kind: "trust", value: "suggested", text: "pack · AI-enriched", confidence: view.meaning.confidence || undefined });
    if (basis === "curated" || basis === "decode_table" || basis === "ta") return chip({ kind: "trust", value: "confirmed", text: `pack · ${basis.replace("_", " ")}` });
    return chip({ kind: "trust", value: "asserted", text: "pack" });
  }
  if (source === "falcon") return chip({ kind: "trust", value: "asserted", text: "your imported Falcon dictionary" });
  return null;
}

function field(label, input) {
  return h("label", { class: "r-ann__field" }, h("span", { class: "r-ann__label" }, label), input);
}

export function annotation({ view, sourcetype, name, catalogue, onSaved, compact = false, typeHead = null }) {
  const root = h("div", { class: "r-ann" });
  let editing = false;

  function draw(v) {
    root.replaceChildren();
    if (editing) return root.appendChild(form(v));
    if (typeHead) root.appendChild(callout({ kind: typeHead.kind, label: typeHead.label, body: typeHead.body }));
    const m = v && v.meaning;
    // Compact: the page already shows the pack's meaning; offer only the
    // button until the user writes something.
    if (compact && !(v && v.user)) {
      root.appendChild(
        h(
          "p",
          null,
          h(
            "button",
            {
              type: "button",
              class: "r-btn r-btn--small",
              onClick: () => {
                editing = true;
                draw(v);
              },
            },
            m && m.description ? `Override on ${sourcetype}` : `Describe on ${sourcetype}`,
          ),
        ),
      );
      return;
    }
    // The concept first: "Principal ARN; on this table PrincipalArn".
    const c = v && v.concept;
    if (c) {
      const b = v.binding;
      root.appendChild(h("p", { class: "r-ann__concept" }, h("b", null, c.label), `; on this ${TERMS.sourcetype} `, h("code", null, name), b && b.alias_of ? [" (alias of ", h("code", null, b.alias_of), ")"] : null));
      if (b && b.note) root.appendChild(h("p", { class: "r-ann__notes r-secondary" }, b.note));
    }
    if (m && m.description) {
      root.appendChild(h("p", { class: "r-ann__desc" }, m.description, " ", sourceChip(m.source, v)));
      const under = m.source === "user" ? (v.packField && v.packField.description) || (v.pack && v.pack.meaning && v.pack.meaning.description) : null;
      if (under) root.appendChild(h("details", { class: "r-ann__under" }, h("summary", null, heading("pack-description")), h("p", { class: "r-secondary" }, under)));
    } else {
      root.appendChild(h("p", { class: "r-ann__desc r-muted" }, v && v.pack ? "In the catalogue, but no description yet." : `Nothing describes ${name} on ${sourcetype} yet.`));
    }
    // The notes, with or without a description above them: a note of yours
    // under the pack's description carries its own chip.
    if (m && m.notes) root.appendChild(h("p", { class: "r-ann__notes r-secondary" }, m.notes, m.notesSource === "user" ? [" ", sourceChip("user", v)] : null));
    const t = (v && v.taxonomy) || {};
    const bits = [];
    if (t.role) bits.push(h("span", null, "role ", h("code", null, t.role), t.roleSource === "user" ? h("span", { class: "r-muted" }, " (yours)") : null));
    if (t.tags && t.tags.length) bits.push(h("span", null, "tags ", ...t.tags.flatMap((x, i) => [i ? " " : "", h("code", null, x)])));
    if (t.sensitivity) bits.push(h("span", null, "sensitivity ", h("code", null, t.sensitivity)));
    if (t.owner) bits.push(h("span", null, "owner ", h("code", null, t.owner)));
    if (bits.length) root.appendChild(h("p", { class: "r-ann__tax r-secondary" }, ...bits.flatMap((b, i) => [i ? " · " : "", b])));
    const wrote = v && v.user && v.user.updated_at && (v.user.description || v.user.notes || v.user.role || (v.user.tags && v.user.tags.length) || v.user.sensitivity || v.user.owner);
    if (wrote) root.appendChild(h("p", { class: "r-muted r-ann__when" }, `your note · ${new Date(v.user.updated_at).toLocaleString()}`));
    if (sourcetype) {
      root.appendChild(
        h(
          "p",
          null,
          h(
            "button",
            {
              type: "button",
              class: "r-btn r-btn--small",
              onClick: () => {
                editing = true;
                draw(v);
              },
            },
            v && v.user ? "Edit your note" : m && m.description ? "Override" : `Describe this ${TERMS.field}`,
          ),
        ),
      );
    }
  }

  function form(v) {
    const ann = (v && v.user) || {};
    const desc = h("textarea", { class: "r-input", rows: 3, placeholder: `What ${name} means on ${sourcetype}`, value: ann.description || "" });
    const notes = h("input", { class: "r-input", type: "text", placeholder: "notes: hunting tips, gotchas", value: ann.notes || "" });
    const tags = h("input", { class: "r-input", type: "text", placeholder: "tags, comma-separated", value: (ann.tags || []).join(", ") });
    const role = h("input", { class: "r-input", type: "text", placeholder: "role (ip, hash, user_id…)", value: ann.role || (v && v.taxonomy && v.taxonomy.role) || "" });
    const sens = h("select", { class: "r-input" }, SENSITIVITIES.map((s) => h("option", { value: s, selected: (ann.sensitivity || "") === s }, s || "sensitivity -")));
    const owner = h("input", { class: "r-input", type: "text", placeholder: "owner (team or person)", value: ann.owner || "" });
    const status = h("span", { class: "r-muted" });
    const save = h("button", { type: "button", class: "r-btn r-btn--primary" }, "Save");
    const cancel = h("button", { type: "button", class: "r-btn" }, "Cancel");
    const clear = ann.updated_at ? h("button", { type: "button", class: "r-btn r-btn--danger" }, "Remove your note") : null;
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        await catalogue.annotate(sourcetype, name, {
          description: desc.value.trim(),
          notes: notes.value.trim(),
          tags: tags.value.split(",").map((s) => s.trim()).filter(Boolean),
          role: role.value.trim() === ((v && v.taxonomy && v.taxonomy.roleSource === "pack" && v.taxonomy.role) || "") ? "" : role.value.trim(),
          sensitivity: sens.value,
          owner: owner.value.trim(),
        });
        editing = false;
        const next = catalogue.fieldOn(sourcetype, name);
        draw(next);
        if (onSaved) onSaved(next);
      } catch (err) {
        status.textContent = err && err.message ? err.message : String(err);
        save.disabled = false;
      }
    });
    cancel.addEventListener("click", () => {
      editing = false;
      draw(v);
    });
    if (clear) {
      clear.addEventListener("click", async () => {
        clear.disabled = true;
        try {
          await catalogue.annotate(sourcetype, name, { description: null, notes: null, tags: null, role: null, sensitivity: null, owner: null });
          editing = false;
          const next = catalogue.fieldOn(sourcetype, name);
          draw(next);
          if (onSaved) onSaved(next);
        } catch (err) {
          status.textContent = err && err.message ? err.message : String(err);
          clear.disabled = false;
        }
      });
    }
    const f = h(
      "div",
      { class: "r-ann__form" },
      field("Description", desc),
      field("Notes", notes),
      h("div", { class: "r-ann__row" }, field("Role", role), field("Sensitivity", sens)),
      h("div", { class: "r-ann__row" }, field("Tags", tags), field("Owner", owner)),
      h("div", { class: "r-ann__actions" }, save, cancel, clear, status),
    );
    setTimeout(() => desc.focus(), 0);
    return f;
  }

  // The title block's Note action opens the editor from outside.
  root.edit = () => {
    editing = true;
    draw(catalogue && sourcetype ? catalogue.fieldOn(sourcetype, name) || view : view);
  };

  draw(view);
  return root;
}

export function sourcetypeAnnotation({ record, catalogue, onSaved }) {
  const root = h("div", { class: "r-ann" });
  let editing = false;
  let current = record;
  const name = record.name;

  function draw(rec) {
    current = rec;
    root.replaceChildren();
    if (editing) return root.appendChild(form(rec));
    root.appendChild(h("p", { class: rec.description ? "r-ann__desc" : "r-ann__desc r-muted" }, rec.description || `No description for this ${TERMS.sourcetype} yet.`));
    if (rec.tags && rec.tags.length) root.appendChild(h("p", { class: "r-secondary" }, "tags ", ...rec.tags.flatMap((x, i) => [i ? " " : "", h("code", null, x)])));
    root.appendChild(
      h(
        "p",
        null,
        h(
          "button",
          {
            type: "button",
            class: "r-btn r-btn--small",
            onClick: () => {
              editing = true;
              draw(rec);
            },
          },
          rec.description ? "Edit" : `Describe this ${TERMS.sourcetype}`,
        ),
      ),
    );
  }

  function form(rec) {
    const desc = h("textarea", { class: "r-input", rows: 3, placeholder: `What ${name} is: the feed, the product, who owns it`, value: rec.description || "" });
    const tags = h("input", { class: "r-input", type: "text", placeholder: "tags, comma-separated", value: (rec.tags || []).join(", ") });
    const disc = h("input", { class: "r-input", type: "text", placeholder: "record-type field (e.g. eventName, EventCode)", value: rec.discriminator || "" });
    const status = h("span", { class: "r-muted" });
    const save = h("button", { type: "button", class: "r-btn r-btn--primary" }, "Save");
    const cancel = h("button", { type: "button", class: "r-btn" }, "Cancel");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        await catalogue.annotateSourcetype(name, { description: desc.value.trim(), tags: tags.value.split(",").map((s) => s.trim()).filter(Boolean), discriminator: disc.value.trim() });
        editing = false;
        const next = catalogue.sourcetype(name) || { name };
        draw(next);
        if (onSaved) onSaved(next);
      } catch (err) {
        status.textContent = err && err.message ? err.message : String(err);
        save.disabled = false;
      }
    });
    cancel.addEventListener("click", () => {
      editing = false;
      draw(rec);
    });
    return h(
      "div",
      { class: "r-ann__form" },
      field("Description", desc),
      h("div", { class: "r-ann__row" }, field("Tags", tags), field("Record-type field", disc)),
      h("div", { class: "r-ann__actions" }, save, cancel, status),
    );
  }

  // The page's Describe action opens the editor from the title block.
  root.edit = () => {
    editing = true;
    draw(current);
  };

  draw(record);
  return root;
}

export default { annotation, sourcetypeAnnotation };
