// holding: what the analyst held. Two groups, two stores, one order:
//
//   Held     the current investigation's pins (app/lib/notebook.js): a value
//            the analyst pressed Hold on, with where it came from.
//   Pinned   app/lib/pinned.js: the environment. Kept across sessions.
//
// A clicked value is not held: the click is a hop on the trail (app.js)
// and its value rides in the route, never in a store. The tab's fact store
// (app/lib/investigation.js) is written by the same three gestures that
// write the notebook (Hold, Attach, this rail's add form), so the drawer
// binds what was held; nothing clicked is drawn here or kept there.
//
// On the stacked surfaces the component is the frame's third row: one
// line, `Holding 2 · aid=abc123 · SHA256HashData=8ae6… ▸`, drawn only
// while something is held or pinned; a tap opens the rail in place (Held,
// Pinned, the notebook link, Add). On the wide tab the rail is open in
// the side column and the line is not drawn (components.css, surfaces).
//
// The index (the workspace on Sentinel) is scope, kept under Settings
// (app/lib/scope.js): typing it into the Add form sets the Settings value.
//
//   const el = holding();   el.count() → held plus pinned; el.refreshCopy()

import { h, replace } from "./h.js";
import { foldBody } from "./foldBody.js";
import * as investigation from "../lib/investigation.js";
import * as pinned from "../lib/pinned.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";
import * as notebook from "../lib/notebook.js";
import { displayTitle } from "../lib/notebook-md.js";
import { copy } from "../lib/copy.js";
import { PLATFORM } from "../lib/platform.js";
import { midEllipsis } from "./titleBlock.js";

// A long value middle-ellipsizes like the frame's line, the full value in title.
const VAL_MAX = 20;

function chip(k, v, { muted = false, title = "", actions = [], href = null } = {}) {
  const shown = midEllipsis(v, VAL_MAX);
  const body = [h("code", null, k), h("span", { "aria-hidden": "true" }, "="), h("span", { class: "r-holding__val", title: shown === v ? null : v }, shown)];
  return h(
    "span",
    { class: ["r-holding__chip", muted && "r-holding__chip--muted"], title: title || `${k}=${v}` },
    href ? h("a", { class: "r-holding__link", href }, body) : body,
    actions,
  );
}

function action(label, ariaLabel, onClick, extra = "", title = "") {
  return h("button", { type: "button", class: ["r-holding__act", extra], "aria-label": ariaLabel, title: title || null, onClick }, label);
}

// The current investigation's pins, one per field and value, in hop order.
export function heldPins() {
  const inv = notebook.current();
  if (!inv) return [];
  const seen = new Set();
  const out = [];
  for (const e of inv.entries) {
    if (e.kind !== "pin") continue;
    const key = `${e.field}=${e.value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(e);
  }
  return out;
}

export function holding() {
  const lineCount = h("span", { class: "r-holding__count" });
  const lineSummary = h("span", { class: "r-holding__summary" });
  const heldFacts = h("div", { class: "r-holding__facts" });
  const pinFacts = h("div", { class: "r-holding__facts" });

  const keyInput = h("input", { class: "r-field__input", type: "text", placeholder: copy("holding.key"), "aria-label": "Fact key", autocomplete: "off", spellcheck: "false" });
  const valInput = h("input", { class: "r-field__input", type: "text", placeholder: copy("holding.value"), "aria-label": "Fact value", autocomplete: "off", spellcheck: "false" });

  function take() {
    const k = keyInput.value.trim();
    const v = valInput.value.trim();
    if (!k || !v) return null;
    keyInput.value = "";
    valInput.value = "";
    keyInput.focus();
    if (scope.isScopeKey(k)) {
      scope.setIndex(v);
      return null;
    }
    return [k, v];
  }

  // Open/close the add form from either control, clearing its inputs once
  // closed so a mistaken open never leaves half-typed text behind.
  function setAdding(on) {
    el.classList.toggle("is-adding", on);
    addToggle.setAttribute("aria-expanded", on ? "true" : "false");
    addToggle.textContent = on ? "Close" : "Add";
    if (on) {
      keyInput.focus();
    } else {
      keyInput.value = "";
      valInput.value = "";
    }
  }

  const addForm = h(
    "form",
    {
      class: "r-holding__add",
      onSubmit: (e) => {
        e.preventDefault();
        const kv = take();
        if (!kv) return;
        // The add form's Hold is a Hold: the notebook pin, with the
        // platform as its provenance, and the tab's fact store so the
        // drawer binds it. The Held group draws the notebook's pins.
        investigation.set(kv[0], kv[1]);
        notebook.record({ field: kv[0], value: kv[1], from: { platform: PLATFORM } }).catch(() => {});
      },
      onKeydown: (e) => {
        if (e.key !== "Escape") return;
        e.preventDefault();
        setAdding(false);
        addToggle.focus();
      },
    },
    keyInput,
    valInput,
    h("button", { type: "submit", class: "r-holding__addbtn" }, "Hold"),
    h(
      "button",
      {
        type: "button",
        class: "r-holding__addbtn",
        title: "Keep it across sessions, this browser only",
        onClick: () => {
          const kv = take();
          if (kv) pinned.set(kv[0], kv[1]);
        },
      },
      "Pin",
    ),
    h(
      "button",
      {
        type: "button",
        class: "r-holding__addcancel",
        "aria-label": "Close the add form",
        onClick: () => {
          setAdding(false);
          addToggle.focus();
        },
      },
      "Cancel",
    ),
  );

  // Narrow widths hide the add form behind this (components.css); wide
  // widths show the form and hide the toggle. Its own label says which way
  // a click takes it, since at narrow widths it is the only control.
  const addToggle = h(
    "button",
    {
      type: "button",
      class: "r-holding__addtoggle",
      "aria-expanded": "false",
      onClick: () => setAdding(!el.classList.contains("is-adding")),
    },
    "Add",
  );
  const hint = h("p", { class: "r-muted r-holding__hint" }, copy("holding.hint"));
  const heldLabel = h("p", { class: "r-holding__label" }, "Held");
  const pinLabel = h("p", { class: "r-holding__label" }, copy("holding.pinned"));
  // Add rides the Held label's row, not a row of its own: a control alone
  // in a band reads as an empty band (components.css band rhythm).
  const heldLabelRow = h("div", { class: "r-holding__labelrow" }, heldLabel, addToggle);
  const heldGroup = h("div", { class: "r-holding__group" }, heldLabelRow, heldFacts);
  const pinGroup = h("div", { class: "r-holding__group" }, pinLabel, pinFacts);
  const nbLink = h("a", { class: "r-holding__notebook", href: "#/notebook" });

  function renderNotebook() {
    const inv = notebook.current();
    if (!inv) {
      nbLink.textContent = "notebook: nothing current";
      nbLink.title = "The next Hold starts an investigation";
      return;
    }
    const pins = inv.entries.filter((e) => e.kind === "pin").length;
    nbLink.textContent = `in notebook: ${displayTitle(inv)}${pins ? ` (${pins})` : ""}`;
    nbLink.title = `${pins} held ${pins === 1 ? "value" : "values"} with provenance; open the notebook`;
  }

  let n = 0;

  function render() {
    const held = heldPins();
    const pins = pinned.all();
    const tab = investigation.all();
    const shadowed = new Map(facts.shadows(pins, tab).map((s) => [s.key, s]));

    replace(
      heldFacts,
      held.length
        ? held.map((e) => {
            const from = e.from || {};
            const where = [from.container ? `on ${from.container}` : null, from.scope ? `in ${from.scope}` : null].filter(Boolean).join(" ");
            const href = from.container ? `#/v/${encodeURIComponent(e.value)}?st=${encodeURIComponent(from.container)}&name=${encodeURIComponent(e.field)}` : null;
            return chip(e.field, e.value, {
              title: where ? `${e.field}=${e.value} ${where}` : "",
              href,
              actions: [
                action(
                  "×",
                  `Release ${e.field}=${e.value}`,
                  () => {
                    notebook
                      .removeEntry(e.id)
                      .then(() => investigation.remove(e.field))
                      .catch(() => {});
                  },
                  "r-holding__act--rm",
                  "Release from this investigation",
                ),
              ],
            });
          })
        : h("p", { class: "r-muted" }, copy("holding.empty")),
    );

    const pinEntries = Object.entries(pins);
    replace(
      pinFacts,
      pinEntries.map(([k, v]) => {
        const s = shadowed.get(k);
        return chip(k, v, {
          muted: Boolean(s),
          title: s ? `The held ${k}=${s.held} wins over this pin while it lasts.` : "",
          actions: [
            action("unpin", `Unpin ${k}: hold it in the current investigation instead`, () => {
              pinned.remove(k);
              if (!(k in tab)) investigation.set(k, v);
              notebook.record({ field: k, value: v, from: { platform: PLATFORM } }).catch(() => {});
            }),
            action("×", `Forget ${k}`, () => pinned.remove(k), "r-holding__act--rm"),
          ],
        });
      }),
    );
    pinGroup.hidden = !pinEntries.length;

    n = held.length + pinEntries.length;
    lineCount.textContent = String(n);
    const items = [...held.map((e) => `${e.field}=${midEllipsis(e.value, 12)}`), ...pinEntries.map(([k, v]) => `${k}=${midEllipsis(v, 12)}`)];
    lineSummary.textContent = items.join(" · ");
    el.classList.toggle("r-holding--empty", !n);
    line.title = items.length ? items.join(", ") : "";
  }

  function setOpen(on) {
    el.classList.toggle("is-open", on);
    line.setAttribute("aria-expanded", on ? "true" : "false");
  }

  const line = h(
    "button",
    { type: "button", class: "r-holding__line", "aria-expanded": "false", onClick: () => setOpen(!el.classList.contains("is-open")) },
    h("span", { class: "r-holding__word" }, "Holding"),
    lineCount,
    h("span", { class: "r-holding__dot", "aria-hidden": "true" }, "·"),
    lineSummary,
    h("span", { class: "r-holding__caret", "aria-hidden": "true" }, "▸"),
  );

  // The collapsed line already says "Holding N"; the opened body does not
  // repeat it, and Add rides the Held label's row instead of a row of its
  // own. One block when open: this header, this body, then the separator
  // (components.css, foldBody.js), never a rule between the two.
  const body = foldBody(
    "div",
    { class: "r-holding__body" },
    heldGroup,
    pinGroup,
    nbLink,
    addForm,
    hint,
  );

  const el = h("section", { class: "r-holding", "aria-label": "What you are holding" }, line, body);

  facts.subscribe(render);
  notebook.subscribe(() => {
    renderNotebook();
    render();
  });
  notebook
    .load()
    .then(() => {
      renderNotebook();
      render();
    })
    .catch(() => {});
  render();
  renderNotebook();

  el.count = () => n;
  el.setOpen = setOpen;
  // The panel lives for the session, so its copy.js lines are re-asked
  // when the surface changes (app.js): placeholders, labels, the hint,
  // and the empty line through a render.
  el.refreshCopy = () => {
    keyInput.placeholder = copy("holding.key");
    valInput.placeholder = copy("holding.value");
    pinLabel.textContent = copy("holding.pinned");
    hint.textContent = copy("holding.hint");
    render();
  };
  return el;
}

export default holding;
