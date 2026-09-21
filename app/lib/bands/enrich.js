// The enrichment band: one row per applicable source from the registry
// (app/lib/enrich.js), drawn by its mode.
//
//   ENRICH_CSS                        the rows' stylesheet, for the app's value page (POPUP_CSS carries it too)
//   enrichModel(offers) → [{ id, label, mode, allowed, why }]   (pure)
//   enrichBlock({ value, offers, ask, settingsUrl, hold, platform }) → Element | null
//       see the notes above enrichBlock for the offer/refuse pattern, the
//       settings link and the result actions
//
// DOM module (uses h.js). A bundle row reads the extension's own file; a
// fetch row sends nothing until its own button takes a trusted click.

import { h } from "../../components/h.js";
import { PLATFORM, termsFor } from "../platform.js";
import { heading } from "../headings.js";
import * as notebook from "../notebook.js";
import { sourceOwner } from "../modules.js";
import { foldBlock } from "./band.js";
import { attachButton, heldPin } from "./hold-and-benign.js";

// The enrichment row's own rules, written against the --rc-* palette only so
// the app's value page can carry them with a variable map instead of POPUP_CSS.
export const ENRICH_CSS = `
.reach-enrich__row--refused{cursor:help}
.reach-enrich .reach-row__body{overflow-wrap:anywhere}
.reach-enrich__body{margin-top:8px}
.reach-enrich__body:empty{display:none}
.reach-enrich__title{display:flex;align-items:baseline;gap:6px}
.reach-enrich__bundled{font-size:10px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--rc-fg2);border:1px solid var(--rc-line);border-radius:2px;padding:0 4px;cursor:help}
.reach-enrich__actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:6px}
.reach-enrich__choose{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:6px;flex:1 1 100%;min-width:0}
.reach-enrich__choose select{flex:1 1 160px;min-width:0;width:auto;max-width:100%}
.reach-enrich__note{font-size:12px;color:var(--rc-fg2)}
.reach-enrich__sends{font-size:12px;color:var(--rc-fg2);overflow-wrap:anywhere;margin-top:4px}
`;
// The enrichment registry's row (app/lib/enrich.js, P6): one row per
// applicable source, drawn by its mode. A bundle source (CISA KEV) is
// fetched lazily and the row fills in the moment it resolves, no click
// needed: that fetch reads the extension's own bundled file, never the
// network. A fetch or stream source (VirusTotal today) keeps its own
// offer/refuse pattern: two explicit clicks stand between the page and the
// third party, the value that opened this popup and the row's own button,
// and the row is gated by Settings before the button ever appears. A
// deeplink source is a link, nothing is ever sent to open it.
//
//   enrichModel(offers) → [{ id, label, mode, allowed, why }]   (pure)
//       offers: [{ source, kind, id, allowed, why }] from enrich.offersFor()
//   enrichBlock({ value, offers, ask, settingsUrl }) → Element | null
//       ask   (msg) → Promise<response>, the message to the background worker
//               a fetch-mode source's call() may need (VirusTotal's own)
//       settingsUrl   a string, or (source) → string | { href, onClick }: where
//               the "set it up" link on an enabled-but-unconfigured source
//               points (the settings surface anchored on the source's module;
//               onClick opens the panel's own fold instead of a new tab)
export function enrichModel(offers) {
  return (offers || []).map((o) => ({ id: o.source.id, label: o.source.label, mode: o.source.mode, allowed: o.allowed !== false, why: o.why || null }));
}

//       hold   the pin fields for the value (holdBlock's), when a result may be
//               attached to the notebook; an "Attach to notebook" button follows
//               a result that said something
//   A result may carry actions: [{ id, label, title, held?, run(ctx) }], one
//   button each after the result (the self-hosted source's "Record sighting"
//   and "Propose to MISP"). An action marked held draws only for a value
//   already in the notebook, and gets that pin's reason; a click here never
//   holds. run() answers a result to draw in the result's place, or
//   { status: "choose", prompt, choices: [{ id, label }], submit(id) } for
//   one pick before the write.
export function enrichBlock({ value, offers, ask, settingsUrl, hold = null, platform = PLATFORM } = {}) {
  // A row only for a source that declares the offer's kind: a source
  // that cannot answer the value's shape never draws, so no "No result."
  // on a lookup that was never possible, and a value no source answers
  // draws no block (and so no Enrichment heading) at all.
  const applicable = (offers || []).filter((o) => o && o.source && (!o.kind || (Array.isArray(o.source.kinds) && o.source.kinds.includes(o.kind))));
  const rows = applicable.map((o) => ({ el: enrichSourceRow(value, o, { ask, settingsUrl, hold }), configure: o.configure === true })).filter((r) => r.el);
  if (!rows.length) return null;
  // The first offer stands on the first screen, and so does every row
  // whose source is on but not configured: its "Set it up" link is one
  // click away, never behind the fold. The rest fold shut behind one
  // summary line.
  const open = rows.filter((r, i) => i === 0 || r.configure).map((r) => r.el);
  const rest = rows.filter((r, i) => i !== 0 && !r.configure).map((r) => r.el);
  if (!rest.length) return h("div", { class: "reach-enrich" }, ...open);
  return h("div", { class: "reach-enrich" }, ...open, foldBlock(heading("other-sources", rest.length, termsFor(platform)), h("div", { class: "reach-enrich" }, ...rest)));
}

function attachFor(hold, source, res) {
  if (!hold || !res || !Array.isArray(res.lines) || !res.lines.length || res.status === "error" || res.status === "refused") return null;
  return attachButton({ ...hold, source: source.label, summary: res.lines.join(" "), result: { status: res.status, lines: res.lines } });
}

// A row's source declares nothing sent through its owning module's `sends`
// line (app/lib/modules.js), not through source.mode: a deeplink row sends
// nothing over the network either, so it carries the same mark as a bundle
// row. One title string for every source an owner's `sends` starts with
// "nothing"; the module registry is the one place that says which.
const BUNDLED_TITLE = "read from the extension's own file, nothing sent";

function enrichSourceRow(value, offer, { ask, settingsUrl, hold }) {
  const { source, allowed, why, configure } = offer;
  const owner = sourceOwner(source.id);
  const bundled = !!owner && /^nothing\b/.test(owner.sends || "");
  const label = h("div", { class: "reach-enrich__label" }, source.label);
  const title = bundled ? h("div", { class: "reach-enrich__title" }, label, h("span", { class: "reach-enrich__bundled", title: BUNDLED_TITLE }, "bundled")) : label;
  const setup = typeof settingsUrl === "function" ? settingsUrl(source) : settingsUrl;
  const setupUrl = setup && typeof setup === "object" ? setup.href : setup;
  const setupClick = setup && typeof setup === "object" && typeof setup.onClick === "function" ? setup.onClick : null;

  if (source.mode === "bundle") {
    const body = h("div", { class: "reach-row__body reach-row__body--muted" }, "Checking…");
    const linkWrap = h("div", { class: "reach-enrich__body" });
    source
      .call(value, {})
      .then((res) => {
        renderEnrichResult(body, res);
        if (res && res.link) linkWrap.appendChild(h("a", { class: "reach-link", href: res.link.href, target: "_blank", rel: "noopener" }, `${res.link.label || "Open"} →`));
        const attach = attachFor(hold, source, res);
        if (attach) linkWrap.appendChild(attach);
      })
      .catch(() => renderEnrichResult(body, { status: "error", lines: [`Could not read ${source.label}.`] }));
    return h("div", { class: "reach-row reach-enrich__row" }, title, body, linkWrap);
  }

  if (source.mode === "deeplink") {
    const link = source.linkFor ? source.linkFor(value, {}) : null;
    if (!link) return null;
    return h("div", { class: "reach-row reach-enrich__row" }, title, h("a", { class: "reach-link", href: link.href, target: "_blank", rel: "noopener" }, `${link.label || "Open"} →`));
  }

  // fetch / stream: VirusTotal's own offer/refuse pattern, generalised.
  // The module is on (an off module's source is never offered); refused
  // for a shape reason the row says why, refused for want of a key or an
  // origin it says "not configured" and links the module's settings.
  if (!allowed) {
    const openLink = source.linkFor ? source.linkFor(value, {}) : null;
    return h(
      "div",
      { class: "reach-row reach-enrich__row reach-enrich__row--refused" },
      title,
      h("div", { class: "reach-row__body reach-row__body--muted", title: why || "" }, configure ? `${source.label}: not configured.` : why || `${source.label} is off.`),
      configure && setupUrl ? h("a", { class: "reach-link reach-enrich__setup", href: setupUrl, target: setupClick ? null : "_blank", rel: "noopener", onClick: setupClick }, "Set it up →") : null,
      openLink ? h("a", { class: "reach-link", href: openLink.href, target: "_blank", rel: "noopener" }, `${openLink.label || "Open"} →`) : null,
    );
  }

  const body = h("div", { class: "reach-enrich__body" });
  const openLink = source.linkFor ? source.linkFor(value, {}) : null;
  const btn = h(
    "button",
    { type: "button", class: "reach-run-btn reach-run-btn--live", title: `Send this to ${source.label}. Nothing is sent until you click.`, onClick: (e) => run(e) },
    `Check on ${source.label}`,
  );
  const split = openLink
    ? h("div", { class: "reach-run-split" }, btn, h("a", { class: "reach-run-btn reach-run-btn--tab", href: openLink.href, target: "_blank", rel: "noopener", title: openLink.label }, "Open ↗"))
    : h("div", { class: "reach-run-split" }, btn);
  // What the click sends and where: the owning module's sends line, beside
  // the button on every online row (rule 8.12), read off the registry.
  const sends = owner && owner.sends ? h("p", { class: "reach-enrich__sends" }, `Sends: ${owner.sends}`) : null;

  async function run(e) {
    if (!e.isTrusted) return; // a synthetic click never sends anything
    btn.disabled = true;
    btn.replaceChildren(h("span", { class: "reach-spinner" }), `Asking ${source.label}…`);
    body.replaceChildren();
    let res;
    try {
      res = await source.call(value, { ask });
    } catch (err) {
      res = { status: "error", lines: [err && err.message ? err.message : String(err)] };
    }
    btn.disabled = false;
    btn.textContent = "Check again";
    showResult(res);
  }

  function showResult(res) {
    renderEnrichResult(body, res);
    const attach = attachFor(hold, source, res);
    if (attach) body.appendChild(attach);
    enrichActions(body, res, { ask, hold, redraw: showResult });
  }

  return h("div", { class: "reach-row reach-enrich__row" }, title, split, sends, body);
}

// The result's follow-up actions, each one explicit click. A held action
// needs the value's pin (heldPin over the loaded notebook) and never
// records one; the pin's reason travels with the click.
function enrichActions(body, res, { ask, hold, redraw }) {
  const actions = res && Array.isArray(res.actions) ? res.actions.filter((a) => a && typeof a.run === "function" && a.label) : [];
  if (!actions.length) return;
  const wrap = h("div", { class: "reach-enrich__actions" });
  const draw = () => {
    for (const a of actions) {
      const pin = hold && a.held ? heldPin({ field: hold.field, value: hold.value, container: hold.container }) : null;
      if (a.held && !pin) continue;
      const btn = h("button", { type: "button", class: "reach-mini reach-enrich__action", dataset: { action: a.id || "" }, title: a.title || "" }, a.label);
      btn.addEventListener("click", async (e) => {
        if (!e.isTrusted) return; // a synthetic click never writes anything
        for (const b of wrap.querySelectorAll("button")) b.disabled = true;
        btn.replaceChildren(h("span", { class: "reach-spinner" }), a.label);
        let out;
        try {
          out = await a.run({ ask, pin, reason: pin && pin.reason ? pin.reason : "" });
        } catch (err) {
          out = { status: "error", lines: [err && err.message ? err.message : String(err)] };
        }
        if (out && out.status === "choose") {
          wrap.replaceChildren(chooser(out, redraw, () => redraw(res)));
          return;
        }
        redraw(out);
      });
      wrap.appendChild(btn);
    }
    if (wrap.children.length) body.appendChild(wrap);
  };
  if (actions.some((a) => a.held)) notebook.load().then(draw, draw);
  else draw();
}

// One pick before a write: a select over the choices, Send and Cancel
// (Cancel puts the result and its actions back, nothing sent).
function chooser(out, redraw, cancelled) {
  const select = h("select", { class: "reach-input", "aria-label": out.prompt || "Choose" }, (out.choices || []).map((c) => h("option", { value: c.id }, c.label)));
  const note = h("span", { class: "reach-enrich__note" }, out.prompt || "");
  const send = h("button", { type: "button", class: "reach-mini reach-enrich__send" }, "Send");
  const cancel = h("button", { type: "button", class: "reach-mini reach-enrich__cancel" }, "Cancel");
  const root = h("div", { class: "reach-enrich__choose" }, note, select, send, cancel);
  send.addEventListener("click", async (e) => {
    if (!e.isTrusted) return;
    send.disabled = true;
    cancel.disabled = true;
    let res;
    try {
      res = await out.submit(select.value);
    } catch (err) {
      res = { status: "error", lines: [err && err.message ? err.message : String(err)] };
    }
    redraw(res);
  });
  cancel.addEventListener("click", cancelled);
  return root;
}

function renderEnrichResult(body, res) {
  body.replaceChildren();
  const status = res && res.status;
  const cls = status === "error" ? "reach-row__body--warn" : "reach-row__body--muted";
  const lines = (res && res.lines) || [];
  if (!lines.length) {
    if (status !== "ok") body.appendChild(h("div", { class: `reach-row__body ${cls}` }, "No result."));
    return;
  }
  for (const [i, line] of lines.entries()) {
    body.appendChild(h("div", { class: status === "ok" ? "reach-row__body" : `reach-row__body ${cls}`, dataset: { line: i === 0 ? "headline" : "detail" } }, line));
  }
}
