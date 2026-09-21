// Where a field goes from here: the other sourcetypes that carry it, and the
// pack workflows that start from it. Rules in popup-shell.js POPUP_CSS
// (.reach-everywhere, .reach-workflows).
//
//   everywhereBlock({ rows, name, appUrl, titled, platform, newTab }) → Element | null
//       rows: catalogue.fieldEverywhere(); each sourcetype with fill where
//       discovery measured it and which layer knows it
//   workflowsBlock({ rows, value, appUrl, href, sourcetype, titled, platform, newTab }) → Element | null
//       rows: workflows.forField(); links into the app with the clicked value
//       bound to the entry param
//
// DOM module (uses h.js). Never fetches.

import { h } from "../../components/h.js";
import { PLATFORM } from "../platform.js";
import { bandTitle } from "./band.js";

// Where a field name lives when the popup cannot tell which sourcetype it
// is inside: each sourcetype that carries it, with fill where discovery
// measured it and which layer knows it. `rows` is catalogue.fieldEverywhere().
export function everywhereBlock({ rows, name, appUrl, titled = true, platform = PLATFORM, newTab = true }) {
  if (!rows || !rows.length) return null;
  const MAX = 6;
  const items = rows.slice(0, MAX).map((r) => {
    const bits = [];
    if (r.fill !== null) bits.push(`${Math.round(r.fill * 100)}% fill`);
    else if (r.sources.includes("discovered")) bits.push("seen, not profiled");
    if (r.sources.includes("pack")) bits.push(r.packId || "pack");
    if (r.sources.includes("user")) bits.push("your note");
    if (!r.described && !bits.length) bits.push("no description");
    const href = appUrl ? appUrl(`#/f/${encodeURIComponent(name)}?st=${encodeURIComponent(r.sourcetype)}`) : null;
    const label = h("code", null, r.sourcetype);
    return h(
      "li",
      { class: "reach-everywhere__row" },
      href ? h("a", { href, target: newTab ? "_blank" : null, rel: newTab ? "noopener" : null, class: "reach-everywhere__st" }, label) : label,
      h("span", { class: "reach-everywhere__how" }, bits.length ? ` ${bits.join(" · ")}` : ""),
    );
  });
  return h(
    "div",
    { class: "reach-row reach-everywhere" },
    titled ? h("div", { class: "reach-row__title" }, bandTitle("everywhere", rows.length, platform)) : null,
    h("ul", { class: "reach-everywhere__list" }, ...items),
    rows.length > MAX ? h("div", { class: "reach-row__body--muted" }, `and ${rows.length - MAX} more`) : null,
  );
}

// Workflows a pack starts from this field on this sourcetype, as links into
// the app with the clicked value (when there is one) bound to the entry
// param. `rows` is workflows.forField(); `appUrl` maps a hash route to a URL.
export function workflowsBlock({ rows, value, appUrl, href, sourcetype, titled = true, platform = PLATFORM, newTab = true }) {
  if (!rows || !rows.length || !appUrl || !href) return null;
  const carried = sourcetype ? { st: sourcetype } : {}; // the walker renders results against the table the click was on
  return h(
    "div",
    { class: "reach-row reach-workflows" },
    titled ? h("div", { class: "reach-row__title" }, bandTitle("workflows", undefined, platform)) : null,
    ...rows.map((w) =>
      h(
        "a",
        { class: "reach-link reach-workflows__link", href: appUrl(href(w.id, { ...carried, ...(value ? { [w.param]: value } : {}) })), target: newTab ? "_blank" : null, rel: newTab ? "noopener" : null, title: w.kicker || "" },
        `${w.title} →`,
      ),
    ),
  );
}
