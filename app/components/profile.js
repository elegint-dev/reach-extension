// profile: what discovery measured for a field on a sourcetype: fill rate,
// distinct count, top values, range. Facts from the user's own Splunk, so
// every number carries when and over what sample it was measured.
//
//   profileBlock({ profile })      the full block for a field page
//   fillBadge(profile)             "87%" for a list row, or null

import { h } from "./h.js";
import { headingNode } from "../lib/headings.js";

// "-7d" → "the last 7d"; "0" → "all time". The discovery window as prose.
export function windowLabel(window) {
  if (window === "0" || window === 0) return "all time";
  return `the last ${String(window || "").replace(/^-/, "")}`;
}

// "measured 17 Sep 2026, 14:02 over the last 7d, 5,000 sampled events".
export function measuredLine(profile) {
  const when = profile.measured_at ? new Date(profile.measured_at).toLocaleString() : "";
  return `measured ${when} over ${windowLabel(profile.window)}, ${Number(profile.sample || 0).toLocaleString()} sampled events`;
}

export function fillBadge(profile) {
  if (!profile || profile.fill === null || profile.fill === undefined) return null;
  const pct = Math.round(profile.fill * 100);
  return h("span", { class: "r-muted r-cofields__fill", title: `${profile.count} of ${profile.sample} sampled events carry it` }, `${pct}%`);
}

export function profileBlock({ profile }) {
  if (!profile) return null;
  const pct = profile.fill === null ? "-" : `${Math.round(profile.fill * 100)}%`;
  const facts = [
    h("span", { class: "r-stat" }, h("b", null, pct), "fill"),
    h("span", { class: "r-stat" }, h("b", null, String(profile.distinct)), profile.distinct_exact ? "distinct values" : "distinct (approx.)"),
    h("span", { class: "r-stat" }, h("b", null, String(profile.count)), `of ${profile.sample} sampled`),
  ];
  if (profile.numeric && profile.min !== null) facts.push(h("span", { class: "r-stat" }, h("b", null, `${profile.min} – ${profile.max}`), `range${profile.mean !== null ? `, mean ${Number(profile.mean).toFixed(2)}` : ""}`));
  const top = (profile.top || []).slice(0, 10);
  return h(
    "section",
    { class: "r-section" },
    headingNode("profile"),
    h("p", { class: "r-hold__role" }, ...facts),
    top.length
      ? h(
          "table",
          { class: "r-table r-profile__top" },
          h("thead", null, h("tr", null, h("th", null, "top value"), h("th", { class: "r-table__right" }, "count"), h("th", { class: "r-table__right" }, "share"))),
          h(
            "tbody",
            null,
            top.map((t) =>
              h("tr", null, h("td", null, h("code", null, t.value)), h("td", { class: "r-table__right" }, String(t.count)), h("td", { class: "r-table__right r-muted" }, profile.count ? `${Math.round((t.count / profile.count) * 100)}%` : "")),
            ),
          ),
        )
      : null,
    h("p", { class: "r-muted" }, `Measured ${profile.measured_at ? new Date(profile.measured_at).toLocaleString() : ""} over ${windowLabel(profile.window)}, first ${profile.sample} events.`),
  );
}

export default { profileBlock, fillBadge, windowLabel, measuredLine };
