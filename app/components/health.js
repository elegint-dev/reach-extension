// health: is this feed still arriving, and has its shape moved: what the
// catalogue's discovered meta says about a sourcetype over time, as chips
// and one line. Nothing here is a verdict about the data; it is when it
// was last seen and what changed between two measurements.
//
//   healthChips(meta)      [chip…]   "last seen 3d ago" (hazard past STALE), "missing since <date>"
//   deltaLine(delta)       "+2 new · 1 gone · 3 fill shifts" with the fields as a title, or null
//   deltaBlock(delta, st)  the Field changes (N) section of a sourcetype page

import { h } from "./h.js";
import { fieldLink } from "./links.js";
import { chip } from "./chip.js";
import { headingNode } from "../lib/headings.js";
import { ageLabel, STALE_PROFILE_SECONDS } from "../lib/discovery.js";
import { epochOf } from "../lib/layer.js";
import { TERMS } from "../lib/platform.js";
import { when } from "../lib/when.js";

const pct = (x) => `${Math.round(x * 100)}%`;

export function healthChips(meta, now = Date.now()) {
  if (!meta) return [];
  const out = [];
  if (meta.missingSince) {
    out.push(chip({ kind: "hazard", text: `missing since ${new Date(meta.missingSince).toLocaleDateString()}`, title: `The latest inventory covering its ${TERMS.index} did not return this ${TERMS.sourcetype}: nothing arrived in the window.` }));
  } else if (epochOf(meta.lastSeen)) {
    const lastSeen = epochOf(meta.lastSeen);
    const age = Math.max(0, Math.round(now / 1000 - lastSeen));
    const stale = age >= STALE_PROFILE_SECONDS;
    // Neutral while fresh, amber once older than a profile is trusted for.
    out.push(chip({ kind: "trust", value: stale ? "asserted" : "inferred", text: `last seen ${ageLabel(age)}`, title: `newest event the last inventory saw: ${when(lastSeen)}` }));
  }
  return out;
}

export function deltaSummary(delta) {
  if (!delta) return null;
  const bits = [];
  if (delta.added.length) bits.push(`+${delta.added.length} new`);
  if (delta.gone.length) bits.push(`${delta.gone.length} gone`);
  if (delta.fill.length) bits.push(`${delta.fill.length} fill shift${delta.fill.length === 1 ? "" : "s"}`);
  return bits.join(" · ");
}

export function deltaLine(delta) {
  const text = deltaSummary(delta);
  if (!text) return null;
  const title = [
    delta.added.length ? `new: ${delta.added.join(", ")}` : "",
    delta.gone.length ? `gone: ${delta.gone.join(", ")}` : "",
    ...delta.fill.map((f) => `${f.field} ${pct(f.from)} → ${pct(f.to)}`),
  ]
    .filter(Boolean)
    .join("\n");
  return h("span", { class: "r-health__delta", title }, text);
}

export function deltaBlock(delta, st) {
  if (!delta || !deltaSummary(delta)) return null;
  const link = (n) => fieldLink(n, st);
  const list = (names) => names.flatMap((n, i) => [i ? ", " : "", link(n)]);
  const when = delta.previous_at ? ` against ${new Date(delta.previous_at).toLocaleString()}` : "";
  return h(
    "section",
    { class: "r-section" },
    headingNode("field-changes", delta.added.length + delta.gone.length + delta.fill.length),
    h("p", { class: "r-secondary" }, `The profile of ${new Date(delta.at).toLocaleString()}${when}. ${TERMS.Fields} are sampled, so a rare one can come and go between runs.`),
    delta.added.length ? h("p", null, h("b", null, "New: "), ...list(delta.added)) : null,
    delta.gone.length ? h("p", null, h("b", null, "Not in this sample: "), ...list(delta.gone)) : null,
    delta.fill.length ? h("p", null, h("b", null, "Fill moved: "), ...delta.fill.flatMap((f, i) => [i ? " · " : "", link(f.field), h("span", { class: "r-muted" }, ` ${pct(f.from)} → ${pct(f.to)}`)])) : null,
  );
}

export default { healthChips, deltaSummary, deltaLine, deltaBlock };
