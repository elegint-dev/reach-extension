// Event page: #/e/<name> (Splunk, the FDR bundle)
//
// Title block: the name, the anchor and CIM chips, the scope line
// (sourcetype, fields, handles), the action row (Sample search fills the
// paste fold, Sourcetype). Sections in the entity master order: Meaning
// (the anchor and PID callouts), CIM mapping, Fields (N).

import { h } from "../components/h.js";
import { fieldLink } from "../components/links.js";
import { chip } from "../components/chip.js";
import { callout } from "../components/callout.js";
import { titleBlock } from "../components/titleBlock.js";
import { openFold } from "../components/drawer.js";
import { headingNode } from "../lib/headings.js";
import { isStacked } from "../lib/surface.js";
import { absentPage, backAction } from "./unknown.js";
import * as fdr from "../lib/fdr-queries.js";
import * as facts from "../lib/facts.js";
import * as scope from "../lib/scope.js";

// PID-translation state from the record type's `pid_spaces` (pack-fields.js).
export function pidState(evRec) {
  const ps = (evRec && evRec.pid_spaces) || {};
  const tpid = ps.TargetProcessId === true;
  const raw = ps.RawProcessId === true;
  if (tpid && raw) return "both";
  if (tpid) return "falcon_only";
  if (raw) return "os_only";
  return "neither";
}

function pidCallout(evRec) {
  switch (pidState(evRec)) {
    case "both":
      return callout({
        kind: "expect",
        label: "Both PID spaces",
        body: h(
          "div",
          null,
          h(
            "p",
            null,
            "This event carries TargetProcessId and RawProcessId on the same record, so the translation between CrowdStrike's process id and the OS PID is readable here directly: no join, no arithmetic.",
          ),
          h("p", null, "These records are where PID translation is resolved. Scope by aid and a time window: the OS PID is recycled."),
        ),
      });
    case "falcon_only":
      return callout({
        kind: "caution",
        label: "Falcon process id only",
        body: h(
          "div",
          null,
          h("p", null, "This event carries TargetProcessId but not RawProcessId. To get the OS PID you must pivot to an anchor event (ProcessRollup2 or SyntheticProcessRollup2) for the same aid and TargetProcessId."),
          h("p", null, "That pivot is in the drawer: it is a lookup, not a conversion. There is no arithmetic that turns one into the other."),
        ),
      });
    case "os_only":
      return callout({
        kind: "hazard",
        label: "OS PID only",
        body: h(
          "div",
          null,
          h("p", null, "This event carries RawProcessId but not TargetProcessId, so it cannot resolve to a CrowdStrike process id on its own record."),
          h("p", null, "The OS PID is recycled. Resolve it with a scoped lookup against the anchor events for the same host and window; expect several candidates."),
        ),
      });
    default:
      // No PID: detection event (unestablished space) / has a handle / no handle.
      if ((evRec.pid_fields_unestablished || []).length) {
        return callout({
          kind: "hazard",
          label: "PID fields in an unestablished space",
          body: h(
            "div",
            null,
            h("p", null, `This is a ${evRec.sourcetype} event. It carries ${evRec.pid_fields_unestablished.join(" and ")}, but nothing on disk says whether those are Falcon process ids or OS PIDs, so they are not treated as process handles and no process join is offered from this event.`),
            h("p", null, h("a", { href: "#/w/detection" }, "The detection workflow"), " leads with the hash and host pivots, which are established, and gates the PID crossover behind that question."),
          ),
        });
      }
      if (!(evRec.handles || []).length) {
        return callout({
          kind: "caution",
          label: "No process handle at all",
          body: "This event carries no ContextProcessId, TargetProcessId or ParentProcessId. You can attribute it to a host (aid) and a time, not to a process. Do not fabricate a process link; the closest you can get is the host's process table for the same window.",
        });
      }
      return callout({
        kind: "note",
        label: "No PID on this event",
        body: `Neither TargetProcessId nor RawProcessId rides on this event, so nothing here translates between the two PID spaces. Attribution comes from ${evRec.handles.join(" / ")}, which is one hop from the process record.`,
      });
  }
}

function cimBlock(ctx, evRec) {
  const c = evRec.cim || { normalized: false, data_models: [], fields: [] };
  if (c.normalized) {
    return h(
      "section",
      { class: "r-section" },
      headingNode("cim-mapping"),
      h(
        "p",
        null,
        "The TA normalises this event into ",
        h("b", null, (c.data_models || []).join(", ")),
        ". You can search it by data model as well as by ",
        h("code", null, "event_simpleName"),
        ".",
      ),
      c.fields && c.fields.length
        ? h("p", { class: "r-inline" }, "CIM fields: ", c.fields.flatMap((n, i) => [i ? " " : null, fieldLink(n, evRec.sourcetype)]))
        : null,
    );
  }
  const counts = ctx.fields.counts();
  return h(
    "section",
    { class: "r-section" },
    headingNode("cim-mapping"),
    callout({
      kind: "note",
      label: "No CIM path",
      body: h(
        "div",
        null,
        h(
          "p",
          null,
          "The TA does not normalise this event into any CIM data model. There is no CIM field to search and no data model that will find it: the only route to this data is the raw ",
          h("code", null, "event_simpleName"),
          ".",
        ),
        h(
          "p",
          null,
          `It is one of ${counts.events_cim_gap} events in the CIM gap, out of ${counts.events} in the catalogue; ${counts.events_cim_normalized} are normalised.`,
        ),
      ),
    }),
  );
}

export function render(ctx) {
  const { fields } = ctx;
  const name = ctx.params.name;
  const rec = fields.event(name);
  if (!rec) {
    return absentPage({
      name,
      chip: "not in the catalogue",
      why: "no event by that name is in the catalogue",
      actions: [backAction(ctx.goBack), h("a", { class: "r-btn", href: `#/unknown/${encodeURIComponent(name)}` }, "Nearest names"), h("a", { class: "r-btn", href: "#/catalogue" }, "Catalogue")],
    });
  }

  const el = h("div", { class: "r-view r-view--event" });
  const st = rec.sourcetype;
  const handles = rec.handles || [];

  el.appendChild(
    titleBlock({
      kind: "event",
      h1: rec.name,
      chips: [
        rec.is_anchor ? chip({ kind: "route", value: "here", text: "anchor event" }) : null,
        rec.cim && rec.cim.normalized ? chip({ kind: "trust", value: "confirmed", text: "CIM normalized" }) : chip({ kind: "trust", value: "inferred", text: "no CIM path" }),
      ],
      scope: [
        h("a", { class: "r-scope__name", href: `#/st/${encodeURIComponent(st)}`, title: st }, h("code", null, st)),
        `${rec.field_count} fields`,
        handles.length ? h("span", { title: handles.join(", ") }, `${handles.length} handle${handles.length === 1 ? "" : "s"}`) : "no process handle",
      ],
      actions: [
        h("button", { type: "button", class: "r-btn", onClick: openFold }, "Sample search"),
        h("a", { class: "r-btn", href: `#/st/${encodeURIComponent(st)}` }, "Sourcetype →"),
      ],
    }),
  );

  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("meaning"),
      rec.is_anchor
        ? callout({
            kind: "why",
            label: "Anchor event",
            body: "This is a process-creation record. It is where a process gets its identity: image, command line, user, start time, both PID spaces. It is also the destination of nearly every pivot in Reach.",
          })
        : null,
      pidCallout(rec),
      handles.length ? h("p", { class: "r-secondary r-inline" }, "Process handles: ", handles.flatMap((n, i) => [i ? " " : null, fieldLink(n, st)])) : null,
      rec.tenant
        ? h("p", { class: "r-secondary" }, `Received ${rec.tenant.count} events${rec.tenant.hosts === null ? "" : ` on ${rec.tenant.hosts} hosts`} in run ${((ctx.fields.manifest().observed || {}).run || {}).id}.`)
        : null,
    ),
  );

  el.appendChild(cimBlock(ctx, rec));

  // Every role group is a fold with its count in the title, closed on
  // stacked surfaces; the summary is data (the role), not a heading.
  const byRole = rec.fields_by_role || {};
  const roles = Object.keys(byRole).sort();
  const stacked = isStacked();
  el.appendChild(
    h(
      "section",
      { class: "r-section" },
      headingNode("fields", rec.field_count),
      h("p", { class: "r-muted" }, "Grouped by role, then alphabetical."),
      h(
        "div",
        { class: "r-rolelist" },
        roles.map((role) =>
          h(
            "details",
            { class: "r-rolelist__group", open: !stacked, dataset: { role } },
            h("summary", { class: "r-rolelist__role" }, role, h("span", { class: "r-muted" }, ` ${byRole[role].length}`)),
            h("p", { class: "r-rolelist__fields" }, byRole[role].slice().sort().flatMap((n, i) => [i ? " " : null, fieldLink(n, st)])),
          ),
        ),
      ),
    ),
  );

  const userParams = {};
  const state = pidState(rec);
  const pivot = { kind: "event_sample" };
  const base = { event: rec.name, sourcetype: rec.sourcetype };

  function fill(rebuild) {
    // The index is scope: resolved for the event's sourcetype at compile
    // time, never a held fact.
    const params = scope.bind({ ...facts.bound(), ...base, ...userParams }, rec.sourcetype);
    const out = fdr.generate(pivot, params);
    ctx.drawer.fill({
      title: `See ${rec.name} on real data`,
      subtitle: state === "falcon_only" ? "…then pivot to an anchor event for the OS PID" : rec.sourcetype,
      spl: out.spl,
      params: rebuild ? out.missing.map((n) => ({ name: n, label: n, value: userParams[n] ?? "", placeholder: n === "earliest" ? "-24h" : "", required: true })) : undefined,
      hazards: [...out.hazards, ...scope.notes(rec.sourcetype)],
    });
  }

  ctx.setDrawerParamHandler((n, v) => {
    userParams[n] = v;
    fill(false);
  });

  el.afterMount = () => fill(true);
  scope.follow(el, () => fill(false));
  return el;
}

export default { render, pidState };
