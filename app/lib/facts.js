// facts: what a pivot's parameters are bound from before a view adds its
// own. Two stores feed it, and this is the one place their order is set:
//
//   pinned         kept across sessions (app/lib/pinned.js): tenant, region…
//   investigation  this tab (app/lib/investigation.js): aid, hostname…
//
// A fact held for the case shadows a pinned one of the same name, so the
// tenant you clicked in wins over the one you keep. A view then layers its
// own spec params and whatever the user typed in the drawer on top, and
// asks scope.js for the index last:
//
//   const params = scope.bind({ ...facts.bound(), ...spec.params, ...userParams }, sourcetype);
//
// The index (the workspace on Sentinel) is never a fact here: it is scope,
// configuration rather than something held. The stores (app/lib/held.js)
// refuse it on write and drop a stale one on read, so what they hand over
// is composed as it is.
//
// compose() is the pure core; bound() reads the stores. shadowed() lists
// the pins the tab is currently overriding, for the Holding panel to show.
//
// carried(name, value) is the value a page is on (the field route's
// ?value=, the value page's own): bound under the field's every name and
// as `value` for that page's pivots, layered over the stores and under
// the user's own inputs. It is never stored: a click holds nothing.
//
//   const params = scope.bind({ ...facts.bound(), ...facts.carried(name, value), ...userParams }, sourcetype);
//
// The stores hold one key per fact (held.js resolves pid and RawProcessId
// to one); bound() hands the fact back under every name a view may ask
// for, so a workflow reads its `pid` input and a pivot its `RawProcessId`.

import * as pinned from "./pinned.js";
import * as investigation from "./investigation.js";
import { aliasesOf, aliasPairs, setAliases, canonicalKey } from "./held.js";
import { isScopeKey } from "./scope.js";
import * as concepts from "./concepts.js";
import * as packs from "./packs.js";
import { PLATFORM } from "./platform.js";

// The alias map for this platform: the loaded packs' bindings, their
// concept-bound inputs and their column-named inputs. Called once the
// packs are loaded and again whenever the catalogue changes.
export function installAliases() {
  const params = [...packs.conceptParams(), ...packs.fieldParams()];
  setAliases(aliasPairs({ bindings: concepts.allBindings(PLATFORM), params }));
}

export function compose(pins, held) {
  return { ...(pins || {}), ...(held || {}) };
}

export function expand(facts) {
  const out = { ...(facts || {}) };
  for (const [k, v] of Object.entries(facts || {})) for (const a of aliasesOf(k)) if (!(a in out)) out[a] = v;
  return out;
}

export function carried(name, value) {
  const key = canonicalKey(name);
  if (!key || isScopeKey(key) || value === undefined || value === null || value === "") return {};
  return expand({ [key]: String(value), value: String(value) });
}

export function shadows(pins, held) {
  const out = [];
  for (const [key, value] of Object.entries(pins || {})) {
    if (held && key in held && held[key] !== value) out.push({ key, pinned: value, held: held[key] });
  }
  return out;
}

export function bound() {
  return expand(compose(pinned.all(), investigation.all()));
}

export function shadowed() {
  return shadows(pinned.all(), investigation.all());
}

export function subscribe(fn) {
  const a = pinned.subscribe(fn);
  const b = investigation.subscribe(fn);
  return () => {
    a();
    b();
  };
}
