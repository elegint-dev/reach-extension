// pinned: key:value facts kept across browser sessions, this browser only.
// The environment the hunter works in rather than the case they are on: a
// tenant id, a region, an account. Views bind a pivot's parameters from
// these first, then from the investigation (this tab), so a fact held for
// the case shadows a pinned one of the same name.
//
//   pinned.get("tenant")
//   pinned.set("tenant", "t1")            // "" removes the key
//   pinned.all()                          // { tenant: "t1", ... }
//   pinned.subscribe(fn)                  // fn() on any change; returns unsubscribe
//
// One instance of app/lib/held.js on localStorage: the key rules, the
// storage guard and the scope-key guard are there. The index is not a pin.
// It is scope (app/lib/scope.js): kept in Settings, derived per sourcetype,
// never held. Earlier builds pinned it here as `index`; scope.js moves that
// in, and the store drops the key on sight.

import { heldStore } from "./held.js";

const store = heldStore({ storage: () => localStorage, key: "reach.pinned" });

export const { normalizeKey, all, get, set, remove, clear, subscribe } = store;
