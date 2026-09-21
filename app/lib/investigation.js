// investigation: key:value facts the hunter is holding (aid, hostname,
// a ticket number, whatever), scoped to this tab and gone when it closes.
// Views read it to pre-fill params. Written only by the gestures that
// write the notebook: the Hold button (holdBlock's onHeld on the field
// and value pages), Attach, and the Holding rail's add form and unpin. A
// click, a route, a render or a typed drawer or workflow input never
// writes it: a clicked value rides in the route and last-event.js, a
// typed one is its page's (facts.carried binds the page's own value).
//
//   investigation.get("aid")
//   investigation.set("aid", "abc123")     // "" removes the key
//   investigation.all()                    // { aid: "abc123", ... }
//   investigation.subscribe(fn)            // fn() on any change; returns unsubscribe
//
// One instance of app/lib/held.js on sessionStorage: the key rules, the
// storage guard and the scope-key guard are there. A clicked `index` (or a
// route or a step named for one) stores nothing: the index is scope
// (app/lib/scope.js), learned for the event's sourcetype instead.

import { heldStore } from "./held.js";

const store = heldStore({ storage: () => sessionStorage, key: "reach.investigation" });

export const { normalizeKey, all, get, set, remove, clear, subscribe } = store;
