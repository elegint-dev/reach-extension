// navstack: the trail. One stack of entries with a cursor, modelled on the
// browser's own history (a new navigation drops whatever was ahead), and
// the one source of truth for the header's back and forward buttons and
// the trail row under them (app.js).
//
//   initial(hash)          -> state, one entry, nothing to move either way
//   advance(state, hash, hop) -> after a navigation the router did not make itself (a new entry);
//                             hop names the row a click landed from (selection.js hopKey), null otherwise
//   relabel(state, hash)   -> after a same-entry change (setUrl's replaceState, router.replace())
//   sameHop(state, hop)    -> true when a click from that row belongs on the current entry
//   moveBack(state)        -> after window.history.back()
//   moveForward(state)     -> after window.history.forward()
//   moveTo(state, pos, hash) -> after a traversal the browser made (its entry carries the position)
//   label(state, meta)     -> the current entry gains { kind, name, field, value, st } for its chip
//   current(state)         -> the current entry
//   trail(state, n)        -> the last n entries up to and including the current one, oldest first
//   canGoBack(state), canGoForward(state) -> boolean
//   serialize(state), restore(text, hash) -> the sessionStorage mirror (reach.trail)
//   resumes(text, hash)    -> true when restore(text, hash) would keep the mirror's trail
//
// Which of advance, relabel, moveBack and moveForward applies is the
// caller's to know, never inferred here: the router flags every move it
// makes itself (goBack, goForward, setUrl, router.replace()), stamps each
// history entry with its position so the browser's own back and forward
// land through moveTo, and any other hashchange is an advance.
// history.length is never read.
//
// An entry is a hop, not a click. A click from the row the current entry
// came from (sameHop) is landed by router.replace(), so the entry, its
// history entry and its chip all take the new value in place; a click from
// another row, or after a navigation the panel made itself (a page with
// no hop), advances. The trail and the browser's history stay entry for
// entry, so back returns to the previous hop.

const entryOf = (hash, hop = null) => (hop ? { hash: String(hash == null ? "" : hash), hop: String(hop) } : { hash: String(hash == null ? "" : hash) });

export function initial(hash) {
  return { stack: [entryOf(hash)], pos: 0 };
}

export function current(state) {
  return state.stack[state.pos];
}

export function advance(state, hash, hop = null) {
  if (current(state).hash === hash) return state; // a re-render of the same hash, not a move
  const stack = state.stack.slice(0, state.pos + 1);
  stack.push(entryOf(hash, hop));
  return { stack, pos: stack.length - 1 };
}

export function sameHop(state, hop) {
  return Boolean(hop) && current(state).hop === String(hop);
}

export function relabel(state, hash) {
  if (current(state).hash === hash) return state;
  const stack = state.stack.slice();
  stack[state.pos] = { ...stack[state.pos], hash };
  return { stack, pos: state.pos };
}

export function label(state, meta) {
  const stack = state.stack.slice();
  const next = { ...stack[state.pos], ...meta, hash: stack[state.pos].hash };
  for (const k of Object.keys(next)) if (next[k] === undefined) delete next[k];
  stack[state.pos] = next;
  return { stack, pos: state.pos };
}

export function moveBack(state) {
  if (state.pos <= 0) return state;
  return { stack: state.stack, pos: state.pos - 1 };
}

export function moveForward(state) {
  if (state.pos >= state.stack.length - 1) return state;
  return { stack: state.stack, pos: state.pos + 1 };
}

// A traversal to a stamped entry: the position must name the entry the
// hash landed on, else the stamp is stale and the caller advances.
export function moveTo(state, pos, hash) {
  if (!Number.isInteger(pos) || pos < 0 || pos >= state.stack.length) return null;
  if (state.stack[pos].hash !== hash) return null;
  if (pos === state.pos) return state;
  return { stack: state.stack, pos };
}

export function canGoBack(state) {
  return state.pos > 0;
}

export function canGoForward(state) {
  return state.pos < state.stack.length - 1;
}

export function trail(state, n = 3) {
  const from = Math.max(0, state.pos + 1 - n);
  return state.stack.slice(from, state.pos + 1);
}

export function serialize(state, extra = {}) {
  return JSON.stringify({ stack: state.stack, pos: state.pos, ...extra });
}

// The mirror comes back as it was written when the page reloads on the
// same hash. The platform switch replaces the document on a new hash and
// says so (switch: true, with the hop the click came from), so the current
// entry is relabelled. Anything else on a new hash is a fresh document (a
// link opened in a new tab) and starts its own trail.
export function restore(text, hash) {
  const kept = resumed(text, hash);
  return kept ? kept.state : initial(hash);
}

// A reloaded document, or the platform switch, resumes its trail; a fresh
// document (a new panel, a link opened in a new tab) does not.
export function resumes(text, hash) {
  return resumed(text, hash) !== null;
}

function resumed(text, hash) {
  let saved = null;
  try {
    saved = text ? JSON.parse(text) : null;
  } catch {
    saved = null;
  }
  if (!saved || !Array.isArray(saved.stack) || !saved.stack.length || !Number.isInteger(saved.pos)) return null;
  const pos = Math.max(0, Math.min(saved.stack.length - 1, saved.pos));
  const stack = saved.stack.filter((e) => e && typeof e.hash === "string").map((e) => ({ ...e }));
  if (stack.length !== saved.stack.length) return null;
  const state = { stack, pos };
  if (current(state).hash === hash) return { state };
  if (saved.switch) return { state: label(relabel(state, hash), { hop: typeof saved.hop === "string" && saved.hop ? saved.hop : undefined }) };
  return null;
}

export default { initial, current, advance, relabel, sameHop, label, moveBack, moveForward, moveTo, canGoBack, canGoForward, trail, serialize, restore, resumes };
