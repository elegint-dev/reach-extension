// panel-close: whether the side panel document has anything typed that a
// window.close() would throw away. Read-only against the live DOM; never
// writes, never imports the components that own these forms (holding.js,
// drawer.js, annotation.js) so this stays a leaf every context can ask.
//
//   hasUnsavedInput(root = document)   true if any of UNSAVED_SELECTORS
//                                       matches an element with a non-empty value
//   UNSAVED_SELECTORS                  the checked selectors, one per surface:
//     the Note/Describe editor (annotation.js's field or sourcetype form),
//     a typed Hold reason (value.js's holdBlock, hold-and-benign.js),
//     a typed drawer parameter (drawer.js's paramsForm),
//     the Holding rail's Add form (holding.js)

export const UNSAVED_SELECTORS = Object.freeze([
  ".r-ann__form textarea",
  ".reach-hold__reason",
  ".r-drawer__params input",
  ".r-holding__add input",
]);

export function hasUnsavedInput(root = (typeof document !== "undefined" ? document : null)) {
  if (!root || typeof root.querySelectorAll !== "function") return false;
  for (const selector of UNSAVED_SELECTORS) {
    for (const el of root.querySelectorAll(selector)) {
      if (typeof el.value === "string" && el.value.trim()) return true;
    }
  }
  return false;
}

export default { UNSAVED_SELECTORS, hasUnsavedInput };
