// surface: which of the three widths the page is on. The stylesheets decide
// layout with media queries at the same two boundaries (tokens.css declares
// them; CSS cannot read a custom property inside a media query, so the
// numbers are repeated there and here, and nowhere else):
//
//   panel    up to 599px    Chrome's side panel (320px to 400px by default;
//                           wider when the user drags it) and any tab that
//                           narrow. The rail stacks, folds start closed,
//                           tap targets are 44px, copy is the short variant.
//   narrow   600 to 899px   a tab too narrow for the 380px rail beside the
//                           ledger; the rail stacks, everything else is wide.
//   wide     900px and up   the rail sits beside the ledger.
//
// Views and components ask here, never matchMedia directly, so the
// breakpoint lives in one place on the JS side too.
//
//   surface()          -> "panel" | "narrow" | "wide"
//   isPanel()          -> surface() === "panel"
//   isStacked()        -> the rail is under the ledger (panel or narrow)
//   onSurface(fn)      -> fn(surface) now and whenever the surface changes
//   pick({panel, narrow, wide}) -> the value for the current surface; a
//                         missing narrow falls back to wide, a missing panel
//                         to narrow, so most copy needs two variants.

export const BREAKPOINTS = Object.freeze({ panel: 599, narrow: 899 });

const queries = {};
function query(max) {
  if (typeof matchMedia !== "function") return null;
  return (queries[max] ||= matchMedia(`(max-width: ${max}px)`));
}

export function surface() {
  const p = query(BREAKPOINTS.panel);
  if (p && p.matches) return "panel";
  const n = query(BREAKPOINTS.narrow);
  if (n && n.matches) return "narrow";
  return "wide";
}

export function isPanel() {
  return surface() === "panel";
}

export function isStacked() {
  return surface() !== "wide";
}

export function onSurface(fn) {
  let last = surface();
  fn(last);
  const check = () => {
    const now = surface();
    if (now === last) return;
    last = now;
    fn(now);
  };
  for (const max of Object.values(BREAKPOINTS)) {
    const q = query(max);
    if (q) q.addEventListener("change", check);
  }
}

export function pick(variants) {
  const s = surface();
  if (s === "panel" && variants.panel !== undefined) return variants.panel;
  if (s !== "wide" && variants.narrow !== undefined) return variants.narrow;
  return variants.wide;
}
