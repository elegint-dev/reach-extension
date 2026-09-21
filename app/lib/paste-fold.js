// The paste's fold under the title block on stacked surfaces. A title set
// while a page renders leaves the fold closed; one set after the analyst
// acted on the page (a row click, a key on a row) opens it and scrolls it
// into view; a refill under the same title, a parameter edit, moves nothing.
// Returns the fold's next state, or null when it stays as it is.
export function foldMove({ title, lastTitle, acted, inFold }) {
  if (!title) return { open: false, scroll: false };
  if (!inFold || title === lastTitle || !acted) return null;
  return { open: true, scroll: true };
}
