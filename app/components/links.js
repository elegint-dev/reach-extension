// The identifier links every view draws the same way: a sourcetype, a
// field (on a sourcetype when one is known), a record type. Each is an
// r-idlink anchor around the name in code, on the app's own hash routes.
//
//   stLink(name)              → <a href="#/st/<name>">
//   fieldLink(name, st?)      → <a href="#/f/<name>?st=<st>">, no query without a sourcetype
//   eventLink(name)           → <a href="#/e/<name>">
//   plural(n, one, many)      → "1 field" | "3 fields"
//
// DOM module (uses h.js).
import { h } from "./h.js";

function idLink(href, name) {
  return h("a", { href, class: "r-idlink" }, h("code", null, name));
}

export function stLink(name) {
  return idLink(`#/st/${encodeURIComponent(name)}`, name);
}

export function fieldLink(name, st = null) {
  const q = st ? `?st=${encodeURIComponent(st)}` : "";
  return idLink(`#/f/${encodeURIComponent(name)}${q}`, name);
}

export function eventLink(name) {
  return idLink(`#/e/${encodeURIComponent(name)}`, name);
}

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

export default { stLink, fieldLink, eventLink, plural };
