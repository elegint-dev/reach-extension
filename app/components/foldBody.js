// foldBody: the shared shape for an open collapsible's body.
//
// An open collapsible draws as one block: header, then body, then the
// closing rule. The rule never sits between header and body. Give the
// element that follows a fold's header this class (or build it with
// foldBody()) and components.css does the rest: no border at the top,
// under an open ancestor (`.r-paste[open]`, `.is-open`) a border after.
// Two callers share it despite different open markup: app.js's `.r-paste`
// (a native <details>) around components/drawer.js's `.r-drawer`, and
// components/holding.js's class-toggled rail body.

import { h } from "./h.js";

export const FOLD_BODY_CLASS = "r-fold__body";

export function foldBody(tag, attrs = {}, ...children) {
  const existing = attrs.class;
  const classes = Array.isArray(existing) ? existing : existing ? [existing] : [];
  return h(tag, { ...attrs, class: [...classes, FOLD_BODY_CLASS] }, ...children);
}

export default foldBody;
