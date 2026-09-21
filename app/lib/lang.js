// lang: what the two query languages share, in one table, so a module that
// holds a language name (pivot.js, ladder.js, benign.js) picks its
// primitives by lookup instead of branching on "spl" or "kql", and the two
// compilers (compile-spl.js, compile-kql.js) refuse the same things with
// the same error.
//
//   LANG.spl, LANG.kql      { id, quote, quoteList, time, lint, Error }
//   lang(id)                the entry, or CompileError bad_lang
//   CompileError(code, message)
//   PARAM_RE, TOKEN_RE      a parameter name; a $name$, $name:time$ or $name:list$ token in text
//   paramToken(name, kind?, what?)   the token for a param, or CompileError bad_param
//   literalText(value, what?)        String(value) for a string, number or boolean carrying no token;
//                                    CompileError bad_literal or literal_token otherwise
//
// spl.lint and kql.lint both answer { ok, violations, warnings } and take
// an options object; only spl reads one today (commands, macros).
//
// No DOM.

import * as spl from "./spl.js";
import * as kql from "./kql.js";

export class CompileError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "CompileError";
    this.code = code;
  }
}

export const LANG = Object.freeze({
  spl: Object.freeze({ id: "spl", quote: spl.quote, quoteList: spl.quoteList, time: spl.timeModifier, lint: spl.lint, Error: spl.SplError }),
  kql: Object.freeze({ id: "kql", quote: kql.quote, quoteList: kql.quoteList, time: kql.timeLiteral, lint: kql.lint, Error: kql.KqlError }),
});

export function lang(id) {
  const l = LANG[id];
  if (!l) throw new CompileError("bad_lang", `not a query language: ${String(id)}`);
  return l;
}

export const PARAM_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
// The token pivot.js expands when it renders a line; a literal carrying one
// would be expanded inside the quotes the compiler adds.
export const TOKEN_RE = /\$[A-Za-z_][A-Za-z0-9_]*(?::time|:list)?\$/;

export function paramToken(name, kind = "", what = "param") {
  if (typeof name !== "string" || !PARAM_RE.test(name)) throw new CompileError("bad_param", `${what}: not a parameter name: ${String(name)}`);
  return kind ? `$${name}:${kind}$` : `$${name}$`;
}

export function literalText(v, what = "literal") {
  if (v === undefined || v === null) throw new CompileError("bad_literal", `${what}: needs a value`);
  if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") throw new CompileError("bad_literal", `${what}: a literal is a string, number or boolean`);
  const s = String(v);
  if (TOKEN_RE.test(s)) throw new CompileError("literal_token", `${what}: literal ${JSON.stringify(s)} reads as a $param$ token; write $name to bind a param`);
  return s;
}

export default { LANG, lang, CompileError, PARAM_RE, TOKEN_RE, paramToken, literalText };
