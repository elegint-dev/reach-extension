// @license Example License
// Exercises strings, regex literals and nested template expressions
// against the comment stripper: evaluated before and after stripping,
// the two runs must return the same thing.
(function () {
  const results = [];
  const s1 = "a // not a comment";
  const s2 = "b /* not a comment either */";
  results.push(s1, s2);

  // a real line comment, safe to remove
  const divided = 10 / 2; // trailing comment after code
  results.push(divided);

  /* a real block comment
     spanning two lines */
  const re = /https?:\/\/example\.com\/[a-z]*/; // a regex with slashes
  results.push(re.test("https://example.com/path"));

  const inner = 3;
  const tpl = `outer-${`nested-${inner + 1 /* comment in nested expr */}`}-end`;
  results.push(tpl);

  if (divided) results.push(/x/.test("x")); // regex directly after an if-paren

  results.push(1 / 2 /* division after a number, not a regex */);

  return results;
})();
