// A wildcard at the front of a value: the lexicon is keyed on whole
// tokens, so nothing narrows the scan and every event in the range is read.

import { stages, fieldTests, mask, trim } from "./_text.js";

// The longest whole token inside a wildcarded value (major breakers split
// it, * never counts): what the lexicon can look up on its own.
function token(value) {
  const parts = String(value).split(/[\s\\/*[\]<>(){}|!;,'"&?+=]+/).filter((p) => /^[A-Za-z0-9._:@#$%-]{3,}$/.test(p) && !/^\d+$/.test(p));
  return parts.sort((a, b) => b.length - a.length)[0] || null;
}

export const rule = {
  id: "spl/leading-wildcard",
  platform: "spl",
  severity: "caution",
  title: "leading wildcard",
  why: "a value that starts with * cannot use the lexicon: every event in the time range is read to test it",
  find(text) {
    const out = [];
    for (const st of stages(text, "spl")) {
      if (st.head !== "" && st.head !== "search") continue;
      for (const t of fieldTests(st, "spl")) {
        if (t.value.startsWith("*") && t.value.length > 1 && !/^\*+$/.test(t.value)) {
          const tok = token(t.value);
          out.push({ start: t.start, end: t.end, fix: { text: tok ? `${tok} ${t.field}=${t.quoted ? `"${t.value}"` : t.value}` : `${t.field}=${t.value.replace(/^\*+/, "")}*`, construct: tok ? "term" : "trailing_wildcard", label: tok ? "a whole token the value carries first: the lexicon narrows on it, the wildcard test runs on what is left" : "keep the literal head, wildcard the tail" } });
        }
      }
      // A bare token with a leading wildcard, outside quotes.
      const m = mask(st.text, "spl");
      for (const hit of m.matchAll(/(?<=^|[\s(])\*(?=[A-Za-z0-9_.])[^\s)]*/g)) {
        const [a, b] = trim([st.start + hit.index, st.start + hit.index + hit[0].length], text);
        const tok = token(hit[0]);
        out.push({ start: a, end: b, fix: { text: tok ? `${tok} ${hit[0]}` : `${hit[0].replace(/^\*+/, "")}*`, construct: tok ? "term" : "trailing_wildcard", label: tok ? "a whole token the value carries first, then the wildcard test" : "keep the literal head, wildcard the tail" } });
      }
    }
    return out;
  },
  cases: {
    hit: [
      "index=main sourcetype=xmlwineventlog Image=*\\cmd.exe",
      'index=main user="*admin"',
      "index=main *evil.exe | stats count",
      "index=main | search process=*powershell*",
    ],
    miss: [
      'index=main Image="C:\\\\Windows\\\\*"',
      "index=main process=powershell* | stats count by host",
      "index=* | stats count",
      'index=main | eval x="*foo"',
      'index=main | regex Image=".*cmd\\.exe$"',
    ],
  },
};

export default rule;
