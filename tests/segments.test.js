import { test } from "node:test";
import assert from "node:assert/strict";
import { segment, SHAPES, KINDS } from "../app/lib/segments.js";

// [sep, text, kind] triples, the way a table reads.
const flat = (r) => r.segments.map((s) => [s.sep, s.text, s.kind]);
const roundTrip = (r) => r.segments.map((s) => s.sep + s.text).join("") + r.tail;

// One row per shape and edge case: value, optional explicit shape, the
// expected shape and detail, the expected triples and tail.
const TABLE = [
  // paths
  { v: String.raw`C:\Windows\System32\cmd.exe`, shape: "path", detail: "windows", segs: [["", "C:", "drive"], ["\\", "Windows", "dir"], ["\\", "System32", "dir"], ["\\", "cmd", "basename"], [".", "exe", "ext"]] },
  { v: String.raw`C:\Users\Alice Smith\AppData\Local\Temp\evil.exe`, shape: "path", detail: "windows", segs: [["", "C:", "drive"], ["\\", "Users", "dir"], ["\\", "Alice Smith", "dir"], ["\\", "AppData", "dir"], ["\\", "Local", "dir"], ["\\", "Temp", "dir"], ["\\", "evil", "basename"], [".", "exe", "ext"]] },
  { v: String.raw`C:\Program Files\App\app.exe`, shape: "path", detail: "windows", segs: [["", "C:", "drive"], ["\\", "Program Files", "dir"], ["\\", "App", "dir"], ["\\", "app", "basename"], [".", "exe", "ext"]] },
  { v: String.raw`\\srv01\share\dir\f.txt`, shape: "path", detail: "unc", segs: [["\\\\", "srv01", "server"], ["\\", "share", "share"], ["\\", "dir", "dir"], ["\\", "f", "basename"], [".", "txt", "ext"]] },
  { v: String.raw`\\srv01\share`, shape: "path", detail: "unc", segs: [["\\\\", "srv01", "server"], ["\\", "share", "share"]] },
  { v: "/usr/bin/python3", shape: "path", detail: "posix", segs: [["/", "usr", "dir"], ["/", "bin", "dir"], ["/", "python3", "basename"]] },
  { v: "/var/log/", shape: "path", detail: "posix", segs: [["/", "var", "dir"], ["/", "log", "basename"]], tail: "/" },
  { v: "/home/john doe/file.txt", shape: "path", detail: "posix", segs: [["/", "home", "dir"], ["/", "john doe", "dir"], ["/", "file", "basename"], [".", "txt", "ext"]] },
  { v: "/home/user/.bashrc", shape: "path", detail: "posix", segs: [["/", "home", "dir"], ["/", "user", "dir"], ["/", ".bashrc", "basename"]] },
  { v: "C:\\", shape: "path", detail: "windows", segs: [["", "C:", "drive"]], tail: "\\" },
  { v: String.raw`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, shape: "path", detail: "registry", segs: [["", "HKLM", "hive"], ["\\", "SOFTWARE", "dir"], ["\\", "Microsoft", "dir"], ["\\", "Windows", "dir"], ["\\", "CurrentVersion", "dir"], ["\\", "Run", "basename"]] },
  { v: String.raw`\REGISTRY\MACHINE\SOFTWARE\Run`, shape: "path", detail: "registry", segs: [["", "\\REGISTRY", "hive"], ["\\", "MACHINE", "dir"], ["\\", "SOFTWARE", "dir"], ["\\", "Run", "basename"]] },
  { v: String.raw`Users\alice\notes.txt`, shape: "path", detail: "windows", segs: [["", "Users", "dir"], ["\\", "alice", "dir"], ["\\", "notes", "basename"], [".", "txt", "ext"]] },
  // command lines
  { v: "powershell.exe -enc AAAA", shape: "cmdline", detail: null, segs: [["", "powershell.exe", "exe"], [" ", "-enc", "flag"], [" ", "AAAA", "arg"]] },
  { v: "cmd /c whoami", shape: "cmdline", detail: null, segs: [["", "cmd", "exe"], [" ", "/c", "flag"], [" ", "whoami", "arg"]] },
  { v: String.raw`"C:\Program Files\App\app.exe" --flag "some value" x`, shape: "cmdline", detail: null, segs: [['"', "C:", "drive"], ["\\", "Program Files", "dir"], ["\\", "App", "dir"], ["\\", "app", "basename"], [".", "exe", "ext"], ['" ', "--flag", "flag"], [' "', "some value", "arg"], ['" ', "x", "arg"]] },
  { v: String.raw`"C:\Program Files\App\app.exe"`, shape: "cmdline", detail: null, segs: [['"', "C:", "drive"], ["\\", "Program Files", "dir"], ["\\", "App", "dir"], ["\\", "app", "basename"], [".", "exe", "ext"]], tail: '"' },
  { v: String.raw`C:\Windows\System32\cmd.exe /c dir`, shape: "cmdline", detail: null, segs: [["", "C:", "drive"], ["\\", "Windows", "dir"], ["\\", "System32", "dir"], ["\\", "cmd", "basename"], [".", "exe", "ext"], [" ", "/c", "flag"], [" ", "dir", "arg"]] },
  { v: '/usr/bin/python3 -c "print(1)"', shape: "cmdline", detail: null, segs: [["/", "usr", "dir"], ["/", "bin", "dir"], ["/", "python3", "basename"], [" ", "-c", "flag"], [' "', "print(1)", "arg"]], tail: '"' },
  { v: "/bin/sh -c /tmp/x", shape: "cmdline", detail: null, segs: [["/", "bin", "dir"], ["/", "sh", "basename"], [" ", "-c", "flag"], [" ", "/tmp/x", "arg"]] },
  { v: String.raw`notepad.exe "C:\a b.txt"`, shape: "cmdline", detail: null, segs: [["", "notepad.exe", "exe"], [' "', String.raw`C:\a b.txt`, "arg"]], tail: '"' },
  // urls
  { v: "https://user:pw@evil.example.com:8443/a/b/c.php?id=1&x=y#frag", shape: "url", detail: null, segs: [["", "https", "scheme"], ["://", "user:pw", "userinfo"], ["@", "evil.example.com", "host"], [":", "8443", "port"], ["/", "a", "dir"], ["/", "b", "dir"], ["/", "c", "basename"], [".", "php", "ext"], ["?", "id=1", "query"], ["&", "x=y", "query"], ["#", "frag", "fragment"]] },
  { v: "http://[2001:db8::1]:80/", shape: "url", detail: null, segs: [["", "http", "scheme"], ["://", "[2001:db8::1]", "host"], [":", "80", "port"]], tail: "/" },
  { v: "https://good.example.org/", shape: "url", detail: null, segs: [["", "https", "scheme"], ["://", "good.example.org", "host"]], tail: "/" },
  { v: "https://x.io", shape: "url", detail: null, segs: [["", "https", "scheme"], ["://", "x.io", "host"]] },
  { v: "https://x.io/?q=1", shape: "url", detail: null, segs: [["", "https", "scheme"], ["://", "x.io", "host"], ["/?", "q=1", "query"]] },
  // arns
  { v: "arn:aws:iam::123456789012:user/jdoe", shape: "arn", detail: null, segs: [["arn:", "aws", "partition"], [":", "iam", "service"], [":", "", "region"], [":", "123456789012", "account"], [":", "user", "resource_type"], ["/", "jdoe", "resource"]] },
  { v: "arn:aws:s3:::my-bucket/path/to/key.txt", shape: "arn", detail: null, segs: [["arn:", "aws", "partition"], [":", "s3", "service"], [":", "", "region"], [":", "", "account"], [":", "my-bucket", "resource_type"], ["/", "path", "resource"], ["/", "to", "resource"], ["/", "key.txt", "resource"]] },
  { v: "arn:aws:lambda:us-east-1:123456789012:function:my-func:1", shape: "arn", detail: null, segs: [["arn:", "aws", "partition"], [":", "lambda", "service"], [":", "us-east-1", "region"], [":", "123456789012", "account"], [":", "function", "resource_type"], [":", "my-func", "resource"], [":", "1", "resource"]] },
  { v: "arn:aws:s3:::my-bucket", shape: "arn", detail: null, segs: [["arn:", "aws", "partition"], [":", "s3", "service"], [":", "", "region"], [":", "", "account"], [":", "my-bucket", "resource"]] },
  { v: "arn:aws:sts::123456789012:assumed-role/AdminRole/session-1", shape: "arn", detail: null, segs: [["arn:", "aws", "partition"], [":", "sts", "service"], [":", "", "region"], [":", "123456789012", "account"], [":", "assumed-role", "resource_type"], ["/", "AdminRole", "resource"], ["/", "session-1", "resource"]] },
  // email and upn
  { v: "jdoe+news@gmail.com", shape: "email", detail: null, segs: [["", "jdoe", "local"], ["+", "news", "tag"], ["@", "gmail", "label"], [".", "com", "label"]] },
  { v: "jdoe@corp.contoso.com", shape: "upn", detail: null, segs: [["", "jdoe", "local"], ["@", "corp", "label"], [".", "contoso", "label"], [".", "com", "label"]] },
  { v: "first.last@corp.contoso.com", shape: "upn", detail: null, segs: [["", "first.last", "local"], ["@", "corp", "label"], [".", "contoso", "label"], [".", "com", "label"]] },
  // ip
  { v: "10.0.0.1", shape: "ip", detail: "v4", segs: [["", "10", "octet"], [".", "0", "octet"], [".", "0", "octet"], [".", "1", "octet"]] },
  { v: "10.0.0.0/8", shape: "ip", detail: "v4", segs: [["", "10", "octet"], [".", "0", "octet"], [".", "0", "octet"], [".", "0", "octet"], ["/", "8", "cidr"]] },
  { v: "2001:db8::1", shape: "ip", detail: "v6", segs: [["", "2001", "group"], [":", "db8", "group"], [":", "", "group"], [":", "1", "group"]] },
  { v: "fe80::1%eth0", shape: "ip", detail: "v6", segs: [["", "fe80", "group"], [":", "", "group"], [":", "1", "group"], ["%", "eth0", "zone"]] },
  { v: "[::1]", shape: "ip", detail: "v6", segs: [["[", "", "group"], [":", "", "group"], [":", "1", "group"]], tail: "]" },
  { v: "2001:db8::/32", shape: "ip", detail: "v6", segs: [["", "2001", "group"], [":", "db8", "group"], [":", "", "group"], [":", "", "group"], ["/", "32", "cidr"]] },
  { v: "::ffff:192.0.2.1", shape: "ip", detail: "v6", segs: [["", "", "group"], [":", "", "group"], [":", "ffff", "group"], [":", "192.0.2.1", "group"]] },
  // domain, hostname, guid
  { v: "evil.example.com", shape: "domain", detail: null, segs: [["", "evil", "label"], [".", "example", "label"], [".", "com", "label"]] },
  { v: "example.com.", shape: "domain", detail: null, segs: [["", "example", "label"], [".", "com", "label"]], tail: "." },
  { v: "xn--80ak6aa92e.com", shape: "domain", detail: null, segs: [["", "xn--80ak6aa92e", "label"], [".", "com", "label"]] },
  { v: "bücher.example", give: "domain", shape: "domain", detail: null, segs: [["", "bücher", "label"], [".", "example", "label"]] },
  { v: "host01.corp.local", give: "hostname", shape: "hostname", detail: null, segs: [["", "host01", "host"], [".", "corp", "label"], [".", "local", "label"]] },
  { v: "WORKSTATION01", give: "hostname", shape: "hostname", detail: null, segs: [["", "WORKSTATION01", "host"]] },
  { v: "550e8400-e29b-41d4-a716-446655440000", shape: "guid", detail: null, segs: [["", "550e8400", "hex"], ["-", "e29b", "hex"], ["-", "41d4", "hex"], ["-", "a716", "hex"], ["-", "446655440000", "hex"]] },
  { v: "{550e8400-e29b-41d4-a716-446655440000}", shape: "guid", detail: "braced", segs: [["{", "550e8400", "hex"], ["-", "e29b", "hex"], ["-", "41d4", "hex"], ["-", "a716", "hex"], ["-", "446655440000", "hex"]], tail: "}" },
  // json and the punctuation fallback
  { v: '{"a": 1, "b": [2]}', shape: "json", detail: null, segs: [["", '{"a": 1, "b": [2]}', "json"]] },
  { v: "S-1-5-21-3623811015-3361044348-30300820-1013", shape: "text", detail: null, segs: [["", "S", "word"], ["-", "1", "digits"], ["-", "5", "digits"], ["-", "21", "digits"], ["-", "3623811015", "digits"], ["-", "3361044348", "digits"], ["-", "30300820", "digits"], ["-", "1013", "digits"]] },
  { v: "hello", shape: "text", detail: null, segs: [["", "hello", "word"]] },
  { v: "User admin logged on", shape: "text", detail: null, segs: [["", "User", "word"], [" ", "admin", "word"], [" ", "logged", "word"], [" ", "on", "word"]] },
  { v: "Failed to open /etc/passwd for user", shape: "text", detail: null, segs: [["", "Failed", "word"], [" ", "to", "word"], [" ", "open", "word"], [" /", "etc", "word"], ["/", "passwd", "word"], [" ", "for", "word"], [" ", "user", "word"]] },
  { v: "***", shape: "text", detail: null, segs: [["", "***", "word"]] },
  { v: "4688", shape: "text", detail: null, segs: [["", "4688", "digits"]] },
  { v: "AKIAIOSFODNN7EXAMPLE", shape: "text", detail: null, segs: [["", "AKIAIOSFODNN7EXAMPLE", "word"]] },
];

for (const row of TABLE) {
  test(`segment: ${row.v}${row.give ? ` as ${row.give}` : ""}`, () => {
    const r = segment(row.v, row.give);
    assert.equal(r.shape, row.shape, "shape");
    assert.equal(r.detail, row.detail, "detail");
    assert.deepEqual(flat(r), row.segs);
    assert.equal(r.tail, row.tail || "");
    assert.equal(roundTrip(r), row.v, "round trip");
    assert.equal(r.truncated, false);
  });
}

test("round trip holds for every table value under every explicit shape it accepts", () => {
  for (const row of TABLE) {
    for (const shape of SHAPES) {
      const r = segment(row.v, shape);
      assert.equal(roundTrip(r), row.v, `${row.v} as ${shape}`);
      assert.ok(SHAPES.includes(r.shape), `${r.shape} is a listed shape`);
    }
  }
});

test("every segment kind has a like-class and every class compiles", () => {
  const seen = new Set();
  for (const row of TABLE) for (const s of segment(row.v, row.give).segments) seen.add(s.kind);
  for (const kind of seen) assert.ok(KINDS[kind], `KINDS has ${kind}`);
  for (const [kind, cls] of Object.entries(KINDS)) assert.doesNotThrow(() => new RegExp(`^${cls}$`), `${kind} class compiles`);
});

test("an explicit shape wins over detection", () => {
  assert.equal(segment("C:\\Program Files\\App\\app.exe", "cmdline").shape, "cmdline");
  assert.deepEqual(flat(segment("C:\\Program Files\\App\\app.exe", "cmdline")).slice(-2), [["\\", "app", "basename"], [".", "exe", "ext"]], "read as a command line, the executable runs to its module extension and has no arguments");
  assert.equal(segment("powershell.exe -enc AAAA", "path").shape, "path");
  assert.equal(segment("10.0.0.1", "text").shape, "text");
  assert.equal(segment("evil.example.com", "hostname").segments[0].kind, "host");
  assert.equal(segment("hello", "nonsense").shape, "text", "an unknown shape name falls through to detection");
});

test("a path with spaces is a path; the same path followed by arguments is a command line", () => {
  assert.equal(segment("C:\\Program Files\\App\\app.exe").shape, "path");
  assert.equal(segment("C:\\Program Files\\App\\app.exe -k").shape, "cmdline");
  assert.equal(segment('"C:\\Program Files\\App\\app.exe"').shape, "cmdline", "a quoted first token is always an executable");
  assert.equal(segment("/usr/bin/python3 script.py").shape, "cmdline", "a module extension after a separator token ends the executable");
  assert.equal(segment("/home/john doe/file.txt").shape, "path", "no flag, no quote, no module extension: a path with a space");
});

test("truncation: a value at the 200-character cut is flagged", () => {
  const long = "C:\\" + "a".repeat(120) + "\\" + "b".repeat(80) + ".exe";
  assert.ok(long.length >= 200);
  const r = segment(long);
  assert.equal(r.truncated, true);
  assert.equal(roundTrip(r), long);
  assert.equal(segment("C:\\short.exe").truncated, false);
  const cut = ("arn:aws:iam::123456789012:user/" + "x".repeat(200)).slice(0, 200);
  assert.equal(segment(cut).shape, "arn", "a cut ARN still reads as an ARN, as shapes.js does");
  assert.equal(segment(cut).truncated, true);
});

test("empty and blank values give no segments", () => {
  assert.deepEqual(segment("").segments, []);
  assert.deepEqual(segment("   ").segments, []);
  assert.deepEqual(segment(null).segments, []);
  assert.equal(segment("  10.0.0.1 ").shape, "ip", "surrounding whitespace is trimmed first");
});

test("quotes in a command line go to separators and tail, never into a segment's text", () => {
  for (const v of ['"a b.exe" -x "y z"', '"a.exe"', 'a.exe "unclosed', '"C:\\x y\\a.exe" "p q" r']) {
    const r = segment(v, "cmdline");
    for (const s of r.segments) assert.ok(!s.text.includes('"'), `${v}: ${s.text}`);
    assert.equal(roundTrip(r), v);
    for (const s of r.segments.filter((x) => x.quoted)) assert.ok(s.sep.endsWith('"'), "a quoted segment's sep ends with the opening quote");
  }
});

test("IPv6: zones, brackets, compression and CIDR each keep their place", () => {
  assert.deepEqual(flat(segment("fe80::1%25eth0")).slice(-1), [["%", "25eth0", "zone"]], "a percent-encoded zone is still a zone");
  assert.equal(segment("[fe80::1%eth0]").tail, "]");
  assert.equal(segment("2001:0db8:0000:0000:0000:0000:0000:0001").segments.length, 8);
  assert.equal(segment("2001:db8::/32").detail, "v6");
  assert.notEqual(segment("10.0.0.0/33").shape, "ip", "a v4 prefix over 32 is not a CIDR");
  assert.notEqual(segment("300.0.0.0/8").shape, "ip", "an octet over 255 is not an address");
  assert.equal(segment("/usr/bin/python3 /tmp/x.py").shape, "cmdline", "a second rooted path is an argument");
});

test("plus-addressing and dotted locals stay on the local side of the @", () => {
  assert.deepEqual(flat(segment("a.b+c.d@x.example")), [["", "a.b", "local"], ["+", "c.d", "tag"], ["@", "x", "label"], [".", "example", "label"]]);
  assert.deepEqual(flat(segment("+lead@x.example")), [["", "+lead", "local"], ["@", "x", "label"], [".", "example", "label"]], "a leading plus is not a tag");
});

test("ARN resource parts keep their own separators, slash or colon", () => {
  const r = segment("arn:aws:ecs:us-east-1:123456789012:task/cluster-a/1234abcd");
  assert.deepEqual(flat(r).slice(4), [[":", "task", "resource_type"], ["/", "cluster-a", "resource"], ["/", "1234abcd", "resource"]]);
  const q = segment("arn:aws:sqs:us-east-1:123456789012:my-queue");
  assert.deepEqual(flat(q).slice(4), [[":", "my-queue", "resource"]], "a resource with no type prefix is a resource");
});
