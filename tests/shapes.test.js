import { test } from "node:test";
import assert from "node:assert/strict";
import { shapeOf, classify, shapeSupports, shapeVeto, numericVeto, detectCve, detectTechnique, detectProcessName, POSITIVE_SHAPES, VETO_ONLY_SHAPES, SUPPORTS, VETOES } from "../app/lib/shapes.js";

test("arn variants and their detail", () => {
  assert.deepEqual(shapeOf("arn:aws:iam::123456789012:user/jdoe"), { shape: "arn", detail: "user" });
  assert.deepEqual(shapeOf("arn:aws:sts::123456789012:assumed-role/AdminRole/session-1"), { shape: "arn", detail: "assumed-role" });
  assert.deepEqual(shapeOf("arn:aws:iam::123456789012:role/AdminRole"), { shape: "arn", detail: "role" });
  assert.equal(shapeOf("arn:aws:sts::123456789012:federated-user/bob").detail, "sts_session");
  assert.equal(shapeOf("not-an-arn"), null);
});

test("access keys and principal ids", () => {
  assert.deepEqual(shapeOf("AKIAIOSFODNN7EXAMPLE"), { shape: "aws_access_key", detail: "long_term" });
  assert.deepEqual(shapeOf("ASIAIOSFODNN7EXAMPLE"), { shape: "aws_access_key", detail: "temporary" });
  assert.equal(shapeOf("AIDAJQABLZS4A3QDU576Q").shape, "aws_principal_id");
  assert.equal(shapeOf("AROAJQABLZS4A3QDU576Q").shape, "aws_principal_id");
  assert.equal(shapeOf("AROAJQABLZS4A3QDU576Q:session-1").shape, "aws_principal_id", "an assumed-role principal id carries its session name");
  assert.equal(shapeOf("akiaiosfodnn7example"), null, "wrong case does not match AWS's own key format");
});

test("windows SID", () => {
  assert.equal(shapeOf("S-1-5-21-3623811015-3361044348-30300820-1013").shape, "sid");
  assert.equal(shapeOf("S-1-5-18").shape, "sid");
  assert.equal(shapeOf("S-1-5"), null, "needs at least one sub-authority beyond the identifier authority");
});

test("upn vs email vs domain", () => {
  assert.equal(shapeOf("jdoe@corp.contoso.com").shape, "upn");
  assert.equal(shapeOf("jdoe@gmail.com").shape, "email");
  assert.equal(shapeOf("jdoe@yahoo.co.uk").shape, "email");
  assert.equal(shapeOf("jdoe@proton.me").shape, "email");
  assert.equal(shapeOf("mailto:jdoe@corp.com"), null, "a scheme prefix is not a local part");
  assert.equal(shapeOf("contoso.com").shape, "domain");
  assert.equal(shapeOf("login.microsoftonline.com").shape, "domain");
  assert.equal(shapeOf("not a domain"), null);
});

test("file names are not domains", () => {
  for (const v of ["svchost.exe", "app.log", "config.json", "run.ps1", "kernel32.dll"]) assert.equal(shapeOf(v), null, v);
});

test("upn and email are labels, never evidence on their own", () => {
  assert.ok(!POSITIVE_SHAPES.has("upn"), "a mailbox column looks exactly like a UPN column");
  assert.ok(!POSITIVE_SHAPES.has("email"));
  assert.ok(shapeSupports("upn", "principal") && shapeSupports("email", "principal"), "both still confirm a principal the name found");
  for (const type of Object.keys(VETOES)) {
    assert.ok(!shapeVeto("upn", type) || !shapeSupports("email", type), `${type}: upn and email never disagree`);
  }
  assert.ok(!shapeVeto("email", "principal") && !shapeVeto("email", "user_id"), "a public-provider address never vetoes an identity");
});

test("guid, hash and hex32 do not collide", () => {
  assert.equal(shapeOf("550e8400-e29b-41d4-a716-446655440000").shape, "guid");
  assert.deepEqual(shapeOf("{550e8400-e29b-41d4-a716-446655440000}"), { shape: "guid", detail: "braced" }, "the Windows/Sysmon braced form is a guid, not json");
  assert.equal(shapeOf("da39a3ee5e6b4b0d3255bfef95601890afd80709").shape, "hash", "40 hex: sha1");
  assert.equal(shapeOf("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"), null, "63 hex chars is neither shape");
  assert.equal(shapeOf("d41d8cd98f00b204e9800998ecf8427e").shape, "hex32", "32 hex chars: md5-shaped, but also a bare id");
});

test("ip v4 and v6", () => {
  assert.deepEqual(shapeOf("10.0.0.1"), { shape: "ip", detail: "v4" });
  assert.equal(shapeOf("256.1.1.1"), null, "octet out of range");
  assert.equal(shapeOf("2001:db8::1").shape, "ip");
  assert.equal(shapeOf("fe80::1ff:fe23:4567:890a").shape, "ip");
  assert.equal(shapeOf("2001:0db8:85a3:0000:0000:8a2e:0370:7334").shape, "ip", "eight groups uncompressed");
  assert.equal(shapeOf("::1").shape, "ip");
  assert.equal(shapeOf("fe80::1%eth0").shape, "ip", "a zone id is part of the address");
  assert.equal(shapeOf("::ffff:10.0.0.1").shape, "ip", "a v4-mapped tail");
  assert.equal(shapeOf("[2001:db8::1]").shape, "ip", "the bracketed URL form");
  assert.equal(shapeOf("[2001:db8::1]:443"), null, "a socket is not an address");
});

test("ip v6 rejects what merely looks like hex and colons", () => {
  for (const v of ["00:1a:2b:3c:4d:5e", "12:34:56", "ab:cd:ef", "::", "2001:::1", "12345:1:1", ":1:2", "1:2:", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7"]) {
    assert.equal(shapeOf(v), null, v);
  }
});

test("epoch seconds vs milliseconds, never plain integer", () => {
  assert.deepEqual(shapeOf("1758140400"), { shape: "epoch", detail: "s" });
  assert.deepEqual(shapeOf("1758140400123"), { shape: "epoch", detail: "ms" });
  assert.equal(shapeOf("42").shape, "integer");
  assert.equal(shapeOf("-42").shape, "integer");
  assert.equal(shapeOf("9999999999").shape, "integer", "ten digits outside the 2001..2099 window is an id, not a time");
  assert.equal(shapeOf("0000000001").shape, "integer");
  assert.equal(shapeOf("0").shape, "integer");
  assert.equal(shapeOf("1").shape, "integer");
});

test("ISO time and JSON text, truncation aware", () => {
  assert.equal(shapeOf("2026-09-18T10:00:00Z").shape, "iso_time");
  assert.equal(shapeOf("2026-09-18 10:00:00.123+00:00").shape, "iso_time");
  assert.equal(shapeOf('{"a":1,"b":[1,2,3]}').shape, "json");
  assert.equal(shapeOf("[1,2,3]").shape, "json");
  // A value cut at 200 chars by recipe.js (Sentinel's TOP_VALUE_MAX):
  // still json-shaped even though it cannot parse.
  const full = '{"requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/Very-Long-Role-Name-' + "x".repeat(200) + '"}}';
  const truncatedJson = full.slice(0, 200);
  assert.equal(truncatedJson.length, 200);
  assert.equal(shapeOf(truncatedJson).shape, "json");
});

test("json needs structure: a brace alone is not json", () => {
  for (const v of ["[INFO] starting", "{DEFAULT}", "{a", "[not json", "[2001:db8::1]", "{550e8400-e29b-41d4-a716-446655440000}"]) {
    const got = shapeOf(v);
    assert.ok(!got || got.shape !== "json", `${v}: ${got && got.shape}`);
  }
  assert.equal(shapeOf("{}").shape, "json");
  assert.equal(shapeOf("[]").shape, "json");
  const truncatedNonJson = "[" + "x".repeat(199);
  assert.equal(shapeOf(truncatedNonJson), null, "a truncated value still needs a JSON opening");
});

test("url and bool", () => {
  assert.equal(shapeOf("https://example.com/path?q=1").shape, "url");
  assert.equal(shapeOf("not a url at all"), null);
  for (const v of ["true", "False", "YES", "no"]) assert.equal(shapeOf(v).shape, "bool", v);
});

test("classify() picks the dominant shape by count share", () => {
  const arnValues = [
    { value: "arn:aws:iam::123456789012:role/A", count: 7 },
    { value: "arn:aws:iam::123456789012:user/B", count: 2 },
    { value: "garbage", count: 1 },
  ];
  const r = classify(arnValues);
  assert.equal(r.shape, "arn");
  assert.equal(r.total, 10);
  assert.equal(r.matched, 9);
  assert.equal(r.share, 0.9);
  assert.equal(r.values, 3, "distinct top values, the count a reader can check");
  assert.equal(r.hits, 2, "distinct top values of the winning shape");
  assert.deepEqual(classify([]), { shape: null, share: 0, matched: 0, total: 0, values: 0, hits: 0 });
  assert.deepEqual(classify([{ value: "", count: 5 }]), { shape: null, share: 0, matched: 0, total: 0, values: 0, hits: 0 });
});

test("classify() on a mixed bag with no majority", () => {
  const r = classify([{ value: "abc", count: 1 }, { value: "def", count: 1 }]);
  assert.equal(r.shape, null, "opaque text is not any detected shape");
});

test("shapeSupports and shapeVeto against taxonomy type ids", () => {
  assert.ok(shapeSupports("arn", "principal"));
  assert.ok(shapeSupports("upn", "principal"));
  assert.ok(shapeSupports("ip", "source_ip"));
  assert.ok(!shapeSupports("ip", "principal"));

  assert.ok(shapeVeto("ip", "principal"), "an address is never a principal");
  assert.ok(shapeVeto("hash", "source_ip"));
  assert.ok(!shapeVeto("arn", "principal"));
  assert.ok(shapeVeto("json", "flag"), "a nested object cannot be a yes/no flag");
  assert.ok(shapeVeto("integer", "raw_object"), "raw_object only accepts json");
  assert.ok(!shapeVeto("json", "raw_object"));
  // The json veto is universal: a type with no VETOES row, or none at all, still refuses an all-JSON column.
  for (const t of ["command_line", "file_path", "user_agent", "event_source", "process_id", "process_uid"]) {
    assert.ok(!VETOES[t] || !VETOES[t].includes("json"), `${t} has no json row of its own`);
    assert.ok(shapeVeto("json", t), `json vetoes ${t}`);
  }
  assert.ok(!shapeVeto("integer", "process_id"), "a type with no row is otherwise unknown, never vetoed");
});

test("positive and veto-only shape sets", () => {
  assert.deepEqual([...POSITIVE_SHAPES].sort(), ["arn", "aws_access_key", "aws_principal_id", "sid"]);
  for (const s of ["ip", "guid", "hash"]) assert.ok(VETO_ONLY_SHAPES.has(s));
  assert.ok(!POSITIVE_SHAPES.has("ip"));
  assert.ok(!VETO_ONLY_SHAPES.has("arn"));
  for (const s of POSITIVE_SHAPES) assert.ok(!VETO_ONLY_SHAPES.has(s), `${s} cannot be both`);
});

test("no shape is both supported and vetoed for one type", () => {
  for (const type of Object.keys(SUPPORTS)) {
    const both = SUPPORTS[type].filter((s) => (VETOES[type] || []).includes(s));
    assert.deepEqual(both, [], `${type}: ${both.join(",")}`);
  }
  assert.ok(shapeSupports("guid", "account_id"), "an Entra tenant id is a GUID-valued account_id");
  assert.ok(!shapeVeto("guid", "account_id"));
});

test("numericVeto: only types whose values are never numbers", () => {
  for (const type of ["principal", "source_ip", "hostname", "file_hash", "raw_object", "user_agent"]) assert.ok(numericVeto(type), type);
  for (const type of ["process_id", "process_uid", "identifier", "outcome", "record_type", "enum", "event_id", "user_id", "session_id", "request_id", "app_id", "flag", "count", "event_time", "account_id"]) {
    assert.ok(!numericVeto(type), `${type}: a type with no shape list, or one a number can satisfy, is never vetoed on numeric alone`);
  }
  assert.ok(shapeSupports("integer", "flag"), "a 0/1 column supports a flag");
  assert.ok(shapeSupports("integer", "event_id"), "a Windows event id is numeric");
  assert.ok(shapeSupports("integer", "process_id"));
});

test("detectCve: CVE-YYYY-NNNN and longer, case-insensitive, not part of SUPPORTS", () => {
  assert.deepEqual(detectCve("CVE-2021-44228"), { shape: "cve", detail: "CVE-2021-44228" });
  assert.deepEqual(detectCve("cve-2021-44228"), { shape: "cve", detail: "CVE-2021-44228" });
  assert.deepEqual(detectCve("  CVE-2024-123456  "), { shape: "cve", detail: "CVE-2024-123456" });
  assert.equal(detectCve("CVE-2021-442"), null, "three digits is short of the minimum four");
  assert.equal(detectCve("CVE-99-44228"), null, "a two-digit year is not a CVE year");
  assert.equal(detectCve("NOT-A-CVE-2021-44228"), null, "anchored: a substring hit does not count");
  assert.equal(detectCve(""), null);
  assert.equal(detectCve(null), null);
  for (const type of Object.keys(SUPPORTS)) assert.ok(!SUPPORTS[type].includes("cve"), `${type}: cve must stay out of SUPPORTS`);
});

test("detectTechnique: T#### and T####.###, case-insensitive, not part of SUPPORTS", () => {
  assert.deepEqual(detectTechnique("T1003.001"), { shape: "technique", detail: "T1003.001" });
  assert.deepEqual(detectTechnique("t1003"), { shape: "technique", detail: "T1003" });
  assert.deepEqual(detectTechnique("  T1566.001  "), { shape: "technique", detail: "T1566.001" });
  assert.equal(detectTechnique("T100"), null, "three digits is short of the required four");
  assert.equal(detectTechnique("T1003.01"), null, "a sub-technique needs three digits");
  assert.equal(detectTechnique("TA0006"), null, "a tactic id is not a technique id");
  assert.equal(detectTechnique("NOT-T1003"), null, "anchored: a substring hit does not count");
  assert.equal(detectTechnique(""), null);
  assert.equal(detectTechnique(null), null);
  for (const type of Object.keys(SUPPORTS)) assert.ok(!SUPPORTS[type].includes("technique"), `${type}: technique must stay out of SUPPORTS`);
});

test("detectProcessName: an executable, driver or library name, bare or in a path, never a bare word", () => {
  assert.deepEqual(detectProcessName("certutil.exe"), { shape: "process_name", detail: "certutil.exe" });
  assert.deepEqual(detectProcessName("C:\\Windows\\System32\\certutil.exe"), { shape: "process_name", detail: "certutil.exe" });
  assert.deepEqual(detectProcessName("iobios64.sys"), { shape: "process_name", detail: "iobios64.sys" });
  assert.deepEqual(detectProcessName("version.dll"), { shape: "process_name", detail: "version.dll" });
  assert.deepEqual(detectProcessName("/usr/bin/find"), { shape: "process_name", detail: "find" });
  assert.equal(detectProcessName("find"), null, "a bare word with no path and no extension is not offered");
  assert.equal(detectProcessName("hello world.exe"), null, "a command line, not a bare name");
  assert.equal(detectProcessName("report.log"), null, "a log file is not a LOL* shape");
  assert.equal(detectProcessName(""), null);
  assert.equal(detectProcessName(null), null);
  for (const type of Object.keys(SUPPORTS)) assert.ok(!SUPPORTS[type].includes("process_name"), `${type}: process_name must stay out of SUPPORTS`);
});
