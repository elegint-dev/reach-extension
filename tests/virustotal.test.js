// app/lib/virustotal.js: the classifier that decides which clicked values
// are ever offered to VirusTotal, and the digest of a v3 report. Pure
// functions; no chrome fake needed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, refusal, pathFor, guiUrlFor, looksLikeKey, summarize, describeError } from "../app/lib/virustotal.js";

test("classify: public IPv4 is an ip", () => {
  assert.deepEqual(classify("8.8.8.8"), { kind: "ip", id: "8.8.8.8" });
  assert.deepEqual(classify("  185.220.101.4 "), { kind: "ip", id: "185.220.101.4" });
});

test("classify: private, loopback, link-local, CGNAT, multicast IPv4 are refused", () => {
  for (const ip of ["10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "127.0.0.1", "169.254.10.10", "100.64.0.1", "100.127.255.255", "0.0.0.0", "224.0.0.1", "255.255.255.255", "192.0.2.1", "198.18.0.1"]) {
    assert.equal(classify(ip), null, ip);
  }
  // Neighbours of the private ranges are still public.
  assert.equal(classify("172.32.0.1").kind, "ip");
  assert.equal(classify("100.128.0.1").kind, "ip");
  assert.equal(classify("11.0.0.1").kind, "ip");
});

test("classify: malformed IPv4 is not an ip (and not a domain either)", () => {
  assert.equal(classify("256.1.1.1"), null);
  assert.equal(classify("1.2.3"), null);
  assert.equal(classify("1.2.3.4.5"), null);
});

test("classify: IPv6", () => {
  assert.deepEqual(classify("2001:4860:4860::8888"), { kind: "ip", id: "2001:4860:4860::8888" });
  assert.deepEqual(classify("2606:4700:4700:0:0:0:0:1111"), { kind: "ip", id: "2606:4700:4700:0:0:0:0:1111" });
  for (const ip of ["::1", "::", "fe80::1", "fd00::1", "fc00:1::1", "ff02::1"]) assert.equal(classify(ip), null, ip);
  assert.equal(classify("2001:db8::1::2"), null, "two :: is malformed");
  assert.equal(classify("2001:db8::1%eth0"), null, "zone id is not accepted");
});

test("classify: hashes by exact hex length, normalised to lower case", () => {
  const md5 = "D41D8CD98F00B204E9800998ECF8427E";
  const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.deepEqual(classify(md5), { kind: "hash", id: md5.toLowerCase() });
  assert.deepEqual(classify(sha1), { kind: "hash", id: sha1 });
  assert.deepEqual(classify(sha256), { kind: "hash", id: sha256 });
  assert.equal(classify(sha1.slice(0, 39)), null, "39 hex is nothing");
  assert.equal(classify(sha256 + "0"), null, "65 hex is nothing");
  assert.equal(classify("g" + md5.slice(1)), null, "non-hex is nothing");
});

test("classify: a 32-hex value on an id field is not offered as an MD5", () => {
  const aid = "0123456789abcdef0123456789abcdef";
  assert.equal(classify(aid, { fieldName: "aid" }), null);
  assert.equal(classify(aid, { fieldName: "cid" }), null);
  assert.equal(classify(aid, { fieldName: "SessionId" }), null);
  assert.equal(classify(aid, { fieldName: "device.id" }), null);
  assert.equal(classify(aid, { fieldName: "MD5HashData" }).kind, "hash");
  assert.equal(classify(aid).kind, "hash");
});

test("classify: hostnames with a public TLD are domains", () => {
  assert.deepEqual(classify("Example.COM"), { kind: "domain", id: "example.com" });
  assert.deepEqual(classify("cdn-1.static.example.co.uk"), { kind: "domain", id: "cdn-1.static.example.co.uk" });
  assert.deepEqual(classify("xn--bcher-kva.com"), { kind: "domain", id: "xn--bcher-kva.com" });
});

test("classify: internal and non-domain strings are refused", () => {
  for (const s of ["dc01.corp.local", "printer.lan", "db.internal", "host.localdomain", "10.in-addr.arpa", "foo.test", "foo.example", "www.example.invalid"]) assert.equal(classify(s), null, s);
  for (const s of ["localhost", "DC01", "some_field", "https://example.com/x", "example.com/path", "user@example.com", "example.com:443", "-bad.example.com", "bad-.example.com", "a..b.com", ".example.com", "example.com.", "example.c0m", "example.123", "", "   ", "C:\\Windows\\cmd.exe", "1.2.3.4:8080"]) {
    assert.equal(classify(s), null, JSON.stringify(s));
  }
  assert.equal(classify("a".repeat(64) + ".com"), null, "a label over 63 chars");
  assert.equal(classify(("a".repeat(60) + ".").repeat(5) + "com"), null, "a name over 253 chars");
});

test("pathFor / guiUrlFor", () => {
  assert.equal(pathFor("ip", "8.8.8.8"), "/ip_addresses/8.8.8.8");
  assert.equal(pathFor("domain", "example.com"), "/domains/example.com");
  assert.equal(pathFor("hash", "abc"), "/files/abc");
  assert.equal(guiUrlFor("ip", "8.8.8.8"), "https://www.virustotal.com/gui/ip-address/8.8.8.8");
  assert.equal(guiUrlFor("domain", "example.com"), "https://www.virustotal.com/gui/domain/example.com");
  assert.equal(guiUrlFor("hash", "abc"), "https://www.virustotal.com/gui/file/abc");
  assert.throws(() => pathFor("url", "x"));
});

test("looksLikeKey", () => {
  assert.equal(looksLikeKey("a".repeat(64)), true);
  assert.equal(looksLikeKey(" " + "0123456789abcdef".repeat(4) + " "), true);
  assert.equal(looksLikeKey("a".repeat(63)), false);
  assert.equal(looksLikeKey("z".repeat(64)), false);
  assert.equal(looksLikeKey(""), false);
  assert.equal(looksLikeKey(null), false);
});

const IP_REPORT = {
  data: {
    id: "185.220.101.4",
    type: "ip_address",
    attributes: {
      as_owner: "Zwiebelfreunde e.V.",
      asn: 208294,
      country: "DE",
      network: "185.220.101.0/24",
      reputation: -12,
      last_analysis_date: 1758000000,
      last_analysis_stats: { malicious: 9, suspicious: 1, harmless: 60, undetected: 24, timeout: 0 },
    },
  },
};

test("summarize: ip", () => {
  const s = summarize("ip", IP_REPORT);
  assert.equal(s.verdict, "malicious");
  assert.deepEqual(s.stats, { malicious: 9, suspicious: 1, harmless: 60, undetected: 24, total: 94 });
  assert.equal(s.reputation, -12);
  assert.equal(s.analysed, "2025-09-16T05:20:00.000Z");
  assert.deepEqual(s.facts, [["owner", "Zwiebelfreunde e.V. (AS208294)"], ["country", "DE"], ["network", "185.220.101.0/24"]]);
});

test("summarize: domain, with categories de-duplicated and capped", () => {
  const s = summarize("domain", {
    data: { attributes: { registrar: "MarkMonitor Inc.", creation_date: 874296000, categories: { a: "search engines", b: "search engines", c: "information technology", d: "x", e: "y", f: "z" }, last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20 } } },
  });
  assert.equal(s.verdict, "clean");
  assert.deepEqual(s.facts, [["registrar", "MarkMonitor Inc."], ["categories", "search engines, information technology, x, y"], ["registered", "1997-09-15"]]);
});

test("summarize: file, suspicious when no vendor says malicious", () => {
  const s = summarize("hash", {
    data: { attributes: { meaningful_name: "invoice.exe", type_description: "Win32 EXE", size: 2621440, first_submission_date: 1700000000, sha256: "e3b0", popular_threat_classification: { suggested_threat_label: "trojan.agent/generic" }, last_analysis_stats: { malicious: 0, suspicious: 2, harmless: 0, undetected: 70 } } },
  });
  assert.equal(s.verdict, "suspicious");
  assert.deepEqual(s.facts, [["threat label", "trojan.agent/generic"], ["name", "invoice.exe"], ["type", "Win32 EXE"], ["size", "2.5 MB"], ["first seen", "2023-11-14"], ["sha256", "e3b0"]]);
});

test("summarize: a zero-byte file shows no size", () => {
  const s = summarize("hash", { data: { attributes: { size: 0, last_analysis_stats: { undetected: 5 } } } });
  assert.deepEqual(s.facts, []);
});

test("summarize: no analysis yet, or no data at all", () => {
  assert.equal(summarize("ip", {}), null);
  assert.equal(summarize("ip", { data: {} }), null);
  const s = summarize("domain", { data: { attributes: {} } });
  assert.equal(s.verdict, "unknown");
  assert.equal(s.stats.total, 0);
  assert.equal(s.analysed, null);
  assert.deepEqual(s.facts, []);
});

test("describeError: one plain sentence per failure", () => {
  assert.match(describeError(401, { error: { code: "WrongCredentialsError" } }), /rejected the API key/);
  assert.match(describeError(401, null), /wants an API key/);
  assert.match(describeError(404, null), /Not in VirusTotal/);
  assert.match(describeError(429, null), /4 lookups a minute and 500 a day/);
  assert.match(describeError(503, null), /having trouble \(503\)/);
  assert.match(describeError(0, null), /network error/);
  assert.equal(describeError(418, { error: { message: "teapot" } }), "VirusTotal: teapot");
  assert.equal(describeError(418, null), "VirusTotal returned 418.");
});

test("refusal: says why a candidate-shaped value gets no offer, and stays quiet for everything else", () => {
  assert.match(refusal("10.0.4.12").why, /private address/);
  assert.match(refusal("203.0.113.5").why, /reserved or documentation/);
  assert.match(refusal("198.51.100.77").why, /reserved or documentation/);
  assert.equal(refusal("203.0.113.5").kind, "ip");
  assert.match(refusal("fe80::1").why, /IPv6/);
  assert.match(refusal("c26d2f327b6a49eebc1432e094ee4a84", { fieldName: "aid" }).why, /identifier on aid/);
  assert.match(refusal("intranet.corp").why, /internal name/);
  assert.equal(refusal("8.8.8.8"), null, "an accepted value has no refusal");
  assert.equal(refusal("CreateAccessKey"), null);
  assert.equal(refusal("arn:aws:iam::1:user/x"), null);
  assert.equal(refusal(""), null);
});
