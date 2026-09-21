import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { build, specFor, lintable, COSTS, ORDER, MAJOR_BREAKERS, TERM_BARE, LINT_COMMANDS, LadderError } from "../app/lib/ladder.js";
import { segment } from "../app/lib/segments.js";
import * as spl from "../app/lib/spl.js";
import * as kql from "../app/lib/kql.js";

const R = String.raw;
const fixture = JSON.parse(readFileSync(new URL("./fixtures/ladder-profile.json", import.meta.url), "utf8"));
const top = (field) => fixture.fields[field].profile.top;

const WIN = R`C:\Windows\System32\cmd.exe`;
const WIN3 = R`C:\a\b\c\cmd.exe`; // three adjacent directories, for the merge tests
const ARN = "arn:aws:iam::123456789012:user/jdoe";
const URLV = "https://evil.example.com/a/b/c.php?id=1";

// Build both platforms and return [construct, text] pairs per platform.
function both(spec, opts) {
  const out = {};
  for (const platform of ["spl", "kql"]) out[platform] = build(spec, { ...opts, platform });
  return out;
}
const pairs = (rungs) => rungs.map((r) => [r.construct, r.text]);
const texts = (rungs) => rungs.map((r) => r.text);

// Unquote a platform string literal the way its parser would, so a regex
// the ladder quoted can be compiled and run against the value.
function unquote(text) {
  assert.ok(text.startsWith('"') && text.endsWith('"'), `quoted: ${text}`);
  return text.slice(1, -1).replace(/\\(.)/g, (m, c) => (c === "n" ? "\n" : c === "t" ? "\t" : c === "r" ? "\r" : c));
}

// ---------------------------------------------------------------------------
// The construct table: value, states, options, expected SPL and KQL texts
// in ladder order, and a fragment of the first rung's why.

const TABLE = [
  {
    name: "windows path, all kept, raw token field: a backslash cannot stand bare in TERM()",
    value: WIN, opts: { field: "Image", fieldClass: "raw_token" },
    spl: [["literal", R`Image="C:\\Windows\\System32\\cmd.exe"`]],
    kql: [["literal", R`Image =~ "C:\\Windows\\System32\\cmd.exe"`]],
    why: { spl: "raw token", kql: "case-insensitive" },
  },
  {
    name: "posix path, all kept, raw token field",
    value: "/usr/bin/python3", opts: { field: "exe", fieldClass: "raw_token" },
    spl: [["term", R`TERM(/usr/bin/python3) exe="/usr/bin/python3"`], ["literal", R`exe="/usr/bin/python3"`]],
    kql: [["literal", R`exe == "/usr/bin/python3"`]],
    why: { spl: "one raw token", kql: "case-sensitive" },
  },
  {
    name: "windows path, all kept, class unknown",
    value: WIN, opts: { field: "Image" },
    spl: [["literal", R`Image="C:\\Windows\\System32\\cmd.exe"`]],
    kql: [["literal", R`Image =~ "C:\\Windows\\System32\\cmd.exe"`]],
    why: { spl: "narrows the scan with the value's own tokens", kql: "case-insensitive" },
  },
  {
    name: "windows path, directory kept, file open",
    value: WIN, states: ["keep", "keep", "keep", "any", "any"], opts: { field: "Image" },
    spl: [["trailing_wildcard", R`Image="C:\\Windows\\System32\\*"`], ["regex", R`| regex Image="(?i)^C:\\\\Windows\\\\System32\\\\.*$"`], ["rex", R`| rex field=Image "(?i)^C:\\\\Windows\\\\System32\\\\(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`Image startswith "C:\\Windows\\System32\\"`], ["regex", R`Image matches regex "(?i)^C:\\\\Windows\\\\System32\\\\.*$"`], ["rex", R`| extend any_1 = extract("(?i)^C:\\\\Windows\\\\System32\\\\(.*)$", 1, Image)`]],
    why: { spl: "trailing wildcard still narrows from the index", kql: "startswith" },
  },
  {
    name: "windows path, file kept, directory open (leading wildcard avoided)",
    value: WIN, states: ["any", "any", "any", "keep", "keep"], opts: { field: "Image" },
    spl: [["like", R`| where like(lower(Image), "%\\cmd.exe")`], ["regex", R`| regex Image="(?i)^.*\\\\cmd\\.exe$"`], ["rex", R`| rex field=Image "(?i)^(?<any_1>.*)\\\\cmd\\.exe$"`]],
    kql: [["like", R`Image endswith "\\cmd.exe"`], ["regex", R`Image matches regex "(?i)^.*\\\\cmd\\.exe$"`], ["rex", R`| extend any_1 = extract("(?i)^(.*)\\\\cmd\\.exe$", 1, Image)`]],
    why: { spl: "leading wildcard avoided", kql: "endswith" },
  },
  {
    name: "windows path, one directory kept in the middle (has is wider)",
    value: WIN, states: ["any", "keep", "any", "any", "any"], opts: { field: "Image" },
    spl: [["like", R`| where like(lower(Image), "%\\windows\\%")`], ["regex", R`| regex Image="(?i)^.*\\\\Windows\\\\.*$"`], ["rex", R`| rex field=Image "(?i)^(?<any_1>.*)\\\\Windows\\\\(?<any_2>.*)$"`]],
    kql: [["term", R`Image has "Windows"`], ["like", R`Image contains "\\Windows\\"`], ["regex", R`Image matches regex "(?i)^.*\\\\Windows\\\\.*$"`], ["rex", R`| extend any_1 = extract("(?i)^(.*)\\\\Windows\\\\(.*)$", 1, Image), any_2 = extract("(?i)^(.*)\\\\Windows\\\\(.*)$", 2, Image)`]],
    why: { spl: "leading wildcard avoided", kql: "term index" },
  },
  {
    name: "windows path, one directory like (one path segment)",
    value: WIN, states: ["keep", "keep", "like", "keep", "keep"], opts: { field: "Image" },
    spl: [["regex", R`| regex Image="(?i)^C:\\\\Windows\\\\[^\\\\/]+\\\\cmd\\.exe$"`], ["rex", R`| rex field=Image "(?i)^C:\\\\Windows\\\\(?<dir_1>[^\\\\/]+)\\\\cmd\\.exe$"`]],
    kql: [["regex", R`Image matches regex "(?i)^C:\\\\Windows\\\\[^\\\\/]+\\\\cmd\\.exe$"`], ["rex", R`| extend dir_1 = extract("(?i)^C:\\\\Windows\\\\([^\\\\/]+)\\\\cmd\\.exe$", 1, Image)`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "cloudtrail arn, user open, search-time field with a dotted name",
    value: ARN, states: ["keep", "keep", "keep", "keep", "keep", "any"], opts: { field: "userIdentity.arn", fieldClass: "search_time" },
    spl: [["trailing_wildcard", R`userIdentity.arn="arn:aws:iam::123456789012:user/*"`], ["regex", R`| regex userIdentity.arn="(?i)^arn:aws:iam::123456789012:user/.*$"`], ["rex", R`| rex field=userIdentity.arn "(?i)^arn:aws:iam::123456789012:user/(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`tostring(userIdentity.arn) startswith "arn:aws:iam::123456789012:user/"`], ["regex", R`tostring(userIdentity.arn) matches regex "^arn:aws:iam::123456789012:user/.*$"`], ["rex", R`| extend any_1 = extract("^arn:aws:iam::123456789012:user/(.*)$", 1, tostring(userIdentity.arn))`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "cloudtrail arn, account open (wildcard inside the value)",
    value: ARN, states: ["keep", "keep", "keep", "any", "keep", "keep"], opts: { field: "userIdentity.arn" },
    spl: [["wildcard", R`userIdentity.arn="arn:aws:iam::*:user/jdoe"`], ["regex", R`| regex userIdentity.arn="(?i)^arn:aws:iam::.*:user/jdoe$"`], ["rex", R`| rex field=userIdentity.arn "(?i)^arn:aws:iam::(?<any_1>.*):user/jdoe$"`]],
    kql: [["wildcard", R`tostring(userIdentity.arn) startswith "arn:aws:iam::" and tostring(userIdentity.arn) endswith ":user/jdoe" and strlen(tostring(userIdentity.arn)) >= 23`], ["regex", R`tostring(userIdentity.arn) matches regex "^arn:aws:iam::.*:user/jdoe$"`], ["rex", R`| extend any_1 = extract("^arn:aws:iam::(.*):user/jdoe$", 1, tostring(userIdentity.arn))`]],
    why: { spl: "wildcard inside the value", kql: "strlen" },
  },
  {
    name: "cloudtrail arn, account like (twelve digits)",
    value: ARN, states: ["keep", "keep", "keep", "like", "keep", "keep"], opts: { field: "userIdentity.arn" },
    spl: [["regex", R`| regex userIdentity.arn="(?i)^arn:aws:iam::\\d{12}:user/jdoe$"`], ["rex", R`| rex field=userIdentity.arn "(?i)^arn:aws:iam::(?<account_1>\\d{12}):user/jdoe$"`]],
    kql: [["regex", R`tostring(userIdentity.arn) matches regex "^arn:aws:iam::\\d{12}:user/jdoe$"`], ["rex", R`| extend account_1 = extract("^arn:aws:iam::(\\d{12}):user/jdoe$", 1, tostring(userIdentity.arn))`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "url, host kept, path open",
    value: URLV, states: ["keep", "keep", "any", "any", "any", "any", "any"], opts: { field: "url" },
    spl: [["trailing_wildcard", R`url="https://evil.example.com/*"`], ["regex", R`| regex url="(?i)^https://evil\\.example\\.com/.*$"`], ["rex", R`| rex field=url "(?i)^https://evil\\.example\\.com/(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`url startswith "https://evil.example.com/"`], ["regex", R`url matches regex "^https://evil\\.example\\.com/.*$"`], ["rex", R`| extend any_1 = extract("^https://evil\\.example\\.com/(.*)$", 1, url)`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "url, host kept, scheme and path open",
    value: URLV, states: ["any", "keep", "any", "any", "any", "any", "any"], opts: { field: "url" },
    spl: [["like", R`| where like(lower(url), "%://evil.example.com/%")`], ["regex", R`| regex url="(?i)^.*://evil\\.example\\.com/.*$"`], ["rex", R`| rex field=url "(?i)^(?<any_1>.*)://evil\\.example\\.com/(?<any_2>.*)$"`]],
    kql: [["like", R`url contains "://evil.example.com/"`], ["regex", R`url matches regex "^.*://evil\\.example\\.com/.*$"`], ["rex", R`| extend any_1 = extract("^(.*)://evil\\.example\\.com/(.*)$", 1, url), any_2 = extract("^(.*)://evil\\.example\\.com/(.*)$", 2, url)`]],
    why: { spl: "leading wildcard avoided", kql: "contains" },
  },
  {
    name: "url, query like",
    value: URLV, states: ["keep", "keep", "keep", "keep", "keep", "keep", "like"], opts: { field: "url" },
    spl: [["regex", R`| regex url="(?i)^https://evil\\.example\\.com/a/b/c\\.php\\?[^&#]*$"`], ["rex", R`| rex field=url "(?i)^https://evil\\.example\\.com/a/b/c\\.php\\?(?<query_1>[^&#]*)$"`]],
    kql: [["regex", R`url matches regex "^https://evil\\.example\\.com/a/b/c\\.php\\?[^&#]*$"`], ["rex", R`| extend query_1 = extract("^https://evil\\.example\\.com/a/b/c\\.php\\?([^&#]*)$", 1, url)`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "ipv4, two octets kept: a /16",
    value: "10.0.1.2", states: ["keep", "keep", "any", "any"], opts: { field: "src_ip" },
    spl: [["trailing_wildcard", R`src_ip="10.0.*"`], ["cidr", R`src_ip="10.0.0.0/16"`], ["regex", R`| regex src_ip="(?i)^10\\.0\\..*$"`], ["rex", R`| rex field=src_ip "(?i)^10\\.0\\.(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`src_ip startswith "10.0."`], ["cidr", R`ipv4_is_in_range(src_ip, "10.0.0.0/16")`], ["regex", R`src_ip matches regex "^10\\.0\\..*$"`], ["rex", R`| extend any_1 = extract("^10\\.0\\.(.*)$", 1, src_ip)`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "ipv4, second octet open: no network, a wildcard",
    value: "10.0.1.2", states: ["keep", "any", "keep", "keep"], opts: { field: "src_ip" },
    spl: [["wildcard", R`src_ip="10.*.1.2"`], ["regex", R`| regex src_ip="(?i)^10\\..*\\.1\\.2$"`], ["rex", R`| rex field=src_ip "(?i)^10\\.(?<any_1>.*)\\.1\\.2$"`]],
    kql: [["wildcard", R`src_ip startswith "10." and src_ip endswith ".1.2" and strlen(src_ip) >= 7`], ["regex", R`src_ip matches regex "^10\\..*\\.1\\.2$"`], ["rex", R`| extend any_1 = extract("^10\\.(.*)\\.1\\.2$", 1, src_ip)`]],
    why: { spl: "wildcard inside", kql: "strlen" },
  },
  {
    name: "ipv4 cidr value kept",
    value: "10.0.0.0/8", opts: { field: "src_ip" },
    spl: [["literal", R`src_ip="10.0.0.0/8"`]],
    kql: [["literal", R`src_ip == "10.0.0.0/8"`], ["cidr", R`ipv4_is_in_range(src_ip, "10.0.0.0/8")`]],
    why: { spl: "CIDR block", kql: "case-sensitive" },
  },
  {
    name: "ipv6 uncompressed, two groups kept: a /32",
    value: "2001:db8:0:0:0:0:0:1", states: ["keep", "keep", "any", "any", "any", "any", "any", "any"], opts: { field: "ip" },
    spl: [["trailing_wildcard", R`ip="2001:db8:*"`], ["cidr", R`ip="2001:db8:0:0:0:0:0:0/32"`], ["regex", R`| regex ip="(?i)^2001:db8:.*$"`], ["rex", R`| rex field=ip "(?i)^2001:db8:(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`ip startswith "2001:db8:"`], ["cidr", R`ipv6_is_in_range(ip, "2001:db8:0:0:0:0:0:0/32")`], ["regex", R`ip matches regex "^2001:db8:.*$"`], ["rex", R`| extend any_1 = extract("^2001:db8:(.*)$", 1, ip)`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "ipv6 with a zone, zone open",
    value: "fe80::1%eth0", states: ["keep", "keep", "keep", "any"], opts: { field: "ip" },
    spl: [["trailing_wildcard", R`ip="fe80::1%*"`], ["regex", R`| regex ip="(?i)^fe80::1%.*$"`], ["rex", R`| rex field=ip "(?i)^fe80::1%(?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`ip startswith "fe80::1%"`], ["regex", R`ip matches regex "^fe80::1%.*$"`], ["rex", R`| extend any_1 = extract("^fe80::1%(.*)$", 1, ip)`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "email, plus tag open",
    value: "jdoe+news@gmail.com", states: ["keep", "any", "keep", "keep"], opts: { field: "sender" },
    spl: [["wildcard", R`sender="jdoe+*@gmail.com"`], ["regex", R`| regex sender="(?i)^jdoe\\+.*@gmail\\.com$"`], ["rex", R`| rex field=sender "(?i)^jdoe\\+(?<any_1>.*)@gmail\\.com$"`]],
    kql: [["wildcard", R`sender startswith "jdoe+" and sender endswith "@gmail.com" and strlen(sender) >= 15`], ["regex", R`sender matches regex "^jdoe\\+.*@gmail\\.com$"`], ["rex", R`| extend any_1 = extract("^jdoe\\+(.*)@gmail\\.com$", 1, sender)`]],
    why: { spl: "wildcard inside", kql: "strlen" },
  },
  {
    name: "email, any mailbox at the domain",
    value: "jdoe+news@gmail.com", states: ["any", "any", "keep", "keep"], opts: { field: "sender" },
    spl: [["like", R`| where like(lower(sender), "%@gmail.com")`], ["regex", R`| regex sender="(?i)^.*@gmail\\.com$"`], ["rex", R`| rex field=sender "(?i)^(?<any_1>.*)@gmail\\.com$"`]],
    kql: [["like", R`sender endswith "@gmail.com"`], ["regex", R`sender matches regex "^.*@gmail\\.com$"`], ["rex", R`| extend any_1 = extract("^(.*)@gmail\\.com$", 1, sender)`]],
    why: { spl: "leading wildcard avoided", kql: "endswith" },
  },
  {
    name: "guid, every group like",
    value: "550e8400-e29b-41d4-a716-446655440000", states: ["like", "like", "like", "like", "like"], opts: { field: "LogonGuid" },
    spl: [["regex", R`| regex LogonGuid="(?i)^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"`], ["rex", R`| rex field=LogonGuid "(?i)^(?<hex_1>[0-9a-fA-F]{8})-(?<hex_2>[0-9a-fA-F]{4})-(?<hex_3>[0-9a-fA-F]{4})-(?<hex_4>[0-9a-fA-F]{4})-(?<hex_5>[0-9a-fA-F]{12})$"`]],
    kql: [["regex", R`LogonGuid matches regex "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"`], ["rex", R`| extend hex_1 = extract("^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$", 1, LogonGuid), hex_2 = extract("^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$", 2, LogonGuid), hex_3 = extract("^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$", 3, LogonGuid), hex_4 = extract("^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$", 4, LogonGuid), hex_5 = extract("^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$", 5, LogonGuid)`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "sid, the RID like (digits)",
    value: "S-1-5-21-3623811015-3361044348-30300820-1013", states: ["keep", "keep", "keep", "keep", "keep", "keep", "keep", "like"], opts: { field: "sid" },
    spl: [["regex", R`| regex sid="(?i)^S-1-5-21-3623811015-3361044348-30300820-\\d+$"`], ["rex", R`| rex field=sid "(?i)^S-1-5-21-3623811015-3361044348-30300820-(?<digits_1>\\d+)$"`]],
    kql: [["regex", R`sid matches regex "^S-1-5-21-3623811015-3361044348-30300820-\\d+$"`], ["rex", R`| extend digits_1 = extract("^S-1-5-21-3623811015-3361044348-30300820-(\\d+)$", 1, sid)`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "command line, encoded argument open, quoted executable",
    value: R`"C:\Program Files\App\app.exe" -enc AAAA`, states: ["keep", "keep", "keep", "keep", "keep", "keep", "any"], opts: { field: "CommandLine" },
    spl: [["trailing_wildcard", R`CommandLine="\"C:\\Program Files\\App\\app.exe\" -enc *"`], ["regex", R`| regex CommandLine="(?i)^\"C:\\\\Program Files\\\\App\\\\app\\.exe\" -enc .*$"`], ["rex", R`| rex field=CommandLine "(?i)^\"C:\\\\Program Files\\\\App\\\\app\\.exe\" -enc (?<any_1>.*)$"`]],
    kql: [["trailing_wildcard", R`CommandLine startswith "\"C:\\Program Files\\App\\app.exe\" -enc "`], ["regex", R`CommandLine matches regex "(?i)^\"C:\\\\Program Files\\\\App\\\\app\\.exe\" -enc .*$"`], ["rex", R`| extend any_1 = extract("(?i)^\"C:\\\\Program Files\\\\App\\\\app\\.exe\" -enc (.*)$", 1, CommandLine)`]],
    why: { spl: "trailing wildcard", kql: "startswith" },
  },
  {
    name: "literal set",
    spec: { values: ["cmd.exe", "powershell.exe", 'a"b'] }, opts: { field: "Image" },
    spl: [["in", R`Image IN ("cmd.exe", "powershell.exe", "a\"b")`]],
    kql: [["in", R`Image in ("cmd.exe", "powershell.exe", "a\"b")`]],
    why: { spl: "3 values", kql: "3 values" },
  },
  {
    name: "literal set, case-insensitive",
    spec: { values: ["cmd.exe", "CMD.EXE", "powershell.exe"] }, opts: { field: "Image", ci: true },
    spl: [["in", R`Image IN ("cmd.exe", "CMD.EXE", "powershell.exe")`]],
    kql: [["in", R`Image in~ ("cmd.exe", "CMD.EXE", "powershell.exe")`]],
    why: { spl: "3 values", kql: "in~" },
  },
  {
    name: "literal set of one is a literal",
    spec: { values: ["cmd.exe"] }, opts: { field: "Image", fieldClass: "indexed" },
    spl: [["term", R`TERM(cmd.exe) Image="cmd.exe"`], ["literal", R`Image="cmd.exe"`]],
    kql: [["literal", R`Image == "cmd.exe"`]],
    why: { spl: "indexed token", kql: "case-sensitive" },
  },
  {
    name: "a value with a star is compared in a where stage",
    value: "a*b", opts: { field: "x", fieldClass: "indexed" },
    spl: [["literal", R`| where x="a*b"`]],
    kql: [["literal", R`x == "a*b"`]],
    why: { spl: "compares the whole string", kql: "case-sensitive" },
  },
  {
    name: "pipeline-derived field: terms become | search stages",
    value: "cmd.exe", opts: { field: "proc", fieldClass: "pipeline_derived" },
    spl: [["literal", R`| search proc="cmd.exe"`]],
    kql: [["literal", R`proc == "cmd.exe"`]],
    why: { spl: "after the stage that derives it", kql: "case-sensitive" },
  },
  {
    name: "sentinel dynamic column",
    value: "cmd.exe", opts: { field: "Properties", dynamic: true },
    spl: [["literal", R`Properties="cmd.exe"`]],
    kql: [["literal", R`tostring(Properties) == "cmd.exe"`]],
    why: { spl: "exact match", kql: "case-sensitive" },
  },
  {
    name: "kept text with an underscore skips like() and keeps the regex",
    value: R`C:\Windows\evil_x.exe`, states: ["any", "any", "keep", "keep"], opts: { field: "Image" },
    spl: [["regex", R`| regex Image="(?i)^.*\\\\evil_x\\.exe$"`], ["rex", R`| rex field=Image "(?i)^(?<any_1>.*)\\\\evil_x\\.exe$"`]],
    kql: [["like", R`Image endswith "\\evil_x.exe"`], ["regex", R`Image matches regex "(?i)^.*\\\\evil_x\\.exe$"`], ["rex", R`| extend any_1 = extract("(?i)^(.*)\\\\evil_x\\.exe$", 1, Image)`]],
    why: { spl: "leading wildcard avoided", kql: "endswith" },
  },
  {
    name: "windows path, two adjacent directories open: one star, not two",
    value: WIN, states: ["keep", "any", "any", "keep", "keep"], opts: { field: "Image" },
    spl: [["wildcard", R`Image="C:\\*\\cmd.exe"`], ["regex", R`| regex Image="(?i)^C:\\\\.*\\\\cmd\\.exe$"`], ["rex", R`| rex field=Image "(?i)^C:\\\\(?<any_1>.*)\\\\cmd\\.exe$"`]],
    kql: [["wildcard", R`Image startswith "C:\\" and Image endswith "\\cmd.exe" and strlen(Image) >= 11`], ["regex", R`Image matches regex "(?i)^C:\\\\.*\\\\cmd\\.exe$"`], ["rex", R`| extend any_1 = extract("(?i)^C:\\\\(.*)\\\\cmd\\.exe$", 1, Image)`]],
    why: { spl: "wildcard", kql: "strlen" },
  },
  {
    name: "windows path, three adjacent directories open: still one star",
    value: WIN3, states: ["keep", "any", "any", "any", "keep", "keep"], opts: { field: "Image" },
    spl: [["wildcard", R`Image="C:\\*\\cmd.exe"`], ["regex", R`| regex Image="(?i)^C:\\\\.*\\\\cmd\\.exe$"`], ["rex", R`| rex field=Image "(?i)^C:\\\\(?<any_1>.*)\\\\cmd\\.exe$"`]],
    kql: [["wildcard", R`Image startswith "C:\\" and Image endswith "\\cmd.exe" and strlen(Image) >= 11`], ["regex", R`Image matches regex "(?i)^C:\\\\.*\\\\cmd\\.exe$"`], ["rex", R`| extend any_1 = extract("(?i)^C:\\\\(.*)\\\\cmd\\.exe$", 1, Image)`]],
    why: { spl: "wildcard", kql: "strlen" },
  },
  {
    name: "windows path, two adjacent directories like: exactly two levels, a repeated character class",
    value: WIN, states: ["keep", "like", "like", "keep", "keep"], opts: { field: "Image" },
    spl: [["regex", R`| regex Image="(?i)^C:\\\\[^\\\\/]+\\\\[^\\\\/]+\\\\cmd\\.exe$"`], ["rex", R`| rex field=Image "(?i)^C:\\\\(?<dir_1>[^\\\\/]+)\\\\(?<dir_2>[^\\\\/]+)\\\\cmd\\.exe$"`]],
    kql: [["regex", R`Image matches regex "(?i)^C:\\\\[^\\\\/]+\\\\[^\\\\/]+\\\\cmd\\.exe$"`], ["rex", R`| extend dir_1 = extract("(?i)^C:\\\\([^\\\\/]+)\\\\([^\\\\/]+)\\\\cmd\\.exe$", 1, Image), dir_2 = extract("(?i)^C:\\\\([^\\\\/]+)\\\\([^\\\\/]+)\\\\cmd\\.exe$", 2, Image)`]],
    why: { spl: "character class", kql: "character class" },
  },
  {
    name: "domain, three adjacent labels like: exactly three labels, one class per label",
    spec: specFor("a.b.c.example.com", ["like", "like", "like", "keep", "keep"], "domain"), opts: { field: "host" },
    spl: [["regex", R`| regex host="(?i)^[^.@]+\\.[^.@]+\\.[^.@]+\\.example\\.com$"`], ["rex", R`| rex field=host "(?i)^(?<label_1>[^.@]+)\\.(?<label_2>[^.@]+)\\.(?<label_3>[^.@]+)\\.example\\.com$"`]],
    kql: [["regex", R`host matches regex "^[^.@]+\\.[^.@]+\\.[^.@]+\\.example\\.com$"`], ["rex", R`| extend label_1 = extract("^([^.@]+)\\.([^.@]+)\\.([^.@]+)\\.example\\.com$", 1, host), label_2 = extract("^([^.@]+)\\.([^.@]+)\\.([^.@]+)\\.example\\.com$", 2, host), label_3 = extract("^([^.@]+)\\.([^.@]+)\\.([^.@]+)\\.example\\.com$", 3, host)`]],
    why: { spl: "character class", kql: "character class" },
  },
];

for (const row of TABLE) {
  test(`ladder: ${row.name}`, () => {
    const spec = row.spec || (row.states ? specFor(row.value, row.states) : row.value);
    const got = both(spec, row.opts);
    assert.deepEqual(pairs(got.spl), row.spl, "spl");
    assert.deepEqual(pairs(got.kql), row.kql, "kql");
    for (const platform of ["spl", "kql"]) {
      const first = got[platform][0];
      assert.ok(first.why.includes(row.why[platform]), `${platform} why: ${first.why}`);
      for (const r of got[platform]) {
        assert.equal(r.why.split("\n").length, 1, "why is one line");
        assert.ok(["term", "stage"].includes(r.form));
        assert.equal(r.form === "stage", r.text.startsWith("| "), `${platform} ${r.construct}: stage form starts with a pipe`);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Properties over a pool of values and state assignments

const POOL = [
  WIN, R`C:\Program Files\App\app.exe`, R`C:\Users\a b\evil_x(1).exe`, R`\\srv\share\f.txt`, "/usr/bin/python3", R`HKLM\SOFTWARE\Run`,
  R`"C:\Program Files\App\app.exe" --flag "some value"`, "powershell.exe -enc AAAA", "cmd /c whoami", ARN, "arn:aws:s3:::my-bucket/path/to/key.txt",
  URLV, "https://user:pw@evil.example.com:8443/a/b/c.php?id=1&x=y#frag", "jdoe+news@gmail.com", "jdoe@corp.contoso.com", "10.0.1.2", "10.0.0.0/8",
  "2001:db8::1", "fe80::1%eth0", "[::1]", "evil.example.com", "550e8400-e29b-41d4-a716-446655440000", "{550e8400-e29b-41d4-a716-446655440000}",
  "S-1-5-21-3623811015-3361044348-30300820-1013", "User admin logged on", "a.b$c^d|e", 'q"uote', "a+b?c", "x[1].y{2}", "4688", "hello", "tab\there",
];

function assignments(n) {
  const all = (s) => new Array(n).fill(s);
  const out = [all("keep"), all("any"), all("like")];
  if (n > 1) {
    out.push(["any", ...all("keep").slice(1)]);
    out.push([...all("keep").slice(1), "any"]);
    out.push(all("keep").map((s, i) => (i % 2 ? "any" : "keep")));
    out.push(all("keep").map((s, i) => (i % 2 ? "keep" : "like")));
    out.push(all("keep").map((s, i) => (i === Math.floor(n / 2) ? "keep" : "any")));
    out.push(all("keep").map((s, i) => (i === Math.floor(n / 2) ? "like" : "keep")));
  }
  return out;
}

function* everySpec() {
  for (const value of POOL) {
    const n = segment(value).segments.length;
    for (const states of assignments(n)) yield { value, states, spec: specFor(value, states) };
  }
}

const CLASSES = [undefined, "indexed", "raw_token", "search_time", "calculated", "lookup_output", "pipeline_derived"];

test("every rung lints clean on its platform, wrapped as lintable() says", () => {
  let n = 0;
  for (const { spec } of everySpec()) {
    for (const fieldClass of CLASSES) {
      for (const r of build(spec, { platform: "spl", field: "f", fieldClass })) {
        assert.deepEqual(spl.lint(lintable(r), { commands: LINT_COMMANDS }), { ok: true, violations: [], warnings: [] }, r.text);
        n++;
      }
      for (const r of build(spec, { platform: "kql", field: "f", fieldClass })) {
        assert.deepEqual(kql.lint(lintable(r)).violations, [], r.text);
        n++;
      }
    }
  }
  assert.ok(n > 1000, `checked ${n} rungs`);
});

test("escaping round trip: the value a spec came from matches every rung built from it", () => {
  for (const { value, spec } of everySpec()) {
    for (const platform of ["spl", "kql"]) {
      for (const r of build(spec, { platform, field: "f", samples: [{ value, count: 1 }] })) {
        assert.deepEqual(r.preview, { matched: 1, total: 1, hits: 1 }, `${platform} ${r.construct} ${r.text} against ${value}`);
      }
    }
  }
});

test("escaping round trip: the quoted regex, unquoted the way the platform would, compiles and matches the value", () => {
  let rexes = 0;
  for (const { value, spec } of everySpec()) {
    for (const platform of ["spl", "kql"]) {
      for (const r of build(spec, { platform, field: "f" })) {
        if (r.construct !== "regex" && r.construct !== "rex") continue;
        let quoted;
        if (r.construct === "regex") quoted = platform === "spl" ? r.text.slice(r.text.indexOf("=") + 1) : r.text.slice(r.text.indexOf("regex ") + 6);
        else quoted = platform === "spl" ? r.text.slice(r.text.indexOf(' "') + 1) : r.text.slice(r.text.indexOf("extract(") + 8, r.text.indexOf('", ') + 1);
        const src = unquote(quoted);
        const flags = src.startsWith("(?i)") ? "i" : "";
        const re = new RegExp(src.replace(/^\(\?i\)/, ""), flags);
        const m = re.exec(value);
        assert.ok(m, `${platform}: ${src} matches ${value}`);
        if (r.construct === "regex") {
          assert.equal(src.replace(/^\(\?i\)/, ""), r.pattern, "the quoted source is the preview pattern");
          continue;
        }
        rexes++;
        const expected = platform === "spl" ? (r.text.match(/\(\?</g) || []).length : (r.text.match(/extract\(/g) || []).length;
        assert.equal(m.length - 1, expected, `${platform}: ${r.text} has one capture group per extracted field`);
        for (let i = 1; i < m.length; i++) assert.notEqual(m[i], undefined, `group ${i} captured`);
        if (platform === "spl") assert.deepEqual(Object.keys(m.groups).length, expected, "named groups");
        if (platform === "kql") {
          const calls = [...r.text.matchAll(/extract\("(?:[^"\\]|\\.)*", (\d+), f\)/g)].map((x) => Number(x[1]));
          assert.deepEqual(calls, calls.map((c, i) => i + 1), "extract() asks for groups 1..n in order");
        }
      }
    }
  }
  assert.ok(rexes > 100, `checked ${rexes} rex rungs`);
});

test("regex metacharacters in a kept value are matched literally, not as syntax", () => {
  const nasty = "a.b$c^d|e(f)[g]{h}+i?j\\k";
  for (const platform of ["spl", "kql"]) {
    const rungs = build(specFor(nasty, ["keep", "any"]), { platform, field: "f", samples: [{ value: nasty + "tail", count: 1 }, { value: "aXb$c^d|e(f)[g]{h}+i?j\\k", count: 1 }] });
    const regex = rungs.find((r) => r.construct === "regex");
    assert.deepEqual(regex.preview, { matched: 1, total: 2, hits: 1 }, "the dot does not match X");
  }
});

test("a leading wildcard is never emitted as a search term or a startswith", () => {
  for (const { spec } of everySpec()) {
    for (const r of build(spec, { platform: "spl", field: "f" })) {
      if (r.form !== "term") continue;
      assert.ok(!/f=\*|f="\*|f="%/.test(r.text), `spl term opens with a wildcard: ${r.text}`);
      assert.ok(!/^\| search f="?\*/.test(r.text), r.text);
    }
    for (const r of build(spec, { platform: "kql", field: "f" })) {
      assert.ok(!/startswith ""/.test(r.text), `kql startswith nothing: ${r.text}`);
      assert.ok(!/(startswith|has|contains|endswith) "\*/.test(r.text), r.text);
    }
  }
});

test("an adjacent-any run never emits two stars: one wildcard for the whole run, on both platforms", () => {
  let checked = 0;
  for (const { spec } of everySpec()) {
    for (const platform of ["spl", "kql"]) {
      for (const r of build(spec, { platform, field: "f" })) {
        if (r.construct !== "wildcard" && r.construct !== "trailing_wildcard") continue;
        assert.ok(!r.text.includes("**"), `${platform} ${r.construct}: two adjacent stars: ${r.text}`);
        checked++;
      }
    }
  }
  assert.ok(checked > 20, `checked ${checked} wildcard rungs`);
});

test("an ip run pushed to exactly-N (like) drops the wildcard rungs and prefers cidr over the depth regex", () => {
  for (const [value, states, shape] of [
    ["10.0.1.2", ["keep", "keep", "like", "like"], "ip"],
    ["2001:db8:0:0:0:0:0:1", ["keep", "keep", "like", "like", "like", "like", "like", "like"], "ip"],
  ]) {
    for (const platform of ["spl", "kql"]) {
      const rungs = build(specFor(value, states, shape), { platform, field: "ip" });
      assert.ok(!rungs.some((r) => r.construct === "wildcard" || r.construct === "trailing_wildcard"), `${platform}: a like run still reads as a wildcard`);
      assert.equal(rungs[0].construct, "cidr", `${platform}: cidr is cheapest once the octets are like, not a depth regex`);
    }
  }
});

test("a spec that opens its first segment reaches like and regex with the no-index caveat, never a term-form wildcard", () => {
  for (const value of [WIN, URLV, "jdoe@corp.contoso.com", "10.0.1.2"]) {
    const n = segment(value).segments.length;
    const spec = specFor(value, ["any", ...new Array(n - 1).fill("keep")]);
    const rungs = build(spec, { platform: "spl", field: "f" });
    assert.ok(rungs.every((r) => r.form === "stage"), `${value}: every rung is a stage`);
    assert.ok(rungs.some((r) => r.construct === "like" || r.construct === "regex"));
    for (const r of rungs.filter((r) => r.construct !== "rex")) assert.ok(r.caveats.some((c) => c.includes("no index help")), `${r.construct}: ${r.caveats}`);
    const k = build(spec, { platform: "kql", field: "f" });
    assert.ok(k.every((r) => !r.text.includes("startswith")));
  }
});

test("TERM() is emitted iff the field class is raw_token or indexed and the value is one indexed token", () => {
  const values = [...POOL, "C:\\Windows\\a-b_c.d", "x%20y", "a--b", "a,b", "a=b", "10.0.0.1", "a b", "a|b", "a;b", "a(b)", "a'b", "a&b", "x%3Ay", "x%2Fy"];
  let emitted = 0;
  for (const value of values) {
    for (const fieldClass of CLASSES) {
      const rungs = build(value, { platform: "spl", field: "f", fieldClass });
      const term = rungs.find((r) => r.construct === "term");
      const expected = (fieldClass === "raw_token" || fieldClass === "indexed") && TERM_BARE.test(value) && !MAJOR_BREAKERS.test(value);
      assert.equal(Boolean(term), expected, `${fieldClass}: ${value}`);
      if (term) {
        emitted++;
        assert.equal(term.cost, 0);
        assert.equal(rungs[0].construct, "term", "TERM is the cheapest rung when present");
        assert.ok(/^TERM\(.+\) f="/.test(term.text), term.text);
      }
    }
  }
  assert.ok(emitted > 10);
  assert.ok(MAJOR_BREAKERS.test("a b") && MAJOR_BREAKERS.test("a--b") && MAJOR_BREAKERS.test("x%20y") && MAJOR_BREAKERS.test("a*b"));
  assert.ok(!MAJOR_BREAKERS.test("C:\\Windows\\a-b_c.d") && !MAJOR_BREAKERS.test("10.0.0.1") && !MAJOR_BREAKERS.test("a=b") && !MAJOR_BREAKERS.test("x%2Fy"));
  assert.equal(build(WIN, { platform: "spl", field: "f", fieldClass: "raw_token" })[0].construct, "literal", "a backslash cannot stand bare inside TERM(), so a Windows path takes the literal rung");
  assert.equal(build("10.0.0.1", { platform: "spl", field: "f", fieldClass: "indexed" })[0].text, R`TERM(10.0.0.1) f="10.0.0.1"`, "minor breakers only: bare");
  assert.equal(build("arn:aws:iam::123456789012:user/jdoe", { platform: "spl", field: "f", fieldClass: "indexed" })[0].text, `TERM(${ARN}) f="${ARN}"`, "an ARN is one token");
  for (const r of build("x", { platform: "spl", field: "f", fieldClass: "indexed" })) assert.ok(!/TERM\("/.test(r.text), "TERM() is never quoted");
});

test("the KQL term rung (has) needs no class, is marked wider and never appears alone", () => {
  for (const fieldClass of CLASSES) {
    const rungs = build(specFor(WIN, ["any", "keep", "any", "any", "any"]), { platform: "kql", field: "f", fieldClass });
    const has = rungs.find((r) => r.construct === "term");
    assert.ok(has, String(fieldClass));
    assert.equal(has.exact, false);
    assert.ok(has.caveats[0].includes("wider"));
    assert.ok(rungs.some((r) => r.construct === "like" && r.exact));
  }
  assert.ok(build(specFor(WIN, ["any", "any", "keep", "any", "any"]), { platform: "kql", field: "f" }).some((r) => r.text === 'f has "System32"'), "System32 alone is one term");
  assert.ok(!build(specFor(WIN, ["any", "keep", "keep", "any", "any"]), { platform: "kql", field: "f" }).some((r) => r.construct === "term"), "Windows\\System32 is two terms with a separator: no has");
  assert.ok(!build(specFor(URLV, ["any", "keep", "any", "any", "any", "any", "any"]), { platform: "kql", field: "f" }).some((r) => r.construct === "term"), "a dotted host is not one term");
  for (const { spec } of everySpec()) for (const r of build(spec, { platform: "kql", field: "f" })) assert.equal(r.exact, r.construct !== "term", r.text);
  for (const { spec } of everySpec()) for (const r of build(spec, { platform: "spl", field: "f" })) assert.equal(r.exact, true, r.text);
});

test("cost order is stable: non-decreasing cost, ties broken by ORDER, and COSTS covers every construct on both platforms", () => {
  assert.deepEqual(Object.keys(COSTS.spl).sort(), [...ORDER].sort());
  assert.deepEqual(Object.keys(COSTS.kql).sort(), [...ORDER].sort());
  for (const { spec } of everySpec()) {
    for (const platform of ["spl", "kql"]) {
      const rungs = build(spec, { platform, field: "f", fieldClass: "raw_token" });
      assert.ok(rungs.length >= 1);
      for (let i = 1; i < rungs.length; i++) {
        const a = rungs[i - 1];
        const b = rungs[i];
        assert.ok(a.cost < b.cost || (a.cost === b.cost && ORDER.indexOf(a.construct) < ORDER.indexOf(b.construct)), `${platform}: ${a.construct} before ${b.construct}`);
        assert.equal(a.cost, COSTS[platform][a.construct]);
      }
      assert.equal(new Set(rungs.map((r) => r.construct)).size, rungs.length, "one rung per construct");
    }
  }
});

test("every construct has a Splunk form and a KQL form somewhere in the pool", () => {
  const seen = { spl: new Set(), kql: new Set() };
  const specs = [...[...everySpec()].map((x) => x.spec), { values: ["a", "b"] }];
  for (const spec of specs) for (const platform of ["spl", "kql"]) for (const r of build(spec, { platform, field: "f", fieldClass: "raw_token" })) seen[platform].add(r.construct);
  for (const c of ORDER) {
    assert.ok(seen.spl.has(c), `spl emits ${c}`);
    assert.ok(seen.kql.has(c), `kql emits ${c}`);
  }
});

test("the lint extension is exactly regex and rex, neither forbidden nor already allowed", () => {
  assert.deepEqual([...LINT_COMMANDS], ["regex", "rex"]);
  for (const c of LINT_COMMANDS) {
    assert.ok(!spl.FORBIDDEN_COMMANDS.includes(c));
    assert.ok(!spl.ALLOWED_COMMANDS.includes(c));
  }
  assert.equal(spl.lint("search * | regex f=\"x\"").ok, false, "without the extension the rung would not lint, which is why the ladder passes it");
});

test("preview counts on the fixture profile, as shapes.classify counts", () => {
  const img = build(specFor(WIN, ["keep", "keep", "keep", "any", "any"]), { platform: "spl", field: "Image", samples: top("Image") });
  assert.deepEqual(img.find((r) => r.construct === "trailing_wildcard").preview, { matched: 65, total: 86, hits: 2 });
  assert.deepEqual(img.find((r) => r.construct === "regex").preview, { matched: 65, total: 86, hits: 2 });
  const lit = build(WIN, { platform: "kql", field: "Image", samples: top("Image") });
  assert.deepEqual(lit[0].preview, { matched: 40, total: 86, hits: 1 });
  const cs = build(WIN, { platform: "kql", field: "Image", ci: false, samples: [...top("Image"), { value: WIN.toUpperCase(), count: 4 }] });
  assert.deepEqual(cs[0].preview, { matched: 40, total: 90, hits: 1 }, "== is case-sensitive");
  const ci = build(WIN, { platform: "spl", field: "Image", samples: [...top("Image"), { value: WIN.toUpperCase(), count: 4 }] });
  assert.deepEqual(ci[0].preview, { matched: 44, total: 90, hits: 2 }, "a search term is not");
  const arn = build(specFor(ARN, ["keep", "keep", "keep", "keep", "keep", "any"]), { platform: "kql", field: "userIdentity.arn", samples: top("userIdentity.arn") });
  assert.deepEqual(arn[0].preview, { matched: 50, total: 65, hits: 2 });
  const acct = build(specFor(ARN, ["keep", "keep", "keep", "any", "keep", "any"]), { platform: "spl", field: "userIdentity.arn", samples: top("userIdentity.arn") });
  assert.equal(acct[0].text, 'userIdentity.arn="arn:aws:iam::*:user/*"');
  assert.deepEqual(acct[0].preview, { matched: 53, total: 65, hits: 3 });
  const host = build(specFor(URLV, ["keep", "keep", "any", "any", "any", "any", "any"]), { platform: "spl", field: "url", samples: top("url") });
  assert.deepEqual(host[0].preview, { matched: 15, total: 20, hits: 2 });
  const net = build(specFor("10.0.1.2", ["keep", "keep", "any", "any"]), { platform: "kql", field: "src_ip", samples: top("src_ip") });
  assert.deepEqual(net.find((r) => r.construct === "cidr").preview, { matched: 70, total: 85, hits: 2 });
  const block = build("10.0.0.0/8", { platform: "spl", field: "src_ip", samples: top("src_ip") });
  assert.deepEqual(block[0].preview, { matched: 80, total: 85, hits: 3 }, "a kept CIDR block previews as a range");
  const set = build({ values: ["10.0.5.5", "192.168.1.1"] }, { platform: "kql", field: "src_ip", samples: top("src_ip") });
  assert.deepEqual(set[0].preview, { matched: 55, total: 85, hits: 2 });
  assert.equal(build(WIN, { platform: "spl", field: "Image" })[0].preview, null, "no samples, no preview");
  assert.deepEqual(build(WIN, { platform: "spl", field: "Image", samples: [] })[0].preview, { matched: 0, total: 0, hits: 0 });
});

test("ipv6 cidr previews expand compressed samples; a compressed or zoned spec has no cidr rung", () => {
  const rungs = build(specFor("2001:db8:0:0:0:0:0:1", ["keep", "keep", "any", "any", "any", "any", "any", "any"]), { platform: "kql", field: "ip", samples: [{ value: "2001:db8::5", count: 2 }, { value: "2001:db9::1", count: 1 }, { value: "[2001:db8::7]", count: 1 }, { value: "10.0.0.1", count: 1 }] });
  assert.deepEqual(rungs.find((r) => r.construct === "cidr").preview, { matched: 3, total: 5, hits: 2 });
  assert.ok(!build(specFor("2001:db8::1", ["keep", "keep", "any", "any"]), { platform: "spl", field: "ip" }).some((r) => r.construct === "cidr"));
  assert.ok(!build(specFor("fe80::1%eth0", ["keep", "any", "any", "keep"]), { platform: "spl", field: "ip" }).some((r) => r.construct === "cidr"));
  assert.ok(!build(specFor("10.0.1.2", ["keep", "any", "keep", "any"]), { platform: "spl", field: "ip" }).some((r) => r.construct === "cidr"), "a kept octet after an open one is not a prefix");
});

test("a truncated spec is matched as a prefix and never as a literal", () => {
  const long = "C:\\" + "a".repeat(120) + "\\" + "b".repeat(80) + ".exe";
  for (const platform of ["spl", "kql"]) {
    const rungs = build(long, { platform, field: "f", fieldClass: "raw_token" });
    assert.ok(!rungs.some((r) => r.construct === "literal" || r.construct === "term"), platform);
    assert.equal(rungs[0].construct, "trailing_wildcard");
    assert.ok(rungs[0].why.includes("200 characters"));
    assert.ok(rungs[0].text.includes(platform === "spl" ? "*\"" : "startswith"));
  }
  const untouched = specFor(long);
  untouched.truncated = false;
  assert.ok(build(untouched, { platform: "spl", field: "f" }).some((r) => r.construct === "literal"), "the flag is what withholds the literal");
});

test("state aliases and a parallel states array are accepted", () => {
  const a = specFor(WIN, ["keep", "keep", "keep", "anything", "anything"]);
  const b = { ...segment(WIN), states: ["keep", "keep", "keep", "any", "any"] };
  const c = { ...segment(WIN), states: [undefined, null, "", "any", "like_this"] };
  assert.equal(build(a, { platform: "spl", field: "f" })[0].text, build(b, { platform: "spl", field: "f" })[0].text);
  assert.equal(build(c, { platform: "spl", field: "f" })[0].construct, "regex");
});

test("errors: platform, field, state and spec", () => {
  assert.throws(() => build(WIN, { field: "f" }), (e) => e instanceof LadderError && e.code === "bad_platform");
  assert.throws(() => build(WIN, { platform: "spl" }), (e) => e.code === "bad_field");
  assert.throws(() => build(WIN, { platform: "spl", field: "bad field" }), (e) => e.code === "bad_field");
  assert.throws(() => build(WIN, { platform: "kql", field: "1st" }), (e) => e.code === "bad_field");
  assert.throws(() => build(specFor(WIN, ["keep", "maybe"]), { platform: "spl", field: "f" }), (e) => e.code === "bad_state");
  assert.throws(() => build({ values: [] }, { platform: "spl", field: "f" }), (e) => e.code === "bad_spec");
  assert.throws(() => build({}, { platform: "spl", field: "f" }), (e) => e.code === "bad_spec");
  assert.throws(() => build(42, { platform: "spl", field: "f" }), (e) => e.code === "bad_spec");
  assert.equal(build(WIN, { platform: "splunk", field: "f" })[0].platform, "spl", "platform names are accepted");
  assert.equal(build(WIN, { platform: "sentinel", field: "f" })[0].platform, "kql");
});

test("case: SPL where and regex rungs lower the field; KQL follows ci, which defaults by shape", () => {
  const winSpl = build(specFor(WIN, ["any", "any", "any", "keep", "keep"]), { platform: "spl", field: "f" });
  assert.ok(winSpl.find((r) => r.construct === "like").text.startsWith("| where like(lower(f), "));
  assert.ok(winSpl.find((r) => r.construct === "regex").text.includes('"(?i)^'));
  assert.equal(build(ARN, { platform: "kql", field: "f" })[0].text, `f == ${kql.quote(ARN)}`, "an ARN compares case-sensitively");
  assert.equal(build(ARN, { platform: "kql", field: "f", ci: true })[0].text, `f =~ ${kql.quote(ARN)}`, "ci is an explicit override");
  assert.equal(build(WIN, { platform: "kql", field: "f", ci: false })[0].text, `f == ${kql.quote(WIN)}`);
  assert.equal(build("HKLM\\SOFTWARE\\Run", { platform: "kql", field: "f" })[0].text.slice(0, 5), "f =~ ", "a registry key is case-insensitive");
  assert.equal(build("powershell.exe -enc AAAA", { platform: "kql", field: "f" })[0].text.slice(0, 5), "f == ", "a bare command line without a Windows path is not");
  assert.equal(build("C:\\Windows\\System32\\cmd.exe /c dir", { platform: "kql", field: "f" })[0].text.slice(0, 5), "f =~ ");
  const regex = build(specFor(WIN, ["keep", "like", "keep", "keep", "keep"]), { platform: "kql", field: "f", ci: false }).find((r) => r.construct === "regex");
  assert.ok(!regex.text.includes("(?i)"));
});

test("SPL field names: bare in terms, regex and rex; single-quoted in an eval context when not plain", () => {
  const rungs = build(specFor(ARN, ["any", "keep", "keep", "keep", "keep", "keep"]), { platform: "spl", field: "userIdentity.arn" });
  assert.equal(rungs[0].text, 'userIdentity.arn="arn:*:iam::123456789012:user/jdoe"', "the partition sits after a literal arn:, so opening it is a wildcard inside the value");
  const upn = build(specFor("jdoe@corp.contoso.com", ["any", "keep", "keep", "keep"]), { platform: "spl", field: "user.name" });
  assert.ok(upn.find((r) => r.construct === "like").text.startsWith("| where like(lower('user.name'), "));
  assert.ok(rungs.find((r) => r.construct === "regex").text.startsWith("| regex userIdentity.arn="));
  assert.ok(rungs.find((r) => r.construct === "rex").text.startsWith("| rex field=userIdentity.arn "));
  const multi = build(ARN, { platform: "spl", field: "resources{}.ARN" });
  assert.equal(multi[0].text, `resources{}.ARN=${spl.quote(ARN)}`);
});

test("KQL field paths: a hyphenated path segment is bracketed", () => {
  assert.equal(build("x", { platform: "kql", field: "Headers.x-forwarded-for" })[0].text, 'tostring(Headers["x-forwarded-for"]) == "x"');
});

test("an all-open spec still emits, as a stage, and an empty value has no segments to open", () => {
  const rungs = build(specFor(WIN, ["any", "any", "any", "any", "any"]), { platform: "spl", field: "f" });
  assert.ok(rungs.every((r) => r.form === "stage"));
  assert.equal(build("", { platform: "spl", field: "f" })[0].text, 'f=""');
});
