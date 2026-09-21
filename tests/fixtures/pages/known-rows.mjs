// Two hand-written ProcessRollup2 rows for splunk-search.html, the
// known-good verdict's other two tiers: a Mac row claiming Apple's
// contactsd path under a signing id the corpus has never seen there
// (impersonation), and an Ubuntu 22.04 row on curl whose hash the bundled
// Linux corpus holds (normal). build-splunk-fixture.mjs appends them after
// the mac signing rows, so a refreshed capture keeps them and the captured
// rows' positions hold.
//
//   node tests/fixtures/pages/known-rows.mjs   prints the rows

import { eventRow } from "./handle-open-row.mjs";

const MAC_HOST = "sensor-mac-01";

// Apple's contactsd path, a signing id and team the corpus has no row for:
// the path belongs to com.apple.contactsd, so the event disagrees with the
// corpus on the signing id (known.js: impersonation).
export const IMPERSONATION = [
  ["CodeSigningFlags", "570491393"],
  ["CommandLine", "/System/Library/Frameworks/Contacts.framework/Support/contactsd"],
  ["ComputerName", "mac-lab-01.example"],
  ["ConfigBuild", "1007.4.0021204.15"],
  ["CsValidationCategory", "4"],
  ["ImageFileName", "/System/Library/Frameworks/Contacts.framework/Support/contactsd"],
  ["MD5HashData", "5d41402abc4b2a76b9719d911017c592"],
  ["ParentBaseFileName", "launchd"],
  ["ParentProcessId", "708948568167359216"],
  ["RawProcessId", "2044"],
  ["SHA256HashData", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
  ["SigningId", "com.evil.contactsd"],
  ["TargetProcessId", "708952894073941120"],
  ["TeamId", "ABCDE12345"],
  ["UserName", "_modelmanagerd"],
  ["aid", "0123456789abcdef0123456789abcdef"],
  ["aip", "203.0.113.20"],
  ["cid", "00000000000000000000000000000002"],
  ["event_platform", "Mac"],
  ["event_simpleName", "ProcessRollup2"],
  ["id", "c7a1d3e2-2f40-4b8e-9a6d-1e5f0c2b3a44"],
  ["name", "ProcessRollup2MacV12"],
  ["timestamp", "1789661500118"],
];

// curl on Ubuntu 22.04, the hash the bundled Linux corpus lists for
// /usr/bin/curl (package curl); aid_os_version names the release the
// verdict reads the corpus by.
export const LINUX = [
  ["CommandLine", "curl -fsSL https://example.com/setup.sh"],
  ["ComputerName", "ubuntu-lab-01"],
  ["ConfigBuild", "1007.4.0021204.15"],
  ["ImageFileName", "/usr/bin/curl"],
  ["MD5HashData", "2f0a7b1c9d3e4f5a6b7c8d9e0f1a2b3c"],
  ["ParentBaseFileName", "bash"],
  ["ParentProcessId", "708952894073942001"],
  ["RawProcessId", "31337"],
  ["SHA256HashData", "b1b4a0805c83790a5854ff58ed222cecebb40ce7f5daeca33878b47089e9c206"],
  ["TargetProcessId", "708952894073942210"],
  ["UID", "1000"],
  ["UserName", "ubuntu"],
  ["aid", "fedcba9876543210fedcba9876543210"],
  ["aid_os_version", "Ubuntu 22.04"],
  ["aip", "203.0.113.30"],
  ["cid", "00000000000000000000000000000002"],
  ["event_platform", "Lin"],
  ["event_simpleName", "ProcessRollup2"],
  ["id", "d8b2e4f3-3a51-4c9f-8b7e-2f6a1d3c4b55"],
  ["name", "ProcessRollup2LinuxV20"],
  ["timestamp", "1789661520204"],
];

const selectedFields = (host) => [["host", host], ["source", "crowdstrike"], ["sourcetype", "crowdstrike:events:sensor"]];

export function impersonationRow(n = 10) {
  return eventRow(n, IMPERSONATION, { time: { iso: "2026-09-17T16:11:40.118+00:00", date: "9/17/26", clock: "4:11:40.118 PM" }, selectedFields: selectedFields(MAC_HOST) });
}

export function linuxRow(n = 11) {
  return eventRow(n, LINUX, { time: { iso: "2026-09-17T16:12:00.204+00:00", date: "9/17/26", clock: "4:12:00.204 PM" }, selectedFields: selectedFields("sensor-linux-01") });
}

export function knownRows(first = 10) {
  return `${impersonationRow(first)}\n${linuxRow(first + 1)}`;
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) console.log(knownRows());
