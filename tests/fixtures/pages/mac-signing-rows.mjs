// Three macOS ProcessRollup2 rows for splunk-search.html, written by hand
// in the same markup as handle-open-row.mjs: the captured mac rows are
// Apple's own contactsd (CsValidationCategory 1, TeamId "-"), the exact
// case the mac signing hunt excludes, so a run against the page needs rows
// its predicate keeps. Two starts of a Finder that a third-party team
// signed under Apple's namespace, and one unsigned binary under
// /usr/libexec claiming a com.apple. name. build-splunk-fixture.mjs
// appends them after the handle-open row; tests/fixtures/hunt-rows.json is
// the stats the hunt's namespace search makes of them.
//
//   node tests/fixtures/pages/mac-signing-rows.mjs   prints the rows
import { eventRow } from "./handle-open-row.mjs";

const FINDER_SHA256 = "3b1fd0c4a7e2985f6d1b0c9e8a7f6d5c4b3a2918f7e6d5c4b3a291807f6e5d4c";
const LIBEXEC_SHA256 = "8ae63dda1b3f0a2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";

function finder(start, pid, tpid, id) {
  return [
    ["CodeSigningFlags", "570425857"],
    ["CommandLine", "/Applications/Fake Finder.app/Contents/MacOS/Finder"],
    ["ComputerName", "mac-lab-01.example"],
    ["ConfigBuild", "1007.4.0021204.15"],
    ["CsValidationCategory", "6"],
    ["ImageFileName", "/Applications/Fake Finder.app/Contents/MacOS/Finder"],
    ["MD5HashData", "9f1c2e3d4a5b6c7d8e9f0a1b2c3d4e5f"],
    ["ParentBaseFileName", "launchd"],
    ["ParentProcessId", "708948568167359216"],
    ["ProcessStartTime", start],
    ["RawProcessId", pid],
    ["SHA1HashData", "4d2a9c8e7f6b5a4c3d2e1f0a9b8c7d6e5f4a3b2c"],
    ["SHA256HashData", FINDER_SHA256],
    ["SigningId", "com.apple.finder"],
    ["TargetProcessId", tpid],
    ["TeamId", "ZZ9X8W7V6U"],
    ["UID", "501"],
    ["UserName", "analyst"],
    ["aid", "0123456789abcdef0123456789abcdef"],
    ["aip", "203.0.113.20"],
    ["cid", "00000000000000000000000000000002"],
    ["event_platform", "Mac"],
    ["event_simpleName", "ProcessRollup2"],
    ["id", id],
    ["name", "ProcessRollup2MacV12"],
    ["timestamp", String(Math.round(Number(start) * 1000))],
  ];
}

export const MAC_SIGNING = [
  {
    fields: finder("1789722724.118", "2231", "708952894073941001", "5c0e1d2a-7b3f-4a8e-9c1d-2e3f4a5b6c7d"),
    time: { iso: "2026-09-18T09:12:04.118+00:00", date: "9/18/26", clock: "9:12:04.118 AM" },
    selectedFields: [["host", "sensor-mac-01"], ["source", "/tmp/falcon/crowdstrike-events-sensor-1789661586.json"], ["sourcetype", "crowdstrike:events:sensor"]],
  },
  {
    fields: finder("1789904451.507", "4410", "708952894073942117", "6d1f2e3b-8c4a-4b9f-8d2e-3f4a5b6c7d8e"),
    time: { iso: "2026-09-20T11:40:51.507+00:00", date: "9/20/26", clock: "11:40:51.507 AM" },
    selectedFields: [["host", "sensor-mac-01"], ["source", "/tmp/falcon/crowdstrike-events-sensor-1789661586.json"], ["sourcetype", "crowdstrike:events:sensor"]],
  },
  {
    fields: [
      ["CodeSigningFlags", "0"],
      ["CommandLine", "/usr/libexec/notasystemd --daemon"],
      ["ComputerName", "mac-lab-02.example"],
      ["ConfigBuild", "1007.4.0021204.15"],
      ["CsValidationCategory", "3"],
      ["ImageFileName", "/usr/libexec/notasystemd"],
      ["MD5HashData", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"],
      ["ParentBaseFileName", "launchd"],
      ["ParentProcessId", "708948568167359216"],
      ["ProcessStartTime", "1789855390.062"],
      ["RawProcessId", "873"],
      ["SHA1HashData", "1f2e3d4c5b6a79880716253443526170f0e1d2c3"],
      ["SHA256HashData", LIBEXEC_SHA256],
      ["SigningId", "com.apple.notasystemd"],
      ["TargetProcessId", "708952894073943208"],
      ["TeamId", "-"],
      ["UID", "0"],
      ["UserName", "root"],
      ["aid", "fedcba9876543210fedcba9876543210"],
      ["aip", "203.0.113.21"],
      ["cid", "00000000000000000000000000000002"],
      ["event_platform", "Mac"],
      ["event_simpleName", "ProcessRollup2"],
      ["id", "7e2a3f4c-9d5b-4c0a-9e3f-4a5b6c7d8e9f"],
      ["name", "ProcessRollup2MacV12"],
      ["timestamp", "1789855390062"],
    ],
    time: { iso: "2026-09-19T22:03:10.062+00:00", date: "9/19/26", clock: "10:03:10.062 PM" },
    selectedFields: [["host", "sensor-mac-02"], ["source", "/tmp/falcon/crowdstrike-events-sensor-1789855400.json"], ["sourcetype", "crowdstrike:events:sensor"]],
  },
];

// The rows, numbered from `first` (the line number after the handle-open row).
export function macSigningRows(first = 7) {
  return MAC_SIGNING.map((r, i) => eventRow(first + i, r.fields, r)).join("\n");
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) console.log(macSigningRows());
