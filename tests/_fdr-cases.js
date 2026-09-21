// The parameter sets every FDR query and bundle edge is rendered under for
// the golden fixture (tests/fixtures/fdr-queries.json): every kind the
// views construct, every edge of the FDR join graph, each with the
// parameters all bound, all bound with latest at now, the view's base
// parameters only, and the partial bindings that move a line or a hazard.
// Shared by the capture and by the parity test.

export const AID = "a".repeat(32);
export const SHA = "8ae63ddace21276fa6cb4b2613468e5730fc550a1374543372972e52dc232ec6";

const WINDOW = { earliest: "-24h", latest: "-1h" };
const ISO = { earliest: "2022-07-27T10:40:00", latest: "2022-07-27T10:50:00" };

// Per kind: the full binding (index bound) and the base parameters the
// view passes before the drawer fills anything.
export const KINDS = {
  trace: {
    full: { field: "ImageFileName", value: "C:\\Windows\\System32\\rundll32.exe", aid: AID, index: "main", ...WINDOW },
    base: { field: "ImageFileName", event: "ProcessRollup2" },
    partial: [
      { field: "ImageFileName", value: "x", earliest: "-24h" },
      { field: "ImageFileName", value: "x", aid: AID, earliest: "-24h" },
      { field: "ImageFileName", value: "x", earliest: "-24h", latest: "now", index: "main" },
      { field: "Bad Field", value: "x", earliest: "-24h" },
    ],
  },
  process_events: {
    full: { aid: AID, tpid: "255667414", index: "main", ...WINDOW },
    base: { aid: AID, tpid: "255667414" },
    partial: [{ aid: AID, tpid: "255667414", earliest: "-24h" }, { aid: AID, tpid: "255667414", ...ISO }],
  },
  process_table: {
    full: { aid: AID, index: "main", ...WINDOW },
    base: {},
    partial: [{ aid: AID, earliest: "-24h" }, { aid: AID, earliest: "-24h", latest: "now", index: "main" }],
  },
  pid_lookup: {
    full: { aid: AID, pid: "936", index: "main", ...WINDOW },
    base: { aid: AID, pid: "936" },
    partial: [{ aid: AID, pid: "936", earliest: "-24h" }, { pid: "936", ...WINDOW }, { aid: AID, pid: "936", ...ISO }, { aid: AID, pid: "936", earliest: "$earliest$", latest: "now" }],
  },
  tpid_to_pid: {
    full: { aid: AID, tpid: "255667414", index: "main", ...WINDOW },
    base: { aid: AID, tpid: "255667414" },
    partial: [{ aid: AID, tpid: "255667414", earliest: "-24h" }, { aid: AID, tpid: "255667414", latest: "now" }, { aid: AID }],
  },
  host_lookup: {
    full: { hostname: "WKSTN-0042", index: "main", ...WINDOW },
    base: { hostname: "WKSTN-0042" },
    partial: [{ hostname: "WKSTN-0042", earliest: "-7d" }, { hostname: 'a"b\\c' }, {}],
  },
  event_sample: {
    full: { event: "ProcessRollup2", aid: AID, field: "ImageFileName", value: "x", index: "main", ...WINDOW },
    base: { event: "ProcessRollup2" },
    partial: [
      { event: "ProcessRollup2", earliest: "-24h" },
      { event: "ProcessRollup2", aid: AID, earliest: "-24h" },
      { event: "ProcessRollup2", field: "ImageFileName", earliest: "-24h" },
      { event: "Event_DetectionSummaryEvent", earliest: "-24h" },
      { event: "Event_DetectionSummaryEvent", sourcetype: "crowdstrike:events:external", value: SHA, field: "SHA256String" },
      { event: "DnsRequest", sourcetype: "crowdstrike:events:sensor", earliest: "-24h", latest: "now" },
      { event: "Bad Event", earliest: "-24h" },
    ],
  },
};

// Per bundle edge: the full binding and the partial ones that matter for
// its shape (aid unbound on a scoped edge, the pid gate).
export const EDGE_PARAMS = {
  full: { value: "V", aid: AID, index: "main", ...WINDOW },
  base: { value: "V" },
  partial: [{}, { value: "V", aid: AID }, { value: "V", earliest: "-24h" }, { value: "V", aid: AID, earliest: "-24h", latest: "now" }, { value: "V", ...WINDOW }, { value: "V", aid: AID, ...ISO }],
};

export function paramSets(spec) {
  const out = [
    { name: "full", params: spec.full },
    { name: "full latest=now", params: { ...spec.full, latest: "now" } },
    { name: "base", params: spec.base },
  ];
  spec.partial.forEach((p, i) => out.push({ name: `partial ${i + 1}`, params: p }));
  return out;
}
