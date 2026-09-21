import "./_splunk.js"; // Splunk-only code under test: the Falcon pack's workflows render SPL
import "./_bundle.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as packs from "../app/lib/packs.js";
import * as catalogue from "../app/lib/catalogue.js";
import * as pivot from "../app/lib/pivot.js";
import * as workflows from "../app/lib/workflows.js";
import * as fdr from "../app/lib/fdr-queries.js";

await catalogue.load();

// The Falcon pack's five guided workflows, in the pack's order, and where the popups offer them.
const FIVE = ["pid", "process", "host", "detection", "ioc"];
const ENTRIES = [
  { id: "process", sourcetype: "crowdstrike:events:sensor", field: "TargetProcessId", param: "tpid" },
  { id: "process", sourcetype: "crowdstrike:events:sensor", field: "ContextProcessId", param: "tpid" },
  { id: "process", sourcetype: "crowdstrike:events:sensor", field: "ParentProcessId", param: "tpid" },
  { id: "pid", sourcetype: "crowdstrike:events:sensor", field: "RawProcessId", param: "pid" },
  { id: "host", sourcetype: "crowdstrike:events:sensor", field: "ComputerName", param: "hostname" },
  { id: "host", sourcetype: "crowdstrike:events:sensor", field: "aid", param: "aid" },
  { id: "host", sourcetype: "crowdstrike:inventory:aidmaster", field: "aid", param: "aid" },
  { id: "detection", sourcetype: "crowdstrike:events:external", field: "SHA256String", param: "sha256" },
  { id: "detection", sourcetype: "crowdstrike:events:external", field: "ComputerName", param: "hostname" },
  { id: "detection", sourcetype: "crowdstrike:events:external", field: "ProcessId", param: "processid" },
  { id: "ioc", sourcetype: "crowdstrike:events:sensor", field: "SHA256HashData", param: "value" },
  { id: "ioc", sourcetype: "crowdstrike:events:sensor", field: "RemoteAddressIP4", param: "value" },
  { id: "ioc", sourcetype: "crowdstrike:events:sensor", field: "DomainName", param: "value" },
  { id: "ioc", sourcetype: "crowdstrike:events:sensor", field: "ImageFileName", param: "value" },
];

test("the pack format validates workflows: ids, steps on declared params, results on known edges, chains on known workflows", () => {
  const ct = packs.pack("aws-cloudtrail");
  assert.equal(packs.validate(ct).length, 0);
  const w = ct.workflows[0];
  const withW = (patch) => ({ ...ct, workflows: [{ ...w, ...patch }] });
  assert.ok(packs.validate(withW({ id: "Bad Id" })).some((e) => /id must be/.test(e)));
  assert.ok(packs.validate(withW({ steps: [] })).some((e) => /steps must be a non-empty array/.test(e)));
  assert.ok(packs.validate(withW({ steps: [{ title: "x", names: ["nope"] }] })).some((e) => /not declared in params/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", edge: "no_such_edge" }] })).some((e) => /unknown edge/.test(e)));
  assert.ok(packs.validate(withW({ chain: { workflow: "nowhere" } })).some((e) => /unknown workflow/.test(e)));
  assert.ok(packs.validate(withW({ entries: [{ concept: "no_such_concept", param: "arn" }] })).some((e) => /entries need/.test(e)));
  assert.ok(packs.validate({ ...ct, workflows: [w, w] }).some((e) => /duplicate workflow id/.test(e)));
});

test("list() spans the Falcon five and every pack's workflows; forField finds the entry and its param", () => {
  const all = workflows.list();
  assert.deepEqual(all.filter((w) => w.packId === "crowdstrike-falcon").map((w) => w.id), [...FIVE, "hunt_mac_signing"]);
  assert.ok(all.some((w) => w.id === "ct_principal" && w.packId === "aws-cloudtrail"));
  const here = workflows.forField("aws:cloudtrail", "userIdentity.arn");
  assert.deepEqual(here.map((w) => [w.id, w.param]), [["ct_principal", "arn"]]);
  assert.deepEqual(workflows.forField("crowdstrike:events:sensor", "TargetProcessId").map((w) => w.id), ["process"]);
  assert.deepEqual(workflows.forField("aws:cloudtrail", "requestID"), []);
  assert.deepEqual(workflows.forField(null, "x"), []);
  assert.ok(workflows.forSourcetype("aws:cloudtrail").length >= 3);
  assert.equal(workflows.href("ct_principal", { arn: "arn:aws:iam::1:user/a", latest: "" }), "#/w/ct_principal?arn=arn%3Aaws%3Aiam%3A%3A1%3Auser%2Fa");
});

test("the five are entered from the same (sourcetype, field) pairs as before, by concept where one is bound and by column elsewhere", () => {
  const listed = workflows.list().filter((w) => FIVE.includes(w.id));
  const got = listed.flatMap((w) => w.entries.map((e) => ({ id: w.id, sourcetype: e.sourcetype, field: e.field, param: e.param })));
  const key = (e) => `${e.id} ${e.sourcetype} ${e.field} ${e.param}`;
  assert.deepEqual(got.map(key).sort(), ENTRIES.map(key).sort());
  for (const e of ENTRIES) {
    const v = catalogue.fieldOn(e.sourcetype, e.field);
    assert.ok(v && v.pack, `${e.field} on ${e.sourcetype}`);
    assert.ok(workflows.forField(e.sourcetype, e.field).some((w) => w.id === e.id && w.param === e.param), key(e));
  }
});

test("a pack workflow becomes the walker's definition, and every result renders SPL once its params are bound", () => {
  for (const w of packs.workflows()) {
    const def = workflows.get(w.id);
    assert.ok(def, w.id);
    assert.equal(def.packId, w.packId);
    assert.ok(def.steps.length && def.title);
    for (const s of def.steps) for (const n of s.names) assert.ok(def.meta[n], `${w.id}: meta for ${n}`);
    // Bind every param a step asks for (and answer a gate with its first
    // emitting choice), then every result must render.
    const p = { earliest: "-24h", latest: "now", index: "aws", aid: "a".repeat(32) };
    for (const s of def.steps) for (const n of s.names) p[n] = p[n] || (n === "field" ? "ImageFileName" : n === "sha256" ? "b".repeat(64) : `v_${n}`);
    if (def.gate) p[def.gate.param] = def.gate.choices.find((c) => def.gate.emits(c.value)).value;
    const results = def.results(p);
    assert.ok(results.length, `${w.id}: results`);
    for (const r of results) {
      assert.ok(r.pivot && (r.pivot.kind === "pack" || r.pivot.kind === "edge"), `${w.id}/${r.id}: pivot`);
      const out = r.pivot.kind === "pack" ? pivot.generate(r.pivot.edge, r.params, { pack: packs.pack(w.packId) }) : fdr.generate(r.pivot, r.params);
      assert.deepEqual(out.missing, [], `${w.id}/${r.id}: ${out.missing.join(", ")} unbound`);
      const on = r.pivot.kind === "pack" ? r.pivot.edge.dst.sourcetype : out.sourcetype;
      assert.ok(out.spl.includes(`sourcetype=${on}`), `${w.id}/${r.id}: ${out.spl}`);
    }
    if (def.chain) {
      const raw = packs.workflow(w.id).chain;
      const c = def.chain({ ...p, arn: "arn:x" });
      assert.ok(c.href.startsWith(`#/w/${raw.workflow}?`), c.href);
      assert.ok(c.inputNames.length);
    }
  }
});

test("the detection workflow's PID-space gate is pack data: the answer picks the search, no answer emits none, the OS reading links into the pid workflow", () => {
  const det = workflows.get("detection", {});
  assert.equal(det.packId, "crowdstrike-falcon");
  assert.ok(det.gate && det.gate.param === "pidspace" && det.gate.choices.length === 3);
  assert.equal(det.gate.emits("falcon"), true);
  assert.equal(det.gate.emits("os"), true);
  assert.equal(det.gate.emits("unknown"), false);
  assert.match(det.gate.blocked, /^Nothing in the catalogue, the TA or the reference says which PID space/);
  assert.deepEqual(det.steps.map((s) => Boolean(s.gate)), [false, false, false, true]);
  const p = { sha256: "a".repeat(64), aid: "b".repeat(32), hostname: "H", earliest: "-1d", latest: "now", processid: "936" };
  const os = det.results({ ...p, pidspace: "os" });
  assert.deepEqual(os.map((r) => r.id), ["hash", "host", "pidspace"]);
  const gated = os.find((r) => r.id === "pidspace");
  assert.equal(gated.gate, true);
  assert.equal(gated.pivot.kind, "pack");
  assert.equal(gated.pivot.edge.id, "cs_pid_lookup");
  assert.deepEqual(gated.params, { aid: p.aid, pid: "936", earliest: "-1d", latest: "now" });
  const falcon = det.results({ ...p, pidspace: "falcon" }).find((r) => r.id === "pidspace");
  assert.equal(falcon.pivot.edge.id, "cs_process_events");
  assert.deepEqual(falcon.params, { aid: p.aid, tpid: "936", earliest: "-1d", latest: "now" });
  const unknown = det.results({ ...p, pidspace: "unknown" }).find((r) => r.id === "pidspace");
  assert.equal(unknown.pivot, null);
  assert.equal(det.results(p).find((r) => r.id === "pidspace").pivot, null, "no answer, no search");
  const link = det.gate.choices.find((c) => c.value === "os").callout.link;
  assert.equal(link.href(p), "#/w/pid?aid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&pid=936&earliest=-1d&latest=now");
  assert.equal(det.gate.choices.find((c) => c.value === "falcon").callout.link, undefined);
  // The hash result is the join graph's detection edge, rendered by fdr-queries.js with the edge's own hazards.
  const hash = os.find((r) => r.id === "hash");
  assert.equal(hash.pivot.kind, "edge");
  assert.equal(hash.pivot.edge.id, "e_sha256string_to_sha256hashdata");
  assert.deepEqual(hash.params, { value: p.sha256, aid: p.aid, earliest: "-1d", latest: "now" });
  assert.equal(workflows.get("nope", {}), null);
});

test("the pid workflow chains into process carrying the TargetProcessId; process cautions on the OS PID; ioc links the value", () => {
  const pid = workflows.get("pid", {});
  assert.equal(pid.meta.pid.label, "RawProcessId");
  assert.match(pid.meta.earliest.hint, /^Relative \(-24h, -7d@d, now\)/);
  assert.equal(pid.results({ aid: "a", pid: "1", earliest: "-1h", latest: "now" })[0].pivot.edge.id, "cs_pid_lookup");
  const chain = pid.chain({ aid: "a", tpid: "2", earliest: "-1h", latest: "" });
  assert.equal(chain.href, "#/w/process?aid=a&tpid=2&earliest=-1h");
  assert.deepEqual(chain.inputNames, ["aid", "tpid", "earliest", "latest"]);
  const process = workflows.get("process", {});
  const ospid = process.results({ aid: "a", tpid: "2", earliest: "-1h", latest: "now" }).find((r) => r.id === "ospid");
  assert.match(ospid.caution, /^Once you hand an OS PID to someone/);
  assert.equal(ospid.pivot.edge.id, "cs_tpid_to_pid");
  assert.equal(workflows.get("ioc", {}).valueLink, true);
  assert.equal(workflows.get("host", {}).valueLink, undefined);
});

test("the pack format validates a gate, a gated result's choices, a column entry and a caution", () => {
  const falcon = packs.pack("crowdstrike-falcon");
  const det = falcon.workflows.find((w) => w.id === "detection");
  const withW = (patch) => ({ ...falcon, workflows: [{ ...det, ...patch }] });
  assert.equal(packs.validate(falcon).length, 0);
  assert.ok(packs.validate(withW({ gate: { ...det.gate, choices: [{ value: "x", label: "x", callout: { kind: "expect", label: "l", body: "b" } }] } })).some((e) => /choice x needs emits true or false/.test(e)));
  assert.ok(packs.validate(withW({ gate: undefined })).some((e) => /a step asks a gate the workflow does not have/.test(e)));
  assert.ok(packs.validate(withW({ steps: det.steps.map((s) => ({ ...s, gate: undefined })) })).some((e) => /is asked under no step/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", gate: true, choices: { nope: { query: "cs_trace" } } }] })).some((e) => /choice nope is not a value of the gate/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", gate: true, choices: { os: { query: "no_such" } } }] })).some((e) => /choice os names unknown query no_such/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "cs_trace", join: "e_x" }] })).some((e) => /names more than one of edge, query and join/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", join: "" }] })).some((e) => /join must be an edge id/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "cs_trace", caution: "" }] })).some((e) => /caution must be a non-empty string/.test(e)));
  assert.ok(packs.validate(withW({ entries: [{ container: "aws:cloudtrail", column: "aid", param: "aid" }] })).some((e) => /a column entry needs a container the pack declares/.test(e)));
  assert.ok(packs.validate(withW({ entries: [{ concept: "aid", container: "crowdstrike:events:sensor", param: "aid" }] })).some((e) => /entries need a known concept and a param/.test(e)));
  assert.ok(packs.validate(withW({ value_link: "yes" })).some((e) => /value_link is true or absent/.test(e)));
  const choice = det.gate.choices.find((c) => c.value === "os");
  const linked = { ...det.gate, choices: det.gate.choices.map((c) => (c === choice ? { ...c, callout: { ...c.callout, link: { ...c.callout.link, workflow: "nowhere" } } } : c)) };
  assert.ok(packs.validate(withW({ gate: linked })).some((e) => /gate choice os links unknown workflow nowhere/.test(e)));
  assert.ok(packs.validate({ ...falcon, params: { ...falcon.params, pid: { label: "x", from_field: "RawProcessId", from_concept: "raw_process_id" } } }).some((e) => /from_field or from_concept, not both/.test(e)));
});

test("a workflow result may name a pack query instead of an edge; a list param binds the pack's list; the definition names its containers and the hunt wording", () => {
  const falcon = packs.pack("crowdstrike-falcon");
  const w = falcon.workflows.find((x) => x.id === "hunt_mac_signing");
  const withW = (patch) => ({ ...falcon, workflows: [{ ...w, ...patch }] });
  assert.equal(packs.validate(falcon).length, 0);
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "no_such_query" }] })).some((e) => /unknown query no_such_query/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "hunt_mac_apple_path", edge: "cs_host_events" }] })).some((e) => /more than one of edge, query and join/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "hunt_mac_apple_path", params: { paths: "@no_such_list" } }] })).some((e) => /unknown list @no_such_list/.test(e)));
  assert.ok(packs.validate(withW({ results: [{ id: "r", query: "hunt_mac_apple_path", shape: { columns: [{ label: "x" }] } }] })).some((e) => /shape needs columns with a key/.test(e)));
  assert.ok(packs.validate({ ...falcon, lists: { apple_paths: { values: [] } } }).some((e) => /list apple_paths: values must be/.test(e)));

  const def = workflows.get("hunt_mac_signing", { params: {} });
  assert.deepEqual(def.containers, ["crowdstrike:events:sensor"]);
  assert.match(def.hunt.schedule, /Save As, Alert/);
  assert.deepEqual(def.steps.map((s) => s.names), [["window"]]);
  const results = def.results({});
  assert.deepEqual(results.map((r) => r.id), ["namespace", "path"]);
  for (const r of results) {
    assert.equal(r.pivot.kind, "pack");
    assert.equal(r.pivot.edge.dst.sourcetype, "crowdstrike:events:sensor");
    assert.equal(r.shape.columns.find((c) => c.key === "ImageFileName").field, "ImageFileName");
    assert.equal(r.shape.columns.find((c) => c.key === "events").field, undefined);
  }
  assert.deepEqual(results[0].params, {});
  assert.deepEqual(results[1].params.paths, falcon.lists.apple_paths.values);
  assert.notEqual(results[1].params.paths, falcon.lists.apple_paths.values, "a copy, not the pack's own array");
  assert.deepEqual(workflows.get("hunt_mac_signing", { params: { window: "-30d" } }).results({ window: "-30d" })[0].params, { window: "-30d" });
  // No value to start from: nothing offers it from a field; the list carries it with the containers its searches run on.
  assert.deepEqual(workflows.forField("crowdstrike:events:sensor", "SigningId"), []);
  const listed = workflows.list().find((x) => x.id === "hunt_mac_signing");
  assert.equal(listed.packId, "crowdstrike-falcon");
  assert.deepEqual(listed.containers, ["crowdstrike:events:sensor"]);
  assert.equal(listed.hunt, true);
});

test("packs.query answers in this platform's language for a query written in both, on that language's own containers, with that language's own hazards", () => {
  const q = packs.query("crowdstrike-falcon", "hunt_mac_apple_path");
  assert.ok(q.spl && !q.kql);
  assert.deepEqual(q.containers, ["crowdstrike:events:sensor"]);
  assert.ok(q.hazards.some((h) => /_time/.test(h.text)), "the Splunk block's own hazard rides along");
  assert.equal(packs.query("crowdstrike-falcon", "hunt_mac_apple_path", { container: "ReachCrowdStrike_CL" }), null);
});
