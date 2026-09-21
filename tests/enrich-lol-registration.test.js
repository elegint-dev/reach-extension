// enrich.js self-registers the seven G3/G4 sources (CIRCL, EPSS,
// LOLDrivers, LOLRMM, LOLBAS, GTFOBins, HijackLibs) on import, with no
// explicit register() call from a caller, the same way the G2 technique
// bundles do (see tests/enrich-technique-registration.test.js for why
// this check needs its own file with no beforeEach hook). Also checks
// the ordering promise app/lib/enrich.js documents: CIRCL is registered
// ahead of VirusTotal, which is registered later, by hand, in each
// popup file, so a hash offer always lists CIRCL first.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as enrich from "../app/lib/enrich.js";
import { source as vtSource } from "../app/lib/enrich/virustotal.js";

test("enrich.js self-registers all seven G3/G4 sources without an explicit register() call", () => {
  const ids = new Set(enrich.all().map((s) => s.id));
  for (const id of ["circl", "epss", "loldrivers", "lolrmm", "lolbas", "gtfobins", "hijacklibs"]) {
    assert.ok(ids.has(id), `${id} was not self-registered`);
  }
});

test("CIRCL lists before VirusTotal on a hash offer, once a popup file registers VirusTotal", () => {
  enrich.register(vtSource);
  const hashSources = enrich.list("hash").map((s) => s.id);
  const circlAt = hashSources.indexOf("circl");
  const vtAt = hashSources.indexOf("virustotal");
  assert.ok(circlAt !== -1 && vtAt !== -1, "both circl and virustotal answer hash");
  assert.ok(circlAt < vtAt, "circl must list before virustotal so a known-good hit is seen first");
});
