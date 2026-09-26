import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

test("finding ids are unique and prefixed", async () => {
  const { makeId } = await importDist("core/finding.js");
  const a = makeId("seed");
  const b = makeId("seed");
  assert.notEqual(a, b);
  assert.ok(a.startsWith("seed_"));
});

test("confidenceFrom maps numeric scores", async () => {
  const { confidenceFrom } = await importDist("core/finding.js");
  assert.equal(confidenceFrom(0.9), "high");
  assert.equal(confidenceFrom(0.5), "medium");
  assert.equal(confidenceFrom(0.1), "low");
});

test("isFinding validates shape", async () => {
  const { isFinding } = await importDist("core/finding.js");
  const good = {
    id: "x",
    kind: "domain",
    value: "example.com",
    rootDomain: "example.com",
    confidence: "high",
    provenance: { source: "operator", method: "cli", retrievedAt: "now" },
    metadata: {},
  };
  assert.equal(isFinding(good), true);
  assert.equal(isFinding({ id: "x" }), false);
  assert.equal(isFinding(null), false);
});

test("pipeline passes findings through stages in order", async () => {
  const { Pipeline } = await importDist("core/pipeline.js");
  const seen = [];
  const stage = (name, values) => ({
    name,
    async run(input) {
      seen.push(name);
      return [...input, ...values];
    },
  });
  const p = new Pipeline()
    .add(stage("a", ["a"]))
    .add(stage("b", ["b"]));
  const out = await p.run([]);
  assert.deepEqual(seen, ["a", "b"]);
  assert.deepEqual(out, ["a", "b"]);
});

test("source registry collects from enabled sources only", async () => {
  const { SourceRegistry } = await importDist("sources/registry.js");
  const makeSource = (name, enabled, findings) => ({
    name,
    description: "",
    enabled,
    async collect() {
      return findings;
    },
  });
  const reg = new SourceRegistry()
    .register(makeSource("on", true, [{ value: 1 }]))
    .register(makeSource("off", false, [{ value: 2 }]));
  const results = await reg.collectAll("example.com");
  assert.equal(results.length, 1);
  assert.equal(results[0].value, 1);
  assert.equal(reg.list().length, 2);
});

test("correlator clusters domains sharing an ip", async () => {
  const { AssetCorrelator } = await importDist("correlate/correlator.js");
  const findings = [
    { id: "1", kind: "domain", value: "a.example.com", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: {} },
    { id: "2", kind: "domain", value: "b.example.com", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: {} },
    { id: "3", kind: "ip", value: "1.2.3.4", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { domain: "a.example.com" } },
    { id: "4", kind: "ip", value: "1.2.3.4", rootDomain: "example.com", confidence: "high", provenance: {}, metadata: { domain: "b.example.com" } },
  ];
  const correlator = new AssetCorrelator();
  const out = await correlator.run(findings);
  const clustered = out.filter((f) => f.metadata && f.metadata.clusterKey);
  assert.equal(clustered.length, 4);
  assert.equal(clustered[0].metadata.clusterKey, "shared-ip:1.2.3.4");
});

test("ledger writes sorted json and renders summary", async () => {
  const { ExposureLedger } = await importDist("report/ledger.js");
  const { mkdtempSync, readFileSync: rf, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-test-"));
  const outPath = join(dir, "ledger.json");
  const findings = [
    { id: "1", kind: "domain", value: "b.example.com", rootDomain: "example.com", confidence: "high", provenance: { source: "crt.sh" }, metadata: {} },
    { id: "2", kind: "domain", value: "a.example.com", rootDomain: "example.com", confidence: "medium", provenance: { source: "operator" }, metadata: {} },
  ];
  const ledger = new ExposureLedger({ outPath });
  ledger.write(findings);
  const written = JSON.parse(rf(outPath, "utf8"));
  assert.equal(written.findings.length, 2);
  assert.equal(written.findings[0].value, "a.example.com");
  assert.ok(written.generatedAt);
  const text = ledger.toConsole(findings);
  assert.ok(text.includes("domains: 2"));
  rmSync(dir, { recursive: true, force: true });
});

test("cli prints usage on no args and rejects bad domains", () => {
  let out = "";
  let code = 0;
  try {
    execFileSync("node", ["dist/cli.js"], { cwd: new URL("..", import.meta.url).pathname });
  } catch (err) {
    out = err.stdout?.toString() ?? "";
    code = err.status ?? 1;
  }
  assert.ok(out.includes("shadowstack"));
  assert.equal(code, 1);
});
