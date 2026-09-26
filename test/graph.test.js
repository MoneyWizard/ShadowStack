import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

const f = (kind, value, extra = {}) => ({
  id: `${kind}-${value}`,
  kind,
  value,
  rootDomain: "example.com",
  confidence: "high",
  provenance: { source: "test", method: "test", retrievedAt: "now" },
  metadata: { ...extra },
});

test("buildGraph creates nodes and edges from findings", async () => {
  const { buildGraph } = await importDist("report/graph.js");
  const findings = [
    f("domain", "a.example.com", { clusterKey: "shared-ip:1.2.3.4" }),
    f("domain", "b.example.com"),
    f("ip", "1.2.3.4", { domain: "a.example.com", clusterKey: "shared-ip:1.2.3.4" }),
    f("cert", "AA:BB", { domains: ["a.example.com", "b.example.com"] }),
    f("domain", "orphan.example.com"),
  ];
  const g = buildGraph(findings);
  assert.equal(g.nodes.length, 5);
  assert.deepEqual(
    g.edges.map((e) => `${e.source}-${e.relation}->${e.target}`).sort(),
    [
      "a.example.com-presents-cert->AA:BB",
      "a.example.com-resolves-to->1.2.3.4",
      "b.example.com-presents-cert->AA:BB",
    ].sort(),
  );
  const clustered = g.nodes.find((n) => n.id === "a.example.com");
  assert.equal(clustered.clusterKey, "shared-ip:1.2.3.4");
});

test("toDot renders valid graphviz with clusters", async () => {
  const { buildGraph, toDot } = await importDist("report/graph.js");
  const findings = [
    f("domain", "a.example.com", { clusterKey: "shared-ip:1.2.3.4" }),
    f("ip", "1.2.3.4", { domain: "a.example.com", clusterKey: "shared-ip:1.2.3.4" }),
  ];
  const dot = toDot(buildGraph(findings));
  assert.ok(dot.startsWith("digraph shadowstack {"));
  assert.ok(dot.includes('subgraph "cluster_shared-ip:1.2.3.4"'));
  assert.ok(dot.includes('"a.example.com" -> "1.2.3.4" [label="resolves-to"];'));
  assert.ok(dot.trimEnd().endsWith("}"));
});

test("toDot escapes quotes in values", async () => {
  const { buildGraph, toDot } = await importDist("report/graph.js");
  const findings = [f("domain", 'we"ird.example.com')];
  const dot = toDot(buildGraph(findings));
  assert.ok(!dot.includes('label="we"ird'));
  assert.ok(dot.includes('label="we\\"ird.example.com"'));
});

test("cli graph command writes dot and json", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-graph-"));
  const repoRoot = new URL("../", import.meta.url).pathname;
  try {
    const ledger = join(dir, "ledger.json");
    writeFileSync(ledger, JSON.stringify({
      generatedAt: "2026-01-01T00:00:00Z",
      findings: [
        f("domain", "a.example.com"),
        f("ip", "1.2.3.4", { domain: "a.example.com" }),
      ],
    }));
    const dotPath = join(dir, "g.dot");
    const jsonPath = join(dir, "g.json");
    execFileSync("node", ["dist/cli.js", "graph", ledger, "--out", dotPath, "--quiet"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    const dot = readFileSync(dotPath, "utf8");
    assert.ok(dot.includes("digraph shadowstack"));
    execFileSync("node", ["dist/cli.js", "graph", ledger, "--out", jsonPath, "--json", "--quiet"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    const json = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(json.nodes.length, 2);
    assert.equal(json.edges.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
