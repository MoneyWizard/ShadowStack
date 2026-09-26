import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
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

test("diffFindings reports added and removed assets", async () => {
  const { diffFindings } = await importDist("report/diff.js");
  const a = [f("domain", "old.example.com"), f("ip", "1.1.1.1")];
  const b = [f("domain", "old.example.com"), f("domain", "new.example.com")];
  const diff = diffFindings(a, b);
  assert.deepEqual(diff.added.map((x) => x.value), ["new.example.com"]);
  assert.deepEqual(diff.removed.map((x) => x.value), ["1.1.1.1"]);
  assert.equal(diff.certRotations.length, 0);
});

test("diffFindings detects cert rotations", async () => {
  const { diffFindings } = await importDist("report/diff.js");
  const a = [
    f("domain", "a.example.com"),
    f("cert", "AA:AA", { domains: ["a.example.com"] }),
  ];
  const b = [
    f("domain", "a.example.com"),
    f("cert", "BB:BB", { domains: ["a.example.com"] }),
  ];
  const diff = diffFindings(a, b);
  assert.equal(diff.certRotations.length, 1);
  assert.equal(diff.certRotations[0].domain, "a.example.com");
  assert.equal(diff.certRotations[0].oldFingerprint, "AA:AA");
  assert.equal(diff.certRotations[0].newFingerprint, "BB:BB");
});

test("diffLedgers validates and reads generatedAt", async () => {
  const { diffLedgers } = await importDist("report/diff.js");
  const a = { generatedAt: "2026-01-01T00:00:00Z", findings: [] };
  const b = { generatedAt: "2026-02-01T00:00:00Z", findings: [f("domain", "x.example.com")] };
  const diff = diffLedgers(a, b);
  assert.equal(diff.generatedA, a.generatedAt);
  assert.equal(diff.generatedB, b.generatedAt);
  assert.equal(diff.added.length, 1);
  assert.throws(() => diffLedgers({ nope: true }, b));
});

test("cli diff command end to end", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-diff-"));
  try {
    const ledgerA = join(dir, "a.json");
    const ledgerB = join(dir, "b.json");
    writeFileSync(ledgerA, JSON.stringify({
      generatedAt: "2026-01-01T00:00:00Z",
      findings: [
        f("domain", "keep.example.com"),
        f("cert", "AA:AA", { domains: ["keep.example.com"] }),
      ],
    }));
    writeFileSync(ledgerB, JSON.stringify({
      generatedAt: "2026-02-01T00:00:00Z",
      findings: [
        f("domain", "keep.example.com"),
        f("domain", "fresh.example.com"),
        f("cert", "BB:BB", { domains: ["keep.example.com"] }),
      ],
    }));
    const repoRoot = new URL("../", import.meta.url).pathname;
    const out = execFileSync("node", ["dist/cli.js", "diff", ledgerA, ledgerB], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    assert.ok(out.includes("added:   2"));
    assert.ok(out.includes("+ [domain] fresh.example.com"));
    assert.ok(out.includes("cert rotations: 1"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
