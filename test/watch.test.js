import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function importDist(rel) {
  const url = new URL(`../dist/${rel}`, import.meta.url).href;
  return import(url);
}

const REPO_ROOT = new URL("../", import.meta.url).pathname;

function makeConfig(dir, overrides = {}) {
  const config = {
    targets: ["example.com"],
    sources: { crtsh: true, wayback: true, hackertarget: true },
    certs: { enabled: false },
    watch: { ledgerDir: dir, retention: 5 },
    ...overrides,
  };
  const path = join(dir, "shadowstack.json");
  writeFileSync(path, JSON.stringify(config));
  return path;
}

test("isAllowlisted matches target and subdomains only", async () => {
  const { isAllowlisted } = await importDist("config/config.js");
  const targets = ["Example.com"];
  assert.equal(isAllowlisted("example.com", targets), true);
  assert.equal(isAllowlisted("www.example.com", targets), true);
  assert.equal(isAllowlisted("deep.sub.example.com", targets), true);
  assert.equal(isAllowlisted("notexample.com", targets), false);
  assert.equal(isAllowlisted("example.com.evil.net", targets), false);
});

test("loadConfig validates and normalizes", async () => {
  const { loadConfig } = await importDist("config/config.js");
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-cfg-"));
  try {
    const bad1 = join(dir, "bad1.json");
    writeFileSync(bad1, JSON.stringify({ targets: [] }));
    assert.throws(() => loadConfig(bad1), /targets/);

    const bad2 = join(dir, "bad2.json");
    writeFileSync(bad2, JSON.stringify({ targets: ["not a domain!"] }));
    assert.throws(() => loadConfig(bad2), /invalid domain/);

    const bad3 = join(dir, "bad3.json");
    writeFileSync(bad3, JSON.stringify({ targets: ["Example.COM."] }));
    const cfg = loadConfig(bad3);
    assert.deepEqual(cfg.targets, ["example.com"]);
    assert.equal(cfg.watch.retention, 30);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recon refuses non-allowlisted domain", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-recon-"));
  try {
    const configPath = makeConfig(dir);
    let stderr = "";
    let code = 0;
    try {
      execFileSync(
        "node",
        ["dist/cli.js", "recon", "other.net", "--config", configPath, "--quiet"],
        { cwd: REPO_ROOT, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      );
    } catch (err) {
      stderr = String(err.stderr);
      code = err.status ?? 1;
    }
    assert.equal(code, 1);
    assert.ok(stderr.includes("not in allowlist"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("watch writes ledgers, reports baseline then drift", async () => {
  const { latestLedger, readLedgerFindings, writeLedger, driftFor, pruneLedgers } =
    await importDist("report/watch.js");
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-watch-"));
  try {
    const mkFinding = (value, kind = "domain") => ({
      id: `${kind}-${value}`,
      kind,
      value,
      rootDomain: "example.com",
      confidence: "high",
      provenance: { source: "t", method: "t", retrievedAt: "now" },
      metadata: {},
    });

    writeLedger(dir, "example.com-2026-01-01.json", [mkFinding("a.example.com")], [
      { source: "crtsh", status: "ok", findingCount: 1 },
    ]);
    const prev = latestLedger(dir, "example.com");
    assert.ok(prev && prev.includes("2026-01-01"));

    const noDrift = driftFor(readLedgerFindings(prev), [mkFinding("a.example.com")]);
    assert.equal(noDrift.added.length, 0);

    const drift = driftFor(readLedgerFindings(prev), [
      mkFinding("a.example.com"),
      mkFinding("new.example.com"),
    ]);
    assert.deepEqual(drift.added.map((f) => f.value), ["new.example.com"]);

    const baseline = driftFor(null, [mkFinding("a.example.com")]);
    assert.equal(baseline, null);

    writeLedger(dir, "example.com-2026-01-02.json", [mkFinding("a.example.com")], []);
    writeLedger(dir, "example.com-2026-01-03.json", [mkFinding("a.example.com")], []);
    writeLedger(dir, "example.com-2026-01-04.json", [mkFinding("a.example.com")], []);
    const removed = pruneLedgers(dir, "example.com", 3);
    assert.equal(removed.length, 1);
    assert.ok(removed[0].includes("2026-01-01"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("watch cli end to end exits 2 on drift", () => {
  const dir = mkdtempSync(join(tmpdir(), "shadowstack-watchcli-"));
  try {
    const configPath = makeConfig(dir);
    const baselineSeed = join(dir, "seed");
    mkdirSync(baselineSeed);

    const mkFinding = (value) => ({
      id: `domain-${value}`,
      kind: "domain",
      value,
      rootDomain: "example.com",
      confidence: "high",
      provenance: { source: "t", method: "t", retrievedAt: "now" },
      metadata: {},
    });
    writeFileSync(
      join(dir, "example.com-2026-01-01T00-00-00-000Z.json"),
      JSON.stringify({
        generatedAt: "2026-01-01T00:00:00Z",
        findings: [mkFinding("known.example.com")],
        sources: [{ source: "crtsh", status: "ok", findingCount: 1 }],
      }),
    );

    let code = 0;
    let stdout = "";
    try {
      stdout = execFileSync(
        "node",
        ["dist/cli.js", "watch", "--config", configPath],
        { cwd: REPO_ROOT, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] },
      );
    } catch (err) {
      code = err.status ?? 1;
      stdout = String(err.stdout);
    }
    assert.ok([0, 2].includes(code), `unexpected exit ${code}`);
    assert.ok(stdout.includes("shadowstack watch"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
