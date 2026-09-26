import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { ShadowStackConfig } from "../config/config.js";
import type { Finding } from "../core/finding.js";
import { diffFindings } from "./diff.js";
import type { LedgerDiff } from "./diff.js";
import { isFinding } from "../core/finding.js";

export interface TargetReport {
  target: string;
  ledgerPath: string;
  previousLedgerPath?: string;
  findings: number;
  drift: Omit<LedgerDiff, "generatedA" | "generatedB"> | null;
  sourceFailures: Array<{ source: string; error?: string }>;
}

export interface WatchReport {
  ranAt: string;
  targets: TargetReport[];
  driftCount: number;
  sourceFailureCount: number;
}

export function ledgerFileName(target: string, timestamp: string): string {
  return `${target.replace(/[^a-z0-9.-]/g, "_")}-${timestamp}.json`;
}

export function latestLedger(dir: string, target: string): string | null {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return null;
  }
  const prefix = `${target}-`;
  const candidates = entries
    .filter((e) => e.startsWith(prefix) && e.endsWith(".json"))
    .sort();
  if (candidates.length === 0) return null;
  return join(dir, candidates[candidates.length - 1]);
}

export function pruneLedgers(dir: string, target: string, retention: number): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const prefix = `${target}-`;
  const candidates = entries
    .filter((e) => e.startsWith(prefix) && e.endsWith(".json"))
    .sort();
  const removed: string[] = [];
  while (candidates.length > retention) {
    const victim = candidates.shift();
    if (!victim) break;
    rmSync(join(dir, victim));
    removed.push(victim);
  }
  return removed;
}

export function readLedgerFindings(path: string): Finding[] {
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const findings = parsed?.findings;
  if (!Array.isArray(findings) || !findings.every(isFinding)) {
    throw new Error(`not a shadowstack ledger: ${path}`);
  }
  return findings;
}

export function writeLedger(
  dir: string,
  fileName: string,
  findings: Finding[],
  sourceHealth: Array<{ source: string; status: string; findingCount: number; error?: string }>,
): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, fileName);
  writeFileSync(
    path,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        findings,
        sources: sourceHealth,
      },
      null,
      2,
    ),
  );
  return path;
}

export function driftFor(
  previous: Finding[] | null,
  current: Finding[],
): Omit<LedgerDiff, "generatedA" | "generatedB"> | null {
  if (previous === null) return null;
  const { added, removed, certRotations } = diffFindings(previous, current);
  if (added.length === 0 && removed.length === 0 && certRotations.length === 0) {
    return { added: [], removed: [], certRotations: [] };
  }
  return { added, removed, certRotations };
}

export function watchToConsole(report: WatchReport): string {
  const lines: string[] = [];
  lines.push(`shadowstack watch — ${report.ranAt}`);
  for (const t of report.targets) {
    lines.push(`  ${t.target}`);
    lines.push(`    findings: ${t.findings}`);
    if (t.sourceFailures.length > 0) {
      lines.push(`    source failures:`);
      for (const f of t.sourceFailures) {
        lines.push(`      ! ${f.source}${f.error ? `: ${f.error}` : ""}`);
      }
    }
    if (t.drift === null) {
      lines.push(`    drift: baseline run (no previous ledger)`);
    } else if (t.drift.added.length === 0 && t.drift.removed.length === 0 && t.drift.certRotations.length === 0) {
      lines.push(`    drift: none`);
    } else {
      lines.push(`    drift:`);
      for (const f of t.drift.added) lines.push(`      + [${f.kind}] ${f.value}`);
      for (const f of t.drift.removed) lines.push(`      - [${f.kind}] ${f.value}`);
      for (const r of t.drift.certRotations) {
        lines.push(`      ~ [domain] ${r.domain}: cert rotated`);
      }
    }
  }
  lines.push(`  totals: targets ${report.targets.length}, drift ${report.driftCount}, source failures ${report.sourceFailureCount}`);
  return lines.join("\n");
}
