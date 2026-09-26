import type { Finding } from "../core/finding.js";

export interface LedgerFile {
  generatedAt: string;
  findings: Finding[];
}

export interface CertRotation {
  domain: string;
  oldFingerprint: string;
  newFingerprint: string;
}

export interface LedgerDiff {
  generatedA: string;
  generatedB: string;
  added: Finding[];
  removed: Finding[];
  certRotations: CertRotation[];
}

function loadLedger(value: unknown): LedgerFile {
  const parsed = value as LedgerFile;
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.findings)) {
    throw new Error("not a shadowstack ledger file");
  }
  return parsed;
}

function certFingerprintByDomain(findings: Finding[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const f of findings) {
    if (f.kind !== "cert") continue;
    const domains = f.metadata.domains as string[] | undefined;
    if (!domains) continue;
    for (const domain of domains) {
      map.set(domain, f.value);
    }
  }
  return map;
}

export function diffFindings(a: Finding[], b: Finding[]): Omit<LedgerDiff, "generatedA" | "generatedB"> {
  const keyOf = (f: Finding) => `${f.kind}:${f.value}`;
  const aByKey = new Map(a.map((f) => [keyOf(f), f]));
  const bByKey = new Map(b.map((f) => [keyOf(f), f]));

  const added: Finding[] = [];
  const removed: Finding[] = [];
  for (const [key, f] of bByKey) {
    if (!aByKey.has(key)) added.push(f);
  }
  for (const [key, f] of aByKey) {
    if (!bByKey.has(key)) removed.push(f);
  }

  const aCerts = certFingerprintByDomain(a);
  const bCerts = certFingerprintByDomain(b);
  const certRotations: CertRotation[] = [];
  for (const [domain, newFp] of bCerts) {
    const oldFp = aCerts.get(domain);
    if (oldFp && oldFp !== newFp) {
      certRotations.push({ domain, oldFingerprint: oldFp, newFingerprint: newFp });
    }
  }

  return { added, removed, certRotations };
}

export function diffLedgers(aRaw: unknown, bRaw: unknown): LedgerDiff {
  const a = loadLedger(aRaw);
  const b = loadLedger(bRaw);
  const { added, removed, certRotations } = diffFindings(a.findings, b.findings);
  return {
    generatedA: a.generatedAt,
    generatedB: b.generatedAt,
    added,
    removed,
    certRotations,
  };
}

export function diffToConsole(diff: LedgerDiff): string {
  const lines: string[] = [];
  lines.push(`shadowstack ledger diff`);
  lines.push(`  a: ${diff.generatedA}`);
  lines.push(`  b: ${diff.generatedB}`);
  lines.push(`  added:   ${diff.added.length}`);
  lines.push(`  removed: ${diff.removed.length}`);
  for (const f of diff.added) {
    lines.push(`    + [${f.kind}] ${f.value}`);
  }
  for (const f of diff.removed) {
    lines.push(`    - [${f.kind}] ${f.value}`);
  }
  lines.push(`  cert rotations: ${diff.certRotations.length}`);
  for (const r of diff.certRotations) {
    lines.push(`    ~ [domain] ${r.domain}: ${r.oldFingerprint.slice(0, 23)}… -> ${r.newFingerprint.slice(0, 23)}…`);
  }
  return lines.join("\n");
}
