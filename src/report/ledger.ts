import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Finding } from "../core/finding.js";

export interface LedgerOptions {
  outPath?: string;
}

export class ExposureLedger {
  constructor(private readonly options: LedgerOptions = {}) {}

  write(findings: Finding[]): void {
    const sorted = [...findings].sort((a, b) =>
      a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
    );
    if (this.options.outPath) {
      mkdirSync(dirname(this.options.outPath), { recursive: true });
      writeFileSync(
        this.options.outPath,
        JSON.stringify({ generatedAt: new Date().toISOString(), findings: sorted }, null, 2),
      );
    }
  }

  toConsole(findings: Finding[]): string {
    const domains = findings.filter((f) => f.kind === "domain");
    const ips = findings.filter((f) => f.kind === "ip");
    const lines: string[] = [];
    lines.push(`shadowstack recon complete`);
    lines.push(`  domains: ${domains.length}`);
    lines.push(`  ips:     ${ips.length}`);
    for (const f of findings) {
      lines.push(`  [${f.kind}] ${f.value} (${f.confidence}, ${f.provenance.source})`);
    }
    return lines.join("\n");
  }
}
