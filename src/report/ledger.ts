import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Finding } from "../core/finding.js";
import { expiryAlerts } from "../certs/expiry.js";
import type { ExpiryAlert } from "../certs/expiry.js";

export interface LedgerOptions {
  outPath?: string;
  now?: Date;
}

export class ExposureLedger {
  constructor(private readonly options: LedgerOptions = {}) {}

  write(findings: Finding[]): { findings: Finding[]; alerts: ExpiryAlert[] } {
    const sorted = [...findings].sort((a, b) =>
      a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
    );
    const alerts = expiryAlerts(sorted, this.options.now);
    if (this.options.outPath) {
      mkdirSync(dirname(this.options.outPath), { recursive: true });
      writeFileSync(
        this.options.outPath,
        JSON.stringify(
          {
            generatedAt: new Date().toISOString(),
            findings: sorted,
            alerts: { expiry: alerts },
          },
          null,
          2,
        ),
      );
    }
    return { findings: sorted, alerts };
  }

  toConsole(findings: Finding[], alerts: ExpiryAlert[] = []): string {
    const domains = findings.filter((f) => f.kind === "domain");
    const ips = findings.filter((f) => f.kind === "ip");
    const lines: string[] = [];
    lines.push(`shadowstack recon complete`);
    lines.push(`  domains: ${domains.length}`);
    lines.push(`  ips:     ${ips.length}`);
    for (const f of findings) {
      lines.push(`  [${f.kind}] ${f.value} (${f.confidence}, ${f.provenance.source})`);
    }
    if (alerts.length > 0) {
      lines.push(`  expiry alerts:`);
      for (const a of alerts) {
        lines.push(
          `    [${a.status}] ${a.subject} — ${a.daysRemaining}d (${a.validTo})`,
        );
      }
    }
    return lines.join("\n");
  }
}
