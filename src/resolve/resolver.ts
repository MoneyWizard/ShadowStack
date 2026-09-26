import { Resolver } from "node:dns/promises";
import type { ReconStage } from "../core/pipeline.js";
import type { Finding } from "../core/finding.js";
import { makeId, confidenceFrom } from "../core/finding.js";

export class QuietResolver implements ReconStage {
  readonly name = "resolve";

  constructor(
    private readonly concurrency = 8,
    private readonly timeoutMs = 5000,
  ) {}

  async run(findings: Finding[]): Promise<Finding[]> {
    const domains = new Set<string>();
    for (const f of findings) {
      if (f.kind === "domain") domains.add(f.value);
    }

    const queue = [...domains];
    const ips = new Map<string, string[]>();
    const workers = Array.from({ length: this.concurrency }, async () => {
      const resolver = new Resolver();
      for (;;) {
        const domain = queue.shift();
        if (domain === undefined) return;
        try {
          const records = await resolver.resolve4(domain);
          if (records.length > 0) {
            ips.set(domain, records);
          }
        } catch {
          continue;
        }
      }
    });
    await Promise.all(workers);

    const out = [...findings];
    for (const [domain, records] of ips) {
      for (const ip of records) {
        out.push({
          id: makeId("ip"),
          kind: "ip",
          value: ip,
          rootDomain: this.rootOf(findings, domain),
          confidence: confidenceFrom(0.9),
          provenance: {
            source: "public-resolver",
            method: "dns-a-record",
            retrievedAt: new Date().toISOString(),
          },
          metadata: { domain },
        });
      }
    }
    return out;
  }

  private rootOf(findings: Finding[], domain: string): string {
    const match = findings.find((f) => f.value === domain);
    return match ? match.rootDomain : domain;
  }
}
