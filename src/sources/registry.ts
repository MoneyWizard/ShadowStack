import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";

export interface SourceHealth {
  source: string;
  status: "ok" | "failed";
  findingCount: number;
  error?: string;
}

export interface CollectResult {
  findings: Finding[];
  health: SourceHealth[];
}

export class SourceRegistry {
  private readonly sources: PassiveSource[] = [];

  register(source: PassiveSource): this {
    this.sources.push(source);
    return this;
  }

  list(): PassiveSource[] {
    return [...this.sources];
  }

  async collectAll(rootDomain: string): Promise<CollectResult> {
    const findings: Finding[] = [];
    const health: SourceHealth[] = [];
    for (const source of this.sources) {
      if (!source.enabled) continue;
      try {
        const found = await source.collect(rootDomain);
        findings.push(...found);
        health.push({ source: source.name, status: "ok", findingCount: found.length });
      } catch (err) {
        health.push({
          source: source.name,
          status: "failed",
          findingCount: 0,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return { findings, health };
  }
}
