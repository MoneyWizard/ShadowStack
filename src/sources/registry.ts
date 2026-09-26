import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";

export class SourceRegistry {
  private readonly sources: PassiveSource[] = [];

  register(source: PassiveSource): this {
    this.sources.push(source);
    return this;
  }

  list(): PassiveSource[] {
    return [...this.sources];
  }

  async collectAll(rootDomain: string): Promise<Finding[]> {
    const results: Finding[] = [];
    for (const source of this.sources) {
      if (!source.enabled) continue;
      try {
        const found = await source.collect(rootDomain);
        results.push(...found);
      } catch {
        continue;
      }
    }
    return results;
  }
}
