import type { PassiveSource } from "./types.js";
import type { Finding } from "../core/finding.js";
import { makeId } from "../core/finding.js";

export class SeedSource implements PassiveSource {
  readonly name = "seed";
  readonly description = "Root domain provided by the operator";
  readonly enabled = true;

  constructor(private readonly rootDomain: string) {}

  async collect(): Promise<Finding[]> {
    return [
      {
        id: makeId("seed"),
        kind: "domain",
        value: this.rootDomain,
        rootDomain: this.rootDomain,
        confidence: "high",
        provenance: {
          source: "operator",
          method: "cli-argument",
          retrievedAt: new Date().toISOString(),
        },
        metadata: {},
      },
    ];
  }
}
