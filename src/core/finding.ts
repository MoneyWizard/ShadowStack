export type AssetKind = "domain" | "ip" | "url" | "cert";

export type Confidence = "low" | "medium" | "high";

export interface Provenance {
  source: string;
  method: string;
  retrievedAt: string;
}

export interface Finding {
  id: string;
  kind: AssetKind;
  value: string;
  rootDomain: string;
  confidence: Confidence;
  provenance: Provenance;
  metadata: Record<string, unknown>;
}

let counter = 0;

export function makeId(prefix: string): string {
  counter += 1;
  const ts = Date.now().toString(36);
  return `${prefix}_${ts}${counter.toString(36)}`;
}

export function confidenceFrom(score: number): Confidence {
  if (score >= 0.75) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

export function isFinding(value: unknown): value is Finding {
  if (typeof value !== "object" || value === null) return false;
  const f = value as Record<string, unknown>;
  return (
    typeof f.id === "string" &&
    typeof f.kind === "string" &&
    typeof f.value === "string" &&
    typeof f.rootDomain === "string" &&
    typeof f.confidence === "string" &&
    typeof f.provenance === "object" &&
    f.provenance !== null
  );
}
