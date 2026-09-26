import type { Finding } from "../core/finding.js";

export interface PassiveSource {
  name: string;
  description: string;
  enabled: boolean;
  collect(rootDomain: string): Promise<Finding[]>;
}
