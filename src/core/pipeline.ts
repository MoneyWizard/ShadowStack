import type { Finding } from "./finding.js";

export interface ReconStage {
  name: string;
  run(input: Finding[]): Promise<Finding[]>;
}

export class Pipeline {
  private readonly stages: ReconStage[] = [];

  add(stage: ReconStage): this {
    this.stages.push(stage);
    return this;
  }

  async run(seed: Finding[]): Promise<Finding[]> {
    let current = seed;
    for (const stage of this.stages) {
      current = await stage.run(current);
    }
    return current;
  }
}
