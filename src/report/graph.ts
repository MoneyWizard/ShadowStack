import type { Finding } from "../core/finding.js";

export interface GraphNode {
  id: string;
  label: string;
  kind: string;
  clusterKey?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface AssetGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export function buildGraph(findings: Finding[]): AssetGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];

  const upsertNode = (f: Finding) => {
    const existing = nodes.get(f.value);
    if (existing) {
      if (f.metadata.clusterKey && !existing.clusterKey) {
        existing.clusterKey = String(f.metadata.clusterKey);
      }
      return existing;
    }
    const node: GraphNode = {
      id: f.value,
      label: f.value,
      kind: f.kind,
    };
    if (f.metadata.clusterKey) node.clusterKey = String(f.metadata.clusterKey);
    nodes.set(f.value, node);
    return node;
  };

  for (const f of findings) {
    if (f.kind === "domain" || f.kind === "ip" || f.kind === "cert") {
      upsertNode(f);
    }
  }

  for (const f of findings) {
    if (f.kind === "ip" && typeof f.metadata.domain === "string") {
      edges.push({ source: f.metadata.domain, target: f.value, relation: "resolves-to" });
    }
    if (f.kind === "cert" && Array.isArray(f.metadata.domains)) {
      for (const domain of f.metadata.domains as string[]) {
        edges.push({ source: domain, target: f.value, relation: "presents-cert" });
      }
    }
  }

  return { nodes: [...nodes.values()], edges };
}

function esc(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function toDot(graph: AssetGraph): string {
  const lines: string[] = [];
  lines.push("digraph shadowstack {");
  lines.push("  rankdir=LR;");
  lines.push("  node [shape=box];");

  const byCluster = new Map<string, GraphNode[]>();
  for (const node of graph.nodes) {
    const key = node.clusterKey ?? "";
    const list = byCluster.get(key) ?? [];
    list.push(node);
    byCluster.set(key, list);
  }

  for (const node of graph.nodes) {
    const attrs = [`label="${esc(node.label)}"`, `kind=${node.kind}`];
    if (node.clusterKey) attrs.push(`cluster="${esc(node.clusterKey)}"`);
    lines.push(`  "${esc(node.id)}" [${attrs.join(", ")}];`);
  }

  for (const [cluster, members] of byCluster) {
    if (!cluster) continue;
    lines.push(`  subgraph "cluster_${esc(cluster)}" {`);
    lines.push(`    label="${esc(cluster)}";`);
    for (const m of members) {
      lines.push(`    "${esc(m.id)}";`);
    }
    lines.push("  }");
  }

  for (const edge of graph.edges) {
    lines.push(
      `  "${esc(edge.source)}" -> "${esc(edge.target)}" [label="${esc(edge.relation)}"];`,
    );
  }

  lines.push("}");
  return lines.join("\n");
}

export function graphToConsole(graph: AssetGraph): string {
  return [
    "shadowstack asset graph",
    `  nodes: ${graph.nodes.length}`,
    `  edges: ${graph.edges.length}`,
    `  clusters: ${new Set(graph.nodes.map((n) => n.clusterKey).filter(Boolean)).size}`,
  ].join("\n");
}
