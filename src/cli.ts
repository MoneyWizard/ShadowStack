import { parseArgs } from "node:util";
import { Pipeline } from "./core/pipeline.js";
import { SeedSource } from "./sources/seed.js";
import { CrtShSource } from "./sources/crtsh.js";
import { WaybackSource } from "./sources/wayback.js";
import { HackerTargetSource } from "./sources/hackertarget.js";
import { SourceRegistry } from "./sources/registry.js";
import { QuietResolver } from "./resolve/resolver.js";
import { CertGrabber } from "./certs/grabber.js";
import { AssetCorrelator } from "./correlate/correlator.js";
import { ExposureLedger } from "./report/ledger.js";
import type { Finding } from "./core/finding.js";

const USAGE = `shadowstack — passive-first attack surface recon

Usage:
  shadowstack recon <domain> [options]
  shadowstack diff <ledger-a.json> <ledger-b.json> [options]
  shadowstack graph <ledger.json> [--out graph.dot] [--json]
  shadowstack ingest <headers-artifact> --root-domain <domain> [--out ledger.json]

Options (recon):
  --out <path>     write findings ledger to a JSON file
  --quiet          only print summary counts
  --certs          also grab TLS certificates from discovered hosts (active)

Options (diff):
  --out <path>     write diff result to a JSON file
  --quiet          only print summary counts

Options (graph):
  --out <path>     write graph as Graphviz DOT (default) or JSON (--json)
  --json           write the graph as node-link JSON instead of DOT
  --quiet          only print summary counts

Options (ingest):
  --root-domain <d>  root domain to tag ingested findings with (required)
  --out <path>       write ingested findings as a ledger JSON file
  --quiet            only print summary counts

  --help           show this help

By default the engine only uses passive sources (certificate transparency,
public DNS resolution). --certs performs live TLS handshakes with
discovered hosts; only use it against assets you are authorized to assess.
`;

interface CliOptions {
  out?: string;
  quiet: boolean;
  certs: boolean;
  json: boolean;
  rootDomain?: string;
  help: boolean;
}

function parseCli(argv: string[]): { command: string; positional: string[]; opts: CliOptions } | null {
  const positional: string[] = [];
  const flags = new Set<string>();
  let out: string | undefined;
  let rootDomain: string | undefined;

  if (argv.includes("--help")) {
    return { command: "", positional: [], opts: { quiet: false, certs: false, json: false, help: true } };
  }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--out" && i + 1 < argv.length) {
      out = argv[++i];
      continue;
    }
    if (arg === "--root-domain" && i + 1 < argv.length) {
      rootDomain = argv[++i].toLowerCase().replace(/\.$/, "");
      continue;
    }
    if (arg === "--out" || arg === "--quiet" || arg === "--certs" || arg === "--json" || arg === "--help") {
      flags.add(arg);
      continue;
    }
    if (arg.startsWith("--")) {
      return null;
    }
    positional.push(arg);
  }

  const command = positional[0];
  if (!command) return null;

  if (command === "diff") {
    if (positional.length < 3) return null;
  } else if (command === "graph") {
    if (positional.length < 2) return null;
  } else if (command === "ingest") {
    if (positional.length < 2) return null;
  } else if (positional.length < 2) {
    return null;
  }

  return {
    command,
    positional,
    opts: {
      out,
      quiet: flags.has("--quiet"),
      certs: flags.has("--certs"),
      json: flags.has("--json"),
      rootDomain,
      help: flags.has("--help"),
    },
  };
}

async function runRecon(domain: string, opts: CliOptions): Promise<void> {
  const registry = new SourceRegistry()
    .register(new SeedSource(domain))
    .register(new CrtShSource())
    .register(new WaybackSource())
    .register(new HackerTargetSource());

  const seed: Finding[] = [];
  const collected = await registry.collectAll(domain);
  seed.push(...collected);

  const pipeline = new Pipeline().add(new QuietResolver());
  if (opts.certs) {
    pipeline.add(new CertGrabber());
  }
  pipeline.add(new AssetCorrelator());

  const findings = await pipeline.run(collected);

  const ledger = new ExposureLedger({ outPath: opts.out });
  const { alerts } = ledger.write(findings);

  if (!opts.quiet) {
    console.log(ledger.toConsole(findings, alerts));
  } else {
    const domains = findings.filter((f) => f.kind === "domain").length;
    const ips = findings.filter((f) => f.kind === "ip").length;
    console.log(`domains: ${domains}  ips: ${ips}`);
  }
}

async function runDiff(paths: string[], opts: CliOptions): Promise<void> {
  const { readFileSync } = await import("node:fs");
  const { diffLedgers, diffToConsole } = await import("./report/diff.js");
  const aRaw = JSON.parse(readFileSync(paths[0], "utf8"));
  const bRaw = JSON.parse(readFileSync(paths[1], "utf8"));
  const diff = diffLedgers(aRaw, bRaw);

  if (opts.out) {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(
      opts.out,
      JSON.stringify({ diffedAt: new Date().toISOString(), ...diff }, null, 2),
    );
  }

  if (!opts.quiet) {
    console.log(diffToConsole(diff));
  } else {
    console.log(
      `added: ${diff.added.length}  removed: ${diff.removed.length}  rotations: ${diff.certRotations.length}`,
    );
  }
}

async function runGraph(path: string, opts: CliOptions): Promise<void> {
  const { readFileSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { dirname } = await import("node:path");
  const { buildGraph, toDot, graphToConsole } = await import("./report/graph.js");
  const ledger = JSON.parse(readFileSync(path, "utf8"));
  const graph = buildGraph(ledger.findings);

  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true });
    if (opts.json) {
      writeFileSync(opts.out, JSON.stringify(graph, null, 2));
    } else {
      writeFileSync(opts.out, toDot(graph));
    }
  } else if (opts.json) {
    console.log(JSON.stringify(graph, null, 2));
  } else {
    console.log(toDot(graph));
  }

  if (!opts.quiet) {
    console.error(graphToConsole(graph));
  }
}

async function runIngest(path: string, opts: CliOptions): Promise<void> {
  if (!opts.rootDomain) {
    throw new Error("--root-domain is required for ingest");
  }
  const { ingestHeaderArtifact } = await import("./ingest/headers.js");
  const { AssetCorrelator } = await import("./correlate/correlator.js");
  const { ExposureLedger } = await import("./report/ledger.js");
  const findings = ingestHeaderArtifact(path, opts.rootDomain);
  const correlated = await new AssetCorrelator().run(findings);
  const ledger = new ExposureLedger({ outPath: opts.out });
  const { alerts } = ledger.write(correlated);
  if (!opts.quiet) {
    console.log(ledger.toConsole(correlated, alerts));
  } else {
    console.log(`urls: ${correlated.filter((f) => f.kind === "url").length}`);
  }
}

async function main(): Promise<void> {
  const parsed = parseCli(process.argv.slice(2));
  if (
    !parsed ||
    parsed.opts.help ||
    (
      parsed.command !== "recon" &&
      parsed.command !== "diff" &&
      parsed.command !== "graph" &&
      parsed.command !== "ingest"
    )
  ) {
    console.log(USAGE);
    process.exitCode = parsed?.opts.help ? 0 : 1;
    return;
  }

  if (parsed.command === "diff") {
    try {
      await runDiff([parsed.positional[1], parsed.positional[2]], parsed.opts);
    } catch (err) {
      console.error(`diff failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "graph") {
    try {
      await runGraph(parsed.positional[1], parsed.opts);
    } catch (err) {
      console.error(`graph failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  if (parsed.command === "ingest") {
    try {
      await runIngest(parsed.positional[1], parsed.opts);
    } catch (err) {
      console.error(`ingest failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
    return;
  }

  const domain = parsed.positional[1].toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(domain)) {
    console.error(`invalid domain: ${parsed.positional[1]}`);
    process.exitCode = 1;
    return;
  }

  try {
    await runRecon(domain, parsed.opts);
  } catch (err) {
    console.error(`recon failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

void main();
