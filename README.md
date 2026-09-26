# ShadowStack

Passive-first attack surface recon engine. ShadowStack discovers what is *already exposed* about assets you are authorized to assess — without touching the target directly.

## Vision

ShadowStack maps the "stack shadow": the hidden infrastructure topology behind your domains that never made it into your asset inventory. It is built as a pipeline of small, auditable stages:

```
sources → resolve → correlate → report
```

- **sources** — pluggable passive intel adapters: certificate transparency (crt.sh), web archive history (Wayback Machine CDX), and passive DNS (HackerTarget). No active scanning, no probing.
- **resolve** — quiet DNS resolution through public resolvers, with bounded concurrency.
- **certs** — opt-in certificate grabber: live TLS handshake with discovered hosts to pull subject, issuer, validity window, serial, SHA-256 fingerprint, and SANs. Certificates are deduped by fingerprint — one finding per deployed cert, tagged with every domain that presents it.
- **correlate** — clusters assets that share infrastructure: domains on the same IP (`shared-ip:`), domains presenting the same certificate (`shared-cert:` — a strong same-deployment signal), and URLs sharing an HTTP header fingerprint (`shared-headers:`), revealing hidden topology.
- **ingest** — HTTP header fingerprint ingestion from existing scan artifacts (JSON or raw response dumps): server, x-powered-by, and CDN detection, no live traffic.
- **report** — an exposure ledger: every finding carries source provenance, timestamp, and confidence. Auditable, re-runnable, diffable over time. With `--certs`, the ledger also carries expiry alerts (`expired` / `critical` ≤7d / `warning` ≤30d). The `diff` command surfaces drift between runs (added/removed assets, cert rotations); the `graph` command exports the asset relationship graph as Graphviz DOT or node-link JSON.

## Install & build

```bash
npm install
npm run build
```

## Usage

```bash
# run passive recon against a root domain you are authorized to assess
npm run recon -- recon example.com

# write a JSON exposure ledger
npm run recon -- recon example.com --out recon-output/example.json

# summary counts only
npm run recon -- recon example.com --quiet

# also grab TLS certificates from discovered hosts (active handshake)
npm run recon -- recon example.com --certs --out recon-output/example.json

# compare two ledger runs: new/removed assets, cert rotations
npm run recon -- diff recon-output/old.json recon-output/new.json

# export the asset relationship graph (Graphviz DOT or JSON)
npm run recon -- graph recon-output/example.json --out recon-output/example.dot
npm run recon -- graph recon-output/example.json --json --out recon-output/example-graph.json

# ingest HTTP header fingerprints from an existing scan artifact
npm run recon -- ingest scan-headers.json --root-domain example.com --out recon-output/headers.json
```

## Tests

```bash
npm test
```

The suite is fully offline (mocked TLS sockets, injected clocks) — no network required.

## Authorization

ShadowStack is a defensive attack-surface management tool. Only run it against assets you own or are explicitly authorized to assess. The default pipeline is passive (certificate transparency logs, public DNS). The `--certs` stage performs live TLS handshakes with discovered hosts; only enable it against assets you are authorized to assess.

## Roadmap

- [ ] More passive sources (passive DNS aggregators, code hosting metadata)
- [ ] Scheduled re-runs with drift alerting (cron-friendly)
- [ ] Interactive dashboard over accumulated ledgers
