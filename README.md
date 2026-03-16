# peer-observer-agents

> [!NOTE]
> This is an experiment in introducing automated discovery and analysis of issues observed on the Bitcoin P2P network, via monitoring by a number of [peer-observer](https://github.com/peer-observer)-configured Bitcoin nodes.

AI agents for the [peer-observer](https://github.com/peer-observer) Bitcoin P2P network monitoring infrastructure.

## peer-observer-agent

A Rust HTTP service that investigates Prometheus alerts using Claude Code CLI with MCP tools, then posts findings as Grafana annotations.

```
Alertmanager webhook
        |
        v
  peer-observer-agent (Rust HTTP server)
        |
        |--> [optional] Bitcoin Core RPC (via WireGuard)
        |         |
        |         '-->  Pre-fetched node data injected into prompt
        |
        |-->  Claude CLI (--mcp-config)
        |         |
        |         '-->  prometheus-mcp-server (via uvx)
        |                    |
        |                    '-->  Prometheus API
        |
        '-->  Grafana Annotations API
```

1. Alertmanager sends a webhook to `POST /webhook`
2. For each firing alert, cooldown suppression checks whether the same `(alertname, host, threadname)` is already claimed (queued or running) or was recently investigated — if so, the alert is skipped before Claude is invoked
3. If not suppressed, the agent calls Claude Code CLI with a Prometheus MCP server
4. Claude autonomously queries Prometheus — discovering metrics, drilling into per-peer data, correlating across hosts, and identifying root causes
5. Posts the investigation findings as a structured Grafana annotation with tags `[ai-annotation, alertname, host, verdict]` (plus `threadname` for thread-aware alerts) where verdict is `benign`, `investigate`, or `action_required` (verdict tag omitted when structured parsing fails and raw text is posted as fallback)
6. Logs telemetry with a stable [correlation ID](docs/telemetry.md) for end-to-end tracing

### Configuration

All config via environment variables prefixed `ANNOTATION_AGENT_*`. Required: `ANNOTATION_AGENT_GRAFANA_API_KEY`, `ANNOTATION_AGENT_MCP_CONFIG`. Optional: `ANNOTATION_AGENT_COOLDOWN_SECS` (default 1800; 0 disables) suppresses redundant investigations when the same alert retriggers within the cooldown window. See [Configuration Reference](docs/deployment.md#configuration-reference) for the full table.

### Quick Start

```bash
export ANNOTATION_AGENT_GRAFANA_API_KEY="your-grafana-token"
export ANNOTATION_AGENT_MCP_CONFIG="/path/to/mcp-config.json"
cargo run
```

```bash
curl http://127.0.0.1:9099/healthz           # health check
curl -X POST http://127.0.0.1:9099/webhook \  # sample alert
  -H "Content-Type: application/json" \
  -d '{"alerts":[{"status":"firing","labels":{"alertname":"PeerObserverBlockStale","host":"test-node","severity":"warning","category":"chain_health"},"annotations":{"description":"No new block in 1 hour"},"startsAt":"2025-06-15T12:00:00Z","endsAt":"0001-01-01T00:00:00Z"}]}'
```

See [docs/testing.md](docs/testing.md) for the full smoke test walkthrough and development checks.

### Building

```bash
cargo build --release
```

### Development

```bash
just check   # fmt + strict clippy
just test    # run test suite
just pre-release  # local release gates (Darwin/Linux)
just fmt     # auto-format code
```

`nix build` remains part of CI, but the flake package targets Linux systems only.

### Documentation

- [Testing](docs/testing.md) — smoke tests, unit tests, CI
- [Deployment](docs/deployment.md) — NixOS, configuration reference, security assumptions, MCP config, health endpoint
- [Telemetry](docs/telemetry.md) — log correlation, structured logging fields, prior context scoping
- [Releasing](docs/releasing.md) — versioning, changelog, release workflow
