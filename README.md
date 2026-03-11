# peer-observer-agents

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
2. For each firing alert, the agent calls Claude Code CLI with a Prometheus MCP server
3. Claude autonomously queries Prometheus — discovering metrics, drilling into per-peer data, correlating across hosts, and identifying root causes
4. Posts the investigation findings as a Grafana annotation with tags `[ai-annotation, alertname, host]`
5. Logs telemetry with a stable [correlation ID](docs/telemetry.md) for end-to-end tracing

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ANNOTATION_AGENT_LISTEN_ADDR` | `127.0.0.1:9099` | HTTP listen address |
| `ANNOTATION_AGENT_GRAFANA_URL` | `http://127.0.0.1:9321` | Grafana base URL |
| `ANNOTATION_AGENT_GRAFANA_API_KEY` | (required) | Grafana service account token |
| `ANNOTATION_AGENT_CLAUDE_BIN` | `claude` | Path to Claude CLI binary |
| `ANNOTATION_AGENT_CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model to use for investigations |
| `ANNOTATION_AGENT_MCP_CONFIG` | (required) | Path to MCP config JSON for Prometheus |
| `ANNOTATION_AGENT_LOG_FILE` | (optional) | Path to append plain-text annotation log |
| `ANNOTATION_AGENT_HTTP_TIMEOUT_SECS` | `30` | HTTP client timeout for Grafana API calls |
| `ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS` | `600` | Max wall-clock time for a Claude CLI investigation |
| `ANNOTATION_AGENT_MAX_CONCURRENT` | `4` | Max concurrent Claude investigations (minimum 1) |
| `ANNOTATION_AGENT_RPC_HOSTS` | (optional) | JSON map of host names to WireGuard IPs for Bitcoin Core RPC pre-fetch (e.g., `{"bitcoin-03":"10.0.0.3"}`) |
| `ANNOTATION_AGENT_RPC_USER` | `rpc-extractor` | Bitcoin Core RPC username |
| `ANNOTATION_AGENT_RPC_PASSWORD` | (required if RPC_HOSTS set) | Bitcoin Core RPC password |
| `ANNOTATION_AGENT_RPC_PORT` | `9000` | Bitcoin Core RPC port (via WireGuard nginx proxy) |

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
- [Deployment](docs/deployment.md) — NixOS, security assumptions, MCP config, health endpoint
- [Telemetry](docs/telemetry.md) — log correlation, structured logging fields, prior context scoping
- [Releasing](docs/releasing.md) — versioning, changelog, release workflow
