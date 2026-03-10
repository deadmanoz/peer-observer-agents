# Testing

## Quick Start (Smoke Test)

Start the agent locally with minimal config:

```bash
export ANNOTATION_AGENT_GRAFANA_API_KEY="your-grafana-token"
export ANNOTATION_AGENT_MCP_CONFIG="/path/to/mcp-config.json"
cargo run
```

Verify the service is up:

```bash
curl http://127.0.0.1:9099/healthz
# Expected: 200 OK (empty body)
```

Send a sample Alertmanager webhook:

```bash
curl -X POST http://127.0.0.1:9099/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [{
      "status": "firing",
      "labels": {"alertname": "PeerObserverBlockStale", "host": "test-node", "severity": "warning", "category": "chain_health"},
      "annotations": {"description": "No new block in 1 hour"},
      "startsAt": "2025-06-15T12:00:00Z",
      "endsAt": "0001-01-01T00:00:00Z"
    }]
  }'
```

On success (HTTP 200), the agent will have called Claude CLI and posted a Grafana annotation. Check the logs for structured telemetry output including `alert_id`, `num_turns`, `cost_usd`, and `session_id`. If Claude CLI or Grafana are not reachable, the endpoint returns HTTP 500 and logs the error with the correlation `alert_id` — this signals Alertmanager to retry the batch. Multiple firing alerts within a single webhook are investigated concurrently.

## Unit Tests

```bash
just test    # or: cargo test
```

## Development Checks

```bash
just check   # fmt + strict clippy (all targets, all features)
just test    # run test suite
just fmt     # auto-format code
```

Or without `just`:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## CI

Every push and PR to `main` runs the same checks via GitHub Actions (`.github/workflows/ci.yml`):

1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test`
4. `nix build` (CI only — the flake targets Linux; use `just pre-release` locally)
