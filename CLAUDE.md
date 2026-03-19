# peer-observer-agents

AI agents for peer-observer Bitcoin P2P network monitoring infrastructure.

## Architecture

Single Rust binary that receives Alertmanager webhooks, dispatches Claude Code CLI with Prometheus MCP tools to investigate alerts, and posts results as Grafana annotations.

```
Alertmanager → POST /webhook → peer-observer-agent → [optional] Bitcoin Core RPC (WireGuard)
                                        │                     └──▶ Pre-fetched node data in prompt
                                        ├──▶ [optional] Parca API (CPU profiling)
                                        │         └──▶ Top CPU functions in prompt
                                        ├──▶ [optional] debug.log (WireGuard nginx)
                                        │         └──▶ Filtered log lines in prompt
                                        ├──▶ Claude CLI (--mcp-config) → Prometheus MCP → Prometheus API
                                        └──▶ Grafana Annotations API
```

## Build & Test

```bash
just check                     # fmt + strict clippy
just test                      # Run test suite
just fmt                       # Auto-format code
just build-release             # Build release binary
just pre-release               # Quality gates (check + test)
just release patch             # Tag a release (patch/minor/major)
nix build                      # Build via flake (Linux/CI)
```

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `src/main.rs` | Bootstrap only: tracing init → config load → server run |
| `src/config.rs` | Env var parsing (`ANNOTATION_AGENT_*`), `RuntimeConfig` + `AppState` construction |
| `src/server.rs` | HTTP router assembly, webhook/healthz/version handlers, `axum::serve` |
| `src/processor.rs` | `process_alert` orchestrator, annotation result handling, log appending |
| `src/alerts/` | Typed alert catalog (`KnownAlert` enum), `AlertSpec` with nested per-source specs |
| `src/context.rs` | Neutral `ContextSection` transport — extractors produce, prompt renders |
| `src/sanitization.rs` | Shared sanitization helpers (XML escaping, host/control-char stripping) |
| `src/prompt/` | Investigation prompt generation, PromQL sanitization, fast-path |
| `src/prompt/instructions/` | Per-family investigation steps (connections, performance, chain, etc.) |
| `src/investigation/` | `collector.rs` (context fetching) + `runner.rs` (Claude CLI subprocess) |
| `src/viewer/` | `/logs` and `/api/logs` — annotation log viewer |
| `src/rpc/` | Bitcoin Core RPC client and response filtering |
| `src/parca/` | Parca profiling API client, CPU profile pre-fetch for performance alerts |
| `src/debug_logs/` | Debug log HTTP client, time/category filtering, pre-fetch for alert investigations |
| `src/profiles/` | Peer profiles: SQLite DB, poller, `/peers` API and viewer |
| `src/annotation.rs` | Structured annotation types, HTML rendering, peer-intervention policy guard |
| `src/grafana.rs` | Grafana annotation API |
| `src/cooldown.rs` | Cooldown suppression |
| `src/correlation.rs` | Alert ID generation, idempotency tags |

## Configuration

All config via `ANNOTATION_AGENT_*` env vars. See [docs/deployment.md](docs/deployment.md#configuration-reference) for the full table.

## Endpoints

- `POST /webhook` — Alertmanager webhook receiver
- `GET /healthz` — Health check
- `GET /logs`, `GET /api/logs` — Annotation log viewer (requires `LOG_FILE` + `VIEWER_AUTH_TOKEN`)
- `GET /peers`, `GET /api/peers`, `GET /api/peers/{id}`, `GET /api/peers/stats` — Peer profiles (requires `PROFILES_DB` + `VIEWER_AUTH_TOKEN`)

## Log Correlation

Each alert gets a stable `alert_id` derived from `(alertname, host, threadname, startsAt)`, logged through all processing stages. See [docs/telemetry.md](docs/telemetry.md) for format details.

## Documentation

### `docs/` (committed)

- `deployment.md` — Configuration reference, security assumptions, MCP config
- `profiles.md` — Peer profiles: identity strategy, SQLite schema, polling, API
- `telemetry.md` — Log correlation format, structured logging fields
- `testing.md` — Smoke tests, unit tests, CI
- `releasing.md` — Release workflow and versioning

### `agent_docs/` (local, gitignored)

Additional reference docs for Claude sessions: deployment runbook, design decisions, module reference. Check this directory when you need operational or architectural context beyond what `docs/` covers.

### Docs Refresh Rule

When doing a docs update sweep, review all docs against the current source code. **Never store a commit hash reference that will be invalidated by amending the same commit** — this creates a circular dependency.
