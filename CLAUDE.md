# peer-observer-agents

AI agents for peer-observer Bitcoin P2P network monitoring infrastructure.

## Architecture

Single Rust binary (`peer-observer-agent`) that receives Alertmanager webhooks and dispatches Claude Code CLI with Prometheus MCP tools to investigate alerts autonomously. Investigation results are posted as Grafana annotations.

```
Alertmanager → POST /webhook → peer-observer-agent → [optional] Bitcoin Core RPC (WireGuard)
                                        │                     └──▶ Pre-fetched node data in prompt
                                        ├──▶ Claude CLI (--mcp-config) → Prometheus MCP → Prometheus API
                                        └──▶ Grafana Annotations API
```

## Build & Test

```bash
just check                     # fmt + strict clippy
just test                      # Run test suite
just fmt                       # Auto-format code
just build-release             # Build release binary
just version                   # Show current version
just pre-release               # Quality gates (check + test)
just release patch             # Tag a release (patch/minor/major)
nix build                      # Build via flake (Linux/CI)
```

## Project Structure

- `src/main.rs` — HTTP server, webhook handler, Claude CLI invocation, Grafana annotation posting, idempotency, telemetry
- `src/annotation.rs` — Structured annotation types (Verdict, StructuredAnnotation), JSON parsing/validation, HTML/plaintext rendering, log field sanitization, HTML stripping
- `src/prompt.rs` — Alert context extraction and investigation prompt generation (per-alert and per-category instructions)
- `src/rpc.rs` — Bitcoin Core JSON-RPC client for pre-fetching node data (getpeerinfo, getblockchaininfo, etc.) over WireGuard
- `Cargo.toml` — Dependencies
- `flake.nix` — Nix build definition with checks (package, fmt, clippy, test)
- `.github/workflows/ci.yml` — CI: fmt, clippy, test, nix build
- `docs/testing.md` — Smoke tests, unit tests, CI
- `docs/deployment.md` — NixOS, security assumptions, MCP config, health endpoint
- `docs/telemetry.md` — Log correlation, structured logging fields, prior context scoping
- `CHANGELOG.md` — Release history ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format)
- `scripts/release.sh` — Release pipeline (version bump, quality gates, commit, tag)
- `docs/releasing.md` — Full release workflow documentation

### Docs Refresh Rule

When doing a docs update sweep, review all docs against the current source code. **Never store a commit hash reference that will be invalidated by amending the same commit** — this creates a circular dependency (the hash changes when you amend, so the stored hash is always stale).

## Key Dependencies

- `axum` — HTTP server for Alertmanager webhooks
- `reqwest` — HTTP client for Grafana API and Bitcoin Core RPC
- `tokio` — Async runtime + process spawning for Claude CLI
- `serde` / `serde_json` — Alertmanager payload deserialization, Claude JSON output parsing
- `anyhow` — Error handling and context propagation
- `chrono` — Timestamp handling
- `tracing` / `tracing-subscriber` — Structured logging with telemetry fields and env-filter
- `libc` — Process group management (`setsid`/`killpg`) for subprocess cleanup on timeout
- `futures-util` — Concurrent RPC fan-out (`join_all`)

## Configuration

All config via environment variables prefixed `ANNOTATION_AGENT_*`. See [docs/deployment.md](docs/deployment.md#configuration-reference) for the full table.

Required: `ANNOTATION_AGENT_GRAFANA_API_KEY`, `ANNOTATION_AGENT_MCP_CONFIG`

Optional tuning: `ANNOTATION_AGENT_HTTP_TIMEOUT_SECS` (default 30), `ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS` (default 600), `ANNOTATION_AGENT_MAX_CONCURRENT` (default 4), `ANNOTATION_AGENT_COOLDOWN_SECS` (default 1800, 0 = disabled)

Optional RPC pre-fetch: `ANNOTATION_AGENT_RPC_HOSTS` (JSON host→IP map), `ANNOTATION_AGENT_RPC_PASSWORD` (required if RPC_HOSTS set), `ANNOTATION_AGENT_RPC_USER` (default `rpc-extractor`), `ANNOTATION_AGENT_RPC_PORT` (default 9000)

## Endpoints

- `POST /webhook` — Alertmanager webhook receiver (concurrent per-alert investigation; returns 200/500)
- `GET /healthz` — Health check (returns 200 OK)

## Log Correlation

Each alert gets a stable `alert_id` in the format `alertname:host:startsAt` (e.g., `PeerObserverBlockStale:bitcoin-03:20250615T120000Z`). This ID is logged through all processing stages for end-to-end tracing.

## Prior Context Scoping

Prior annotation context is scoped by **host only** — the agent fetches all `ai-annotation` annotations from the same host within the last hour. This means a noisy host may provide context from unrelated alert types. This is intentional: host-level correlation catches cascading failures (e.g., a restart triggering both connection drops and block stale alerts) at the cost of occasional irrelevant context.

## Deployment

This crate can be added as a flake input to [infra-library](https://github.com/peer-observer/infra-library) or any NixOS configuration. Consumers must explicitly add this repo as a flake input. The NixOS module at `modules/web/annotation-agent.nix` in infra-library handles:
- systemd service configuration
- MCP config JSON generation (pointing uvx at prometheus-mcp-server)
- Secret management via agenix (Grafana API key)
- Running as the user with Claude CLI credentials

## Design Decisions

- **Claude CLI over API**: Uses Claude Code CLI (`claude -p`) rather than the Anthropic API directly. This means the service user needs `~/.claude/` credentials but avoids managing API keys.
- **MCP for Prometheus**: Rather than pre-fetching hardcoded PromQL queries, Claude has direct access to Prometheus via MCP tools and drives the investigation autonomously.
- **RPC pre-fetch for Bitcoin Core**: When configured, the agent pre-fetches relevant Bitcoin Core RPC data (e.g., `getpeerinfo` for connection alerts, `getblockchaininfo` for chain health alerts) and injects filtered results into the prompt. This gives Claude per-peer IP attribution that Prometheus aggregate metrics cannot provide. RPC responses are filtered per alert type to minimize token cost (~26KB worst case for 125 peers). Graceful degradation: if RPC is unreachable, investigation proceeds with Prometheus only.
- **JSON output format**: Uses `--output-format json` to capture structured telemetry (num_turns, cost, tokens, duration, session_id).
- **Unbounded turns**: No `--max-turns` limit — Claude investigates until it has a conclusion. The `is_error` and "Reached max turns" checks prevent posting error text as annotations.
- **Model**: Defaults to `claude-sonnet-4-6` for fast, cost-effective investigations. Configurable via `ANNOTATION_AGENT_CLAUDE_MODEL`.
- **Structured annotation output**: Claude outputs a JSON object with `verdict`, `action`, `summary`, `cause`, `scope`, and `evidence` fields. Rust validates the schema (enum verdict, non-empty fields, verdict-action consistency) and renders HTML for Grafana tooltips. Graceful fallback: if parsing fails, raw text is posted as-is. The verdict (`benign`/`investigate`/`action_required`) is added as a Grafana tag for dashboard filtering but is NOT part of the idempotency key to prevent duplicate annotations during retries.
- **Grafana HTML annotations**: Annotation tooltips render HTML via DOMPurify sanitization (verified against grafana/grafana AnnotationTooltip2.tsx, 2026-03). Only safe tags used: `<b>`, `<br>`, `&bull;`. Prior annotations have HTML stripped before injection into new investigation prompts.
- **Cooldown suppression**: Uses `(alertname, host)` as the coalescing key, intentionally ignoring `startsAt`. Within the cooldown window, all retriggers for the same alert type on the same host are treated as the same incident. Failed investigations clear the cooldown state so Alertmanager retries are not suppressed. State is in-process only (does not survive restarts).
