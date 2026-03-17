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

### Core modules
- `src/main.rs` — HTTP server startup, webhook handler, `process_alert` orchestrator, `append_log` glue
- `src/types.rs` — Shared DTOs: `ClaudeOutput`, `AlertmanagerPayload`, `Alert`
- `src/state.rs` — `AppState` struct (HTTP client, semaphore, cooldown map, config)
- `src/cooldown.rs` — Cooldown suppression: `CooldownState`, `CooldownGuard`, `try_claim_cooldown`
- `src/correlation.rs` — `AlertId` (stable log correlation), `build_idempotency_tags`, `build_annotation_tags`
- `src/grafana.rs` — All Grafana API: `post_grafana_annotation`, `annotation_exists`, `fetch_recent_annotations`, `format_prior_context`
- `src/investigation.rs` — Claude CLI subprocess: `call_claude`, `parse_claude_output`
- `src/annotation.rs` — Structured annotation types (Verdict, StructuredAnnotation), JSON parsing/validation, HTML rendering, HTML stripping

### Prompt generation (`src/prompt/`)
- `mod.rs` — `build_investigation_prompt` orchestrator, re-exports `AlertContext`, `sanitize`, `strip_control_chars`
- `alert_context.rs` — `AlertContext` struct and `from_alert` constructor
- `sanitization.rs` — `sanitize`, `strip_control_chars`, `sanitize_promql_label`, `sanitize_host_for_prompt`
- `fast_path.rs` — `BandDirection`, `FastPathSpec`, anomaly-band fast-path classification
- `instructions.rs` — Per-alert and per-category investigation instructions with PromQL templates

### Log viewer (`src/viewer/`)
- `mod.rs` — Re-exports
- `log_schema.rs` — `EntryKind`, `Telemetry`, `LogEntry` JSONL types
- `log_file.rs` — `append_jsonl_log` async file writer
- `cursor.rs` — Cursor pagination (base64 encode/decode, `HeapEntry` for bounded top-N)
- `api.rs` — `/api/logs` handler with server-side filters and cursor pagination
- `html.rs` — `/logs` HTML page handler

### RPC client (`src/rpc/`)
- `mod.rs` — `RpcClient`, `rpc_methods_for_alert`, `host_names()`, `getpeerinfo_raw()`, JSON-RPC DTOs
- `filter.rs` — `filter_rpc_response`, `filter_peer_info`, per-alert field allowlists

### Peer profiles (`src/profiles/`)
- `mod.rs` — Re-exports, `ProfileDb`
- `db.rs` — `ProfileDb::open()`, schema DDL, write ops (upsert/insert/presence windows/pruning), read ops (list/detail/stats)
- `models.rs` — `Peer`, `Observation`, `SoftwareChange`, `PresenceWindow`, `PeerSummary`, `PeerProfile`, `ProfileStats`
- `identity.rs` — `bare_address()`, `classify_network()`, `Network` enum, `PeerIdentity`
- `poller.rs` — Background `tokio::spawn` task polling `getpeerinfo` per host, upserting peers/observations/software changes, presence window tracking, retention pruning
- `api.rs` — `/api/peers`, `/api/peers/{id}`, `/api/peers/stats` handlers, `/peers` HTML page handler
- `viewer.html` — Self-contained HTML/CSS/JS peer profiles viewer (embedded via `include_str!`). Peer list with filters, detail view with software timeline and presence windows. XSS-safe (`textContent` only).

### Other files
- `src/viewer.html` — Self-contained HTML/CSS/JS log viewer (embedded via `include_str!`). Renders annotation history with verdict badges, expandable rows, filters, client-side search. All user content rendered via `textContent` (no `innerHTML`) for XSS safety.
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
- `rusqlite` — SQLite database for peer profiles (bundled `libsqlite3`)

## Configuration

All config via environment variables prefixed `ANNOTATION_AGENT_*`. See [docs/deployment.md](docs/deployment.md#configuration-reference) for the full table.

Required: `ANNOTATION_AGENT_GRAFANA_API_KEY`, `ANNOTATION_AGENT_MCP_CONFIG`

Optional tuning: `ANNOTATION_AGENT_HTTP_TIMEOUT_SECS` (default 30), `ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS` (default 600), `ANNOTATION_AGENT_MAX_CONCURRENT` (default 4), `ANNOTATION_AGENT_COOLDOWN_SECS` (default 1800, 0 = disabled)

Optional viewer: `ANNOTATION_AGENT_VIEWER_AUTH_TOKEN` (Bearer token for `/logs` and `/api/logs`; viewer routes only registered when both this and `LOG_FILE` are set)

Optional RPC pre-fetch: `ANNOTATION_AGENT_RPC_HOSTS` (JSON host→IP map), `ANNOTATION_AGENT_RPC_PASSWORD` (required if RPC_HOSTS set), `ANNOTATION_AGENT_RPC_USER` (default `rpc-extractor`), `ANNOTATION_AGENT_RPC_PORT` (default 9000)

Optional peer profiles: `ANNOTATION_AGENT_PROFILES_DB` (SQLite file path; unset = profiles disabled), `ANNOTATION_AGENT_PROFILES_POLL_INTERVAL_SECS` (default 300), `ANNOTATION_AGENT_PROFILES_RETENTION_DAYS` (default 90). Activation: `PROFILES_DB` + `RPC_HOSTS` → poller runs; `PROFILES_DB` + `VIEWER_AUTH_TOKEN` → `/peers` and `/api/peers/*` routes registered; `PROFILES_DB` without `RPC_HOSTS` → DB opened but idle (warning logged)

## Endpoints

- `POST /webhook` — Alertmanager webhook receiver (concurrent per-alert investigation; returns 200/500)
- `GET /healthz` — Health check (returns 200 OK)
- `GET /logs` — Annotation log viewer HTML page (only registered when both `LOG_FILE` and `VIEWER_AUTH_TOKEN` are set)
- `GET /api/logs` — JSONL API for log entries with server-side filtering and cursor pagination (requires `Authorization: Bearer` token)
- `GET /peers` — Peer profiles viewer HTML page (only registered when both `PROFILES_DB` and `VIEWER_AUTH_TOKEN` are set)
- `GET /api/peers` — Peer summaries JSON API with network/host filters and pagination (requires Bearer token)
- `GET /api/peers/{id}` — Full peer profile by peer_id (requires Bearer token)
- `GET /api/peers/stats` — Aggregate stats: total peers, per-network counts, observation count, host statuses with staleness (requires Bearer token)

## Log Correlation

Each alert gets a stable `alert_id` derived from `(alertname, host, threadname, startsAt)`. For alerts without a `threadname` label, the format is `alertname:host:startsAt` (e.g., `PeerObserverBlockStale:bitcoin-03:20250615T120000Z`). For thread-aware alerts, it includes the thread: `alertname:host:threadname:startsAt` (e.g., `PeerObserverThreadSaturation:bitcoin-03:b-msghand:20250615T120000Z`). This ID is logged through all processing stages for end-to-end tracing.

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
- **JSON output format**: Uses `--output-format json` to capture structured telemetry (num_turns, cost_usd, input_tokens, output_tokens, duration_ms, duration_api_ms, stop_reason, is_error, session_id).
- **Unbounded turns**: No `--max-turns` limit — Claude investigates until it has a conclusion. The `is_error` and "Reached max turns" checks prevent posting error text as annotations.
- **Model**: Defaults to `claude-sonnet-4-6` for fast, cost-effective investigations. Configurable via `ANNOTATION_AGENT_CLAUDE_MODEL`.
- **Structured annotation output**: Claude outputs a JSON object with `verdict`, `action`, `summary`, `cause`, `scope`, and `evidence` fields. Rust validates the schema (enum verdict, non-empty fields, verdict-action consistency) and renders HTML for Grafana tooltips. Graceful fallback: if parsing fails, raw text is posted as-is. The verdict (`benign`/`investigate`/`action_required`) is added as a Grafana tag for dashboard filtering but is NOT part of the idempotency key to prevent duplicate annotations during retries.
- **Grafana HTML annotations**: Annotation tooltips render HTML via DOMPurify sanitization (verified against grafana/grafana AnnotationTooltip2.tsx, 2026-03). Only safe tags used: `<b>`, `<br>`, `&bull;`. Prior annotations have HTML stripped before injection into new investigation prompts.
- **Peer profiles in SQLite**: Uses `rusqlite` with bundled `libsqlite3` and WAL mode. Single `Arc<Mutex<Connection>>` accessed via `spawn_blocking` — acceptable for v1 since the poller writes every 5 minutes and API reads are lightweight. `PRAGMA auto_vacuum = INCREMENTAL` for space reclamation after retention deletes. Schema versioned via `PRAGMA user_version`.
- **Presence windows vs sessions**: Tracks identity-level presence (bare IP observed on host), not connection-level sessions. A single peer with both inbound and outbound connections produces one presence window. This is honest about what 5-minute polling can actually tell us.
- **Peer identity keying**: Clearnet peers keyed on `(bare_ip, network)`. Tor/I2P keyed on `(full_address, network)`, accepting fragmentation across address rotations for v1.
- **Software change detection**: Only inserts `software_history` rows when subversion/version/services actually change, avoiding duplicating rarely-changing data across ~72K observation rows/day.
- **Stale host detection**: Host freshness computed at read time (`stale` when `now - last_polled_at > 2 × poll_interval`). Stale window recovery runs at poll time using the poll timestamp (not wall clock) as reference.
- **Cooldown suppression**: Uses `(alertname, host, threadname)` as the coalescing key, intentionally ignoring `startsAt`. Within the cooldown window, all retriggers for the same alert type on the same host (and thread, for thread-aware alerts) are treated as the same incident. For alerts without a `threadname` label, the field defaults to empty string and doesn't change behavior. Failed investigations or Grafana post failures clear the cooldown state so Alertmanager retries are not suppressed. State is in-process only (does not survive restarts).
