# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Introduce typed alert catalog (`src/alerts/`): `define_alerts!` macro generates `KnownAlert` enum with `parse()`, `as_str()`, `kind()`, and `ALL`. Each variant has a compiler-enforced `spec()` returning `AlertSpec` with nested `RpcSpec`, `DebugLogSpec`, `ProfilingSpec`, and `FastPathSpec`. Adding a new alert requires one catalog entry and one instruction dispatcher arm — both enforced at compile time.
- Split investigation instructions into per-family modules (`src/prompt/instructions/{connections,p2p_messages,security,performance,chain,mempool,infra,meta}.rs`) dispatched via exhaustive match on `KnownAlert`.
- Migrate all per-alert routing functions (`rpc_methods_for_alert`, `peer_info_fields_for_alert`, `per_msg_keys_for_alert`, `should_fetch_profile`, `log_filter_for_alert`, `fast_path_spec`) to delegate to `KnownAlert::spec()`. Match-on-string routing eliminated.
- Rewrite grouped alert-subset tests to derive from `KnownAlert::ALL` with relational invariants instead of hand-maintained alert lists.
- Extract `src/config.rs` (env var parsing, `RuntimeConfig`), `src/server.rs` (router, handlers, serve), and `src/processor.rs` (`process_alert`, annotation result handling) from `main.rs`. Main becomes ~30 lines of bootstrap: tracing init → config load → server run.
- Introduce neutral `ContextSection` transport (`src/context.rs`): extractors (RPC, Parca, debug log) return `Option<ContextSection>` instead of `(String, Option<DateTime>)`. Prompt builder renders sections via a generic loop instead of three hardcoded blocks. Move shared sanitization helpers (`sanitize`, `strip_control_chars`, `sanitize_host_for_prompt`) to `src/sanitization.rs` so the context module has no dependency on the prompt layer.
- Split `investigation.rs` into `investigation/{mod,collector,runner}.rs`: context collection separated from Claude CLI subprocess management.
- Extract `VIEWER_CSP` constant from duplicated inline strings in viewer and profiles HTML handlers.
- Consolidate Grafana API request helpers (`grafana_get`/`grafana_post`) and shared prompt test fixtures (`AlertContext::test_default`).

## [0.6.1] - 2026-03-18

### Added

- Track `software_version` (peer-observer-agent crate version) in annotation log entries and display in both log viewer and peer profiles viewer UIs

### Fixed

- Add peer-intervention policy guard to investigation prompts — Claude must recommend operator action rather than executing changes directly
- Remove priming language from investigation instructions that could bias Claude toward specific conclusions

## [0.6.0] - 2026-03-17

### Added

- Add peer profiles component: continuously polls `getpeerinfo` from configured Bitcoin Core nodes and builds persistent per-peer profiles in SQLite. Tracks peer identities, connection observations, software version changes, and presence windows across hosts. New `/peers` viewer and `/api/peers/*` API endpoints with bearer auth. Configurable via `ANNOTATION_AGENT_PROFILES_DB`, `ANNOTATION_AGENT_PROFILES_POLL_INTERVAL_SECS`, and `ANNOTATION_AGENT_PROFILES_RETENTION_DAYS`.
- Add date range filter and browser timezone toggle to log viewer — `logged_after`/`logged_before` query parameters with RFC 3339 support

### Changed

- Modularize codebase: split monolithic `main.rs` (1745 lines), `prompt.rs` (1579 lines), `viewer.rs` (1630 lines), and `rpc.rs` (853 lines) into focused modules — no file exceeds 970 lines, most are under 400. Shared DTOs in `types.rs`, `AppState` in `state.rs`, Grafana concerns in `grafana.rs`, Claude subprocess in `investigation.rs`, cooldown in `cooldown.rs`, correlation in `correlation.rs`. Prompt, viewer, and RPC split into directory modules with clear submodule boundaries.

### Fixed

- Fix peer profiles `services` field names not sorted consistently across observations, causing spurious software change entries
- Fix orphaned peers remaining in database after all their observations are pruned by retention
- Release mutex between prune batches to reduce lock contention during retention cleanup

## [0.5.3] - 2026-03-16

### Fixed

- Fix log viewer filters crashing with `TypeError: Cannot set properties of null` — the `#status` element was destroyed by `renderTable()` via `innerHTML = ''`, causing subsequent `loadLogs()` calls to fail silently before the fetch even ran

## [0.5.2] - 2026-03-16

### Fixed

- Fix log viewer stale-response race condition — initial unfiltered response could overwrite filtered results when user changed filters before initial load completed
- Fix filter dropdowns losing options when applying a filter — known values now accumulate across responses instead of being rebuilt from each filtered response

## [0.5.1] - 2026-03-16

### Added

- Auto-detect reverse proxy auth in viewer — when deployed behind nginx with injected Authorization headers, the viewer skips the token input and loads data immediately

### Fixed

- Flush JSONL writes explicitly to prevent data loss on async file handle drop

## [0.5.0] - 2026-03-16

### Added

- Annotation log viewer: `/logs` HTML page and `/api/logs` JSON API for browsing investigation history with filtering, pagination, and search
- JSONL log format replacing the previous pipe-delimited plaintext format, with dual timestamps (`logged_at` for ordering, `alert_starts_at` for context), full structured annotation fields, and Claude telemetry (cost, tokens, turns, duration)
- `ANNOTATION_AGENT_VIEWER_AUTH_TOKEN` env var — viewer endpoints are only registered when both this and `ANNOTATION_AGENT_LOG_FILE` are set
- Bearer token authentication on `/api/logs`
- Server-side filtering by verdict, host, alertname, and threadname with composite cursor pagination

### Changed

- **BREAKING**: `ANNOTATION_AGENT_LOG_FILE` now writes JSONL format instead of pipe-delimited plaintext. Existing log files must be deleted or rotated before upgrade — the new format is incompatible with the old one.
- Removed `render_annotation_plaintext` and `sanitize_log_field` (superseded by JSONL serialization)

## [0.4.0] - 2026-03-16

### Added

- Thread-level CPU saturation detection via `PeerObserverThreadSaturation` alert support with per-thread investigation instructions
- `threadname` label propagation through the alert identity pipeline (cooldown, idempotency, prompt context) — concurrent thread saturations on the same host are tracked independently
- RPC pre-fetch of `getblockchaininfo` for CPU/thread alerts to enable IBD correlation
- Updated `PeerObserverHighCPU` investigation to check per-thread CPU metrics (`namedprocess_namegroup_thread_cpu_seconds_total`) and reference pre-fetched RPC data
- Cooldown suppression for retriggers of the same `(alertname, host, threadname)` within a configurable window (`ANNOTATION_AGENT_COOLDOWN_SECS`, default 30 minutes). Uses an RAII guard for panic-safe state management. Failed investigations clear the cooldown so Alertmanager retries are not suppressed.

## [0.3.0] - 2026-03-12

### Added

- Pre-fetch Bitcoin Core RPC data (getpeerinfo, getblockchaininfo, getmempoolinfo, etc.) over WireGuard before Claude investigation, giving the agent per-peer IP attribution and node state context
- Per-alert-type RPC method mapping with filtered responses to minimize token cost
- `<rpc-data>` prompt section with sanitization against prompt injection
- Configurable via `ANNOTATION_AGENT_RPC_HOSTS`, `ANNOTATION_AGENT_RPC_USER`, `ANNOTATION_AGENT_RPC_PASSWORD`, `ANNOTATION_AGENT_RPC_PORT`
- Fail-fast startup validation for partial/malformed RPC configuration
- Graceful degradation when RPC is unreachable (investigation continues with Prometheus only)
- Structured annotation output: Claude outputs JSON with `verdict`, `action`, `summary`, `cause`, `scope`, and `evidence` fields, parsed and validated in Rust
- Three-level verdict taxonomy (`benign`/`investigate`/`action_required`) for instant operator triage
- HTML-formatted Grafana annotations with bold field labels for scannable tooltip rendering
- Verdict tag added to Grafana annotation tags for dashboard filtering (not part of idempotency key)
- Graceful fallback: raw text posted when Claude output fails structured JSON parsing
- HTML stripping for prior annotation context injected into investigation prompts
- Pipe-delimited single-line structured log format with field sanitization
- Fast-path self-resolution check for anomaly-band alerts: Claude checks current level vs band before full investigation and short-circuits to a brief benign annotation when the anomaly has already resolved

### Changed

- Sanitize all untrusted fields (labels, annotations, prior context) in investigation prompts via XML entity escaping; XML boundary tags (`<alert-data>`, `<rpc-data>`, `<alert-context-data>`) delimit data sections to reinforce the instruction/data boundary
- Process multiple firing alerts concurrently within a webhook via `JoinSet`; Claude invocations bounded by `ANNOTATION_AGENT_MAX_CONCURRENT` (default 4) via a `Semaphore`
- Kill entire Claude process group on timeout via `setsid` + negative-PID `kill`, ensuring MCP subprocesses are also cleaned up
- Drop Darwin from Nix flake `supportedSystems` (deployment target is NixOS/Linux only)
- Make release script portable (replace BSD `sed -i ''` with temp-file pattern)

## [0.2.0] - 2026-03-10

### Added

- Alertmanager webhook receiver (`POST /webhook`) that dispatches Claude Code CLI for autonomous alert investigation
- Grafana annotation posting with structured investigation results
- Per-alert and per-category investigation prompt generation (`src/prompt.rs`)
- Prior context scoping — fetches recent annotations from same host for correlation
- Idempotency — deduplicates alerts by `alert_id` to prevent redundant investigations
- Health check endpoint (`GET /healthz`)
- Structured logging with `alert_id` for end-to-end log correlation
- Claude CLI telemetry capture (num_turns, cost, tokens, duration, session_id)
- Nix flake with build, fmt, clippy, and test checks
- CI workflow: fmt, clippy, test, nix build
- Comprehensive documentation (deployment, testing, telemetry)

[Unreleased]: https://github.com/peer-observer/peer-observer-agents/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/peer-observer/peer-observer-agents/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/peer-observer/peer-observer-agents/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/peer-observer/peer-observer-agents/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/peer-observer/peer-observer-agents/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/peer-observer/peer-observer-agents/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/peer-observer/peer-observer-agents/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/peer-observer/peer-observer-agents/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/peer-observer/peer-observer-agents/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/peer-observer/peer-observer-agents/releases/tag/v0.2.0
