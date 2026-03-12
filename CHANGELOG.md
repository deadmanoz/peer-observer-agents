# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- Sanitize all untrusted fields (labels, annotations, prior context) in investigation prompts with XML data boundary tags to prevent prompt injection
- Process multiple firing alerts concurrently within a webhook via `JoinSet` (previously serial), bounded by `ANNOTATION_AGENT_MAX_CONCURRENT` (default 4)
- Kill entire Claude process group on timeout via `setsid` + `killpg`, ensuring MCP subprocesses are also cleaned up
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

[Unreleased]: https://github.com/peer-observer/peer-observer-agents/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/peer-observer/peer-observer-agents/releases/tag/v0.2.0
