# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
