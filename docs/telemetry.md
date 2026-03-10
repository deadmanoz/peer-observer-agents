# Telemetry

## Log Correlation

Each alert is assigned a stable correlation ID in the format `alertname:host:startsAt` (e.g., `PeerObserverBlockStale:bitcoin-03:20250615T120000Z`). This `alert_id` is logged through all processing stages — receive, Claude call, duplicate-skip, post/skip, and failure — so a single alert can be traced end-to-end via `grep` or structured log queries.

## Structured Logging

Each investigation logs structured fields via `tracing`:

```
INFO peer_observer_agent: claude investigation completed
  alert_id="PeerObserverAddressMessageSpike:bitcoin-01:20250615T120000Z"
  num_turns=12
  duration_ms=58000
  duration_api_ms=45000
  cost_usd=0.04
  input_tokens=18000
  output_tokens=2500
  stop_reason="end_turn"
  is_error=false
  session_id="abc123"
```

### Fields

| Field | Description |
|-------|-------------|
| `alert_id` | Stable correlation ID (`alertname:host:startsAt`) |
| `num_turns` | Number of Claude conversation turns in the investigation |
| `duration_ms` | Total wall-clock time for the Claude CLI process |
| `duration_api_ms` | Time spent in API calls (subset of `duration_ms`) |
| `cost_usd` | Estimated cost of the investigation |
| `input_tokens` | Total input tokens consumed |
| `output_tokens` | Total output tokens generated |
| `stop_reason` | Why Claude stopped (`end_turn`, `max_tokens`, etc.) |
| `is_error` | Whether Claude returned an error response |
| `session_id` | Claude session ID for debugging |

## Prior Context

The agent fetches recent AI annotations from Grafana (last 1 hour, same host) and includes them in the investigation prompt. This is scoped by **host only** — all `ai-annotation` tags from the same host are included regardless of alert type. This catches cascading failures (e.g., a restart triggering both connection drops and block stale alerts) at the cost of occasional irrelevant context.

## Log File

When `ANNOTATION_AGENT_LOG_FILE` is set, each successful annotation is appended as a plain-text line:

```
[2025-06-15 12:00:00 UTC] PeerObserverBlockStale on bitcoin-03 — No new block in 1 hour, likely slow block interval...
```
