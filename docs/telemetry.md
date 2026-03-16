# Telemetry

## Log Correlation

Each alert is assigned a stable correlation ID derived from `(alertname, host, threadname, startsAt)`. For alerts without a `threadname` label, the format is `alertname:host:startsAt` (e.g., `PeerObserverBlockStale:bitcoin-03:20250615T120000Z`). For thread-aware alerts, it includes the thread: `alertname:host:threadname:startsAt` (e.g., `PeerObserverThreadSaturation:bitcoin-03:b-msghand:20250615T120000Z`). This `alert_id` is logged through all processing stages — receive, Claude call, duplicate-skip, post/skip, and failure — so a single alert can be traced end-to-end via `grep` or structured log queries.

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
| `alert_id` | Stable correlation ID (`alertname:host:startsAt` or `alertname:host:threadname:startsAt`) |
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

When `ANNOTATION_AGENT_LOG_FILE` is set, each successful annotation is appended as a single JSONL line (one JSON object per line):

```json
{"v":1,"logged_at":"2025-06-15T12:05:23Z","alert_starts_at":"2025-06-15T12:00:00Z","alert_id":"PeerObserverBlockStale:bitcoin-03:20250615T120000Z","alertname":"PeerObserverBlockStale","host":"bitcoin-03","threadname":"","entry_kind":"structured","verdict":"benign","summary":"Slow block interval, all hosts at same height.","cause":"Normal mining variance.","scope":"multi-host","evidence":["last_block: 47 min ago","all hosts synced at 890421"],"telemetry":{"num_turns":12,"duration_ms":58000,"duration_api_ms":45000,"cost_usd":0.04,"input_tokens":18000,"output_tokens":2500,"stop_reason":"end_turn","session_id":"abc-123"}}
```

Each entry has two timestamps: `logged_at` (wall-clock time when the entry was written, used for ordering) and `alert_starts_at` (from Alertmanager). The `entry_kind` field distinguishes `structured` entries (with verdict, summary, cause, scope, evidence) from `raw_fallback` entries (with `raw_text` containing unparseable Claude output).

**Breaking change (v0.5.0)**: The log format changed from pipe-delimited plaintext to JSONL. Existing log files must be deleted or rotated before upgrade.

## Cooldown Suppression

When a retrigger of the same `(alertname, host, threadname)` is suppressed by the cooldown window, one of two log lines is emitted at INFO level:

**In-flight suppression** (investigation for this alert has been claimed and is either queued for a concurrency slot or actively running):
```
INFO peer_observer_agent: skipping: investigation already in flight
  alert_id="PeerObserverAddressMessageSpike:bitcoin-01:20250615T183100Z"
```

**Recently-completed suppression** (investigation completed within the cooldown window):
```
INFO peer_observer_agent: skipping: recent investigation within cooldown window
  alert_id="PeerObserverAddressMessageSpike:bitcoin-01:20250615T194500Z"
  cooldown_secs=1800
  elapsed_secs=720
```

| Field | Description |
|-------|-------------|
| `alert_id` | Stable correlation ID of the suppressed alert |
| `cooldown_secs` | Configured cooldown window (seconds) |
| `elapsed_secs` | Time since the last successful investigation completed |
