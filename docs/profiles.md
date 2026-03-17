# Peer Profiles

The peer profiles component continuously polls `getpeerinfo` from configured Bitcoin Core nodes and builds persistent per-peer profiles in SQLite. This provides operators with historical visibility into peer connections, software version changes, and presence patterns across hosts.

## Activation

Peer profiles are controlled by three environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANNOTATION_AGENT_PROFILES_DB` | unset | SQLite file path. Unset = profiles disabled entirely. |
| `ANNOTATION_AGENT_PROFILES_POLL_INTERVAL_SECS` | `300` | Poll interval in seconds (default 5 minutes). |
| `ANNOTATION_AGENT_PROFILES_RETENTION_DAYS` | `90` | Observations, closed presence windows, and software history older than this are pruned. |

**Activation gating:**

- `PROFILES_DB` + `RPC_HOSTS` configured → poller starts, DB populated
- `PROFILES_DB` + `VIEWER_AUTH_TOKEN` configured → `/peers` page and `/api/peers/*` routes registered
- `PROFILES_DB` without `RPC_HOSTS` → DB opened but idle (warning logged). Useful for future data sources.
- `PROFILES_DB` unset → profiles completely disabled, no DB opened

## Peer Identity

Peers are identified by `(bare_address, network)`:

- **Clearnet (IPv4/IPv6/CJDNS):** Key on bare IP with port stripped. `1.2.3.4:8333` → `1.2.3.4`. IPv6 brackets also stripped: `[2001:db8::1]:8333` → `2001:db8::1`.
- **Tor/I2P:** Key on full overlay address with port stripped. `abc...xyz.onion:8333` → `abc...xyz.onion`.
- **Unknown networks:** Peers with unrecognised `network` field values (from future Bitcoin Core versions) are skipped to prevent identity collisions with known network types.

A single peer with both inbound and outbound connections produces one identity (deduplicated via `HashSet` in the poller).

## SQLite Schema

The database uses WAL mode, foreign keys, and `PRAGMA auto_vacuum = INCREMENTAL`. Schema version is tracked via `PRAGMA user_version` (currently version 1).

### Tables

**`peers`** — Unique peer identities.

| Column | Type | Description |
|--------|------|-------------|
| `peer_id` | INTEGER PK | Auto-increment identity |
| `address` | TEXT | Bare IP or overlay address |
| `network` | TEXT | `ipv4`, `ipv6`, `onion`, `i2p`, `cjdns` |
| `first_seen` | TEXT | ISO 8601 UTC, set on first observation |
| `last_seen` | TEXT | ISO 8601 UTC, updated every poll |

Unique constraint on `(address, network)`.

**`observations`** — Append-only connection snapshots from each poll cycle.

| Column | Type | Description |
|--------|------|-------------|
| `observation_id` | INTEGER PK | Auto-increment |
| `peer_id` | INTEGER FK | References `peers` |
| `host` | TEXT | Observing node (e.g., `bitcoin-03`) |
| `observed_at` | TEXT | ISO 8601 UTC poll timestamp |
| `addr_with_port` | TEXT | Full `addr:port` from `getpeerinfo` |
| `inbound` | INTEGER | 0/1 |
| `connection_type` | TEXT | e.g., `outbound-full-relay` |
| `conntime` | INTEGER | Unix epoch when connection was established |
| `starting_height` | INTEGER | Peer's chain height at connection time |
| `synced_headers` | INTEGER | Headers synced from this peer |
| `synced_blocks` | INTEGER | Blocks synced from this peer |

At 125 peers × 2 hosts × 288 polls/day (5-min interval) = ~72,000 rows/day. At 90-day retention: ~6.5M rows, ~1GB.

**`software_history`** — Change-detection only: one row per `(peer, host)` when subversion, version, or services changes.

| Column | Type | Description |
|--------|------|-------------|
| `history_id` | INTEGER PK | Auto-increment |
| `peer_id` | INTEGER FK | References `peers` |
| `host` | TEXT | Observing node |
| `observed_at` | TEXT | ISO 8601 UTC when change was detected |
| `subversion` | TEXT | e.g., `/Satoshi:27.0.0/` |
| `version` | INTEGER | Protocol version number |
| `services` | TEXT | Comma-separated service names (sorted), or hex fallback |

The `servicesnames` array from `getpeerinfo` is sorted before joining to prevent spurious change detection from non-deterministic ordering. Change detection uses explicit `QueryReturnedNoRows` handling — real DB errors are propagated rather than silently treated as "no previous record."

**`presence_windows`** — Tracks when a peer identity was continuously observed on a host.

| Column | Type | Description |
|--------|------|-------------|
| `window_id` | INTEGER PK | Auto-increment |
| `peer_id` | INTEGER FK | References `peers` |
| `host` | TEXT | Observing node |
| `first_observed` | TEXT | Poll timestamp when peer first appeared |
| `last_observed` | TEXT | Updated every poll while active; final value when closed |
| `closed` | INTEGER | 0 = active (peer still present), 1 = closed (peer disappeared) |

A unique partial index enforces at most one active window per `(peer_id, host)`. Presence is tracked at the identity level — a peer with multiple connections produces one window. With 5-minute polling, sub-interval connections are invisible and timestamps have poll-interval granularity.

**Stale window recovery:** On each poll, windows whose `last_observed` is older than 2× the poll interval (relative to the current poll timestamp) are closed. This handles crash recovery and extended RPC outages.

**`host_poll_status`** — Tracks last successful poll per host for freshness detection.

| Column | Type | Description |
|--------|------|-------------|
| `host` | TEXT PK | Observing node |
| `last_polled_at` | TEXT | ISO 8601 UTC, updated inside the same transaction as poll data |

## Polling

The background poller runs as a `tokio::spawn` task that shares the `RpcClient` from `AppState`. Each poll cycle:

1. For each configured host (independently — one failure doesn't block others):
   - Capture the timestamp *before* the RPC call (so it represents when the snapshot was requested)
   - Call `getpeerinfo_raw(host)` for unfiltered JSON
   - Parse all peer data outside the DB lock
   - Commit everything atomically in a single SQLite transaction via `process_host_poll()`:
     - Upsert peer identity, insert observation, detect software changes
     - Update presence windows (stale recovery → close disappeared → update continuing → insert new)
     - Update `host_poll_status` (freshness only recorded when data is committed)
2. After all hosts: run retention pruning (observations, closed presence windows, software history, orphaned peers)
3. Weekly: `PRAGMA incremental_vacuum` (adapts to actual poll interval)

Pruning releases the mutex between 10K-row batches so API reads can interleave during large prune operations. Orphaned peer pruning runs atomically in a single transaction (software history anchor cleanup + peer deletion) to prevent race conditions with concurrent polls.

## API Endpoints

All API endpoints require `Authorization: Bearer <VIEWER_AUTH_TOKEN>` and return `Cache-Control: no-store`.

### `GET /api/peers`

List peer summaries with optional filters.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `network` | string | all | Filter by network type |
| `host` | string | all | Filter to peers ever observed on this host |
| `limit` | integer | 100 | Max results (capped at 500) |
| `offset` | integer | 0 | Pagination offset |

Returns a JSON array of `PeerSummary` objects:

```json
[
  {
    "peer_id": 42,
    "address": "1.2.3.4",
    "network": "ipv4",
    "first_seen": "2025-01-01T00:00:00Z",
    "last_seen": "2025-03-17T08:00:00Z",
    "latest_subversion": "/Satoshi:27.0.0/",
    "observation_count": 12345,
    "active_on_hosts": ["bitcoin-03", "vps-dev-01"]
  }
]
```

### `GET /api/peers/{id}`

Full peer profile by `peer_id` (integer, avoids IPv6 URL encoding issues).

```json
{
  "peer": { "peer_id": 42, "address": "1.2.3.4", "network": "ipv4", "first_seen": "...", "last_seen": "..." },
  "recent_observations": [ { "observation_id": 1, "host": "bitcoin-03", "observed_at": "...", "inbound": false, ... } ],
  "software_history": [ { "history_id": 1, "observed_at": "...", "subversion": "/Satoshi:27.0.0/", ... } ],
  "presence_windows": [ { "window_id": 1, "host": "bitcoin-03", "first_observed": "...", "last_observed": "...", "closed": false } ]
}
```

Recent observations are limited to the last 100, software history to 200, presence windows to 50.

### `GET /api/peers/stats`

Aggregate statistics. Host freshness is computed at read time: `stale` when `now - last_polled_at > 2 × poll_interval`. Active window counts are split by host freshness.

```json
{
  "total_peers": 250,
  "peers_by_network": [ { "network": "ipv4", "count": 180 }, { "network": "onion", "count": 50 } ],
  "total_observations": 1234567,
  "active_windows": 200,
  "stale_windows": 10,
  "hosts": [ { "host": "bitcoin-03", "last_polled_at": "2025-03-17T08:00:00Z", "stale": false } ]
}
```

The host list is derived from `RpcClient::host_names()` (the configured inventory), not just `host_poll_status` rows. Hosts that have never had a successful poll appear with `last_polled_at: null, stale: true`.

### `GET /peers`

Self-contained HTML/CSS/JS peer profiles viewer page. Unauthenticated — the HTML shell contains no profile data. The bearer token is entered client-side and stored in `sessionStorage`. Follows the same design patterns as the `/logs` annotation viewer:

- Dark theme matching the existing viewer
- Network badges (IPv4=green, IPv6=blue, Onion=purple, I2P=yellow, CJDNS=red)
- Peer list table with network/host filters, client-side address/subversion search, pagination
- Click-through to detail view with software timeline, presence windows, recent observations
- UTC/local timezone toggle
- Auto-detection of reverse proxy auth
- All user content rendered via `textContent` (XSS-safe)
