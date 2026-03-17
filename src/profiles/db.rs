//! SQLite database for peer profiles — schema initialization, migrations, and data access.

use anyhow::{Context, Result};
use rusqlite::params;
use std::sync::{Arc, Mutex};

use super::models::{
    HostStatus, NetworkCount, Observation, Peer, PeerProfile, PeerSummary, PresenceWindow,
    ProfileStats, SoftwareChange,
};

/// Schema DDL — executed when `PRAGMA user_version` is 0 (fresh database).
const SCHEMA_DDL: &str = r#"
CREATE TABLE peers (
    peer_id         INTEGER PRIMARY KEY,
    address         TEXT NOT NULL,
    network         TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    UNIQUE(address, network)
);
CREATE INDEX idx_peers_network ON peers(network);
CREATE INDEX idx_peers_last_seen ON peers(last_seen);

CREATE TABLE observations (
    observation_id  INTEGER PRIMARY KEY,
    peer_id         INTEGER NOT NULL REFERENCES peers(peer_id),
    host            TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    addr_with_port  TEXT NOT NULL,
    inbound         INTEGER NOT NULL,
    connection_type TEXT NOT NULL,
    conntime        INTEGER NOT NULL,
    starting_height INTEGER,
    synced_headers  INTEGER,
    synced_blocks   INTEGER
);
CREATE INDEX idx_obs_peer_host_time ON observations(peer_id, host, observed_at);
CREATE INDEX idx_obs_observed_at ON observations(observed_at);

CREATE TABLE software_history (
    history_id      INTEGER PRIMARY KEY,
    peer_id         INTEGER NOT NULL REFERENCES peers(peer_id),
    host            TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    subversion      TEXT NOT NULL,
    version         INTEGER NOT NULL,
    services        TEXT NOT NULL
);
CREATE INDEX idx_swh_peer_host_time ON software_history(peer_id, host, observed_at);

CREATE TABLE presence_windows (
    window_id       INTEGER PRIMARY KEY,
    peer_id         INTEGER NOT NULL REFERENCES peers(peer_id),
    host            TEXT NOT NULL,
    first_observed  TEXT NOT NULL,
    last_observed   TEXT NOT NULL,
    closed          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_pw_peer_host ON presence_windows(peer_id, host);
CREATE INDEX idx_pw_host_active ON presence_windows(host) WHERE closed = 0;
CREATE UNIQUE INDEX idx_pw_one_active ON presence_windows(peer_id, host) WHERE closed = 0;

CREATE TABLE host_poll_status (
    host            TEXT PRIMARY KEY,
    last_polled_at  TEXT NOT NULL
);
"#;

/// SQLite-backed peer profile database.
pub struct ProfileDb {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl ProfileDb {
    /// Open (or create) the SQLite database at `path`.
    ///
    /// - If `user_version` is 0: sets `auto_vacuum = INCREMENTAL`, runs schema DDL,
    ///   sets `user_version = 1`.
    /// - Always sets WAL, foreign_keys, and busy_timeout pragmas.
    pub fn open(path: &str) -> Result<Arc<Self>> {
        let conn =
            rusqlite::Connection::open(path).with_context(|| format!("open SQLite DB: {path}"))?;

        // Always-on pragmas
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", "5000")?;

        let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

        match version {
            0 => {
                // Fresh database — set auto_vacuum before creating tables
                conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
                conn.execute_batch(SCHEMA_DDL)
                    .context("failed to initialize profile schema")?;
                conn.pragma_update(None, "user_version", "1")?;
            }
            1 => {
                // Current schema — nothing to do
            }
            v => {
                anyhow::bail!(
                    "profiles DB has user_version {v}, but this binary only supports version 1"
                );
            }
        }

        Ok(Arc::new(Self {
            conn: Arc::new(Mutex::new(conn)),
        }))
    }

    // ── Write operations (individual, used by tests) ────────────────────

    /// Upsert a peer: INSERT OR IGNORE + UPDATE last_seen. Returns `peer_id`.
    #[cfg(test)]
    pub async fn upsert_peer(&self, address: &str, network: &str, now: &str) -> Result<i64> {
        let conn = Arc::clone(&self.conn);
        let address = address.to_string();
        let network = network.to_string();
        let now = now.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO peers (address, network, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
                params![address, network, now],
            )?;
            conn.execute(
                "UPDATE peers SET last_seen = ?1 WHERE address = ?2 AND network = ?3",
                params![now, address, network],
            )?;
            let peer_id: i64 = conn.query_row(
                "SELECT peer_id FROM peers WHERE address = ?1 AND network = ?2",
                params![address, network],
                |row| row.get(0),
            )?;
            Ok(peer_id)
        })
        .await?
    }

    /// Insert an observation row.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_observation(
        &self,
        peer_id: i64,
        host: &str,
        observed_at: &str,
        addr_with_port: &str,
        inbound: bool,
        connection_type: &str,
        conntime: i64,
        starting_height: Option<i64>,
        synced_headers: Option<i64>,
        synced_blocks: Option<i64>,
    ) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let host = host.to_string();
        let observed_at = observed_at.to_string();
        let addr_with_port = addr_with_port.to_string();
        let connection_type = connection_type.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO observations (peer_id, host, observed_at, addr_with_port, inbound, connection_type, conntime, starting_height, synced_headers, synced_blocks) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![peer_id, host, observed_at, addr_with_port, inbound as i32, connection_type, conntime, starting_height, synced_headers, synced_blocks],
            )?;
            Ok(())
        })
        .await?
    }

    /// Check if software has changed for this (peer, host) and insert a new row if so.
    #[cfg(test)]
    pub async fn record_software_change(
        &self,
        peer_id: i64,
        host: &str,
        observed_at: &str,
        subversion: &str,
        version: i64,
        services: &str,
    ) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let host = host.to_string();
        let observed_at = observed_at.to_string();
        let subversion = subversion.to_string();
        let services = services.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            // Check latest entry for this (peer, host)
            let latest: Option<(String, i64, String)> = conn
                .query_row(
                    "SELECT subversion, version, services FROM software_history WHERE peer_id = ?1 AND host = ?2 ORDER BY observed_at DESC LIMIT 1",
                    params![peer_id, host],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .ok();

            let changed = match latest {
                None => true, // No previous record
                Some((prev_sub, prev_ver, prev_svc)) => {
                    prev_sub != subversion || prev_ver != version || prev_svc != services
                }
            };

            if changed {
                conn.execute(
                    "INSERT INTO software_history (peer_id, host, observed_at, subversion, version, services) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![peer_id, host, observed_at, subversion, version, services],
                )?;
            }
            Ok(())
        })
        .await?
    }

    /// Run the full presence window tracking for a host after a successful poll.
    ///
    /// `seen_peer_ids` is the set of peer_ids observed in this poll cycle.
    /// `poll_interval_secs` is used for stale window recovery (2x threshold).
    #[cfg(test)]
    pub async fn update_presence_windows(
        &self,
        host: &str,
        now: &str,
        seen_peer_ids: Vec<i64>,
        poll_interval_secs: u64,
    ) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let host = host.to_string();
        let now = now.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // Step 1: Stale window recovery — close windows whose last_observed is
            // older than 2× poll interval relative to the current poll timestamp.
            // Uses the provided `now` rather than wall clock so callers (including tests)
            // control the reference point.
            let stale_secs = (poll_interval_secs * 2) as i64;
            // Parse now as ISO 8601, fall back to current time
            let now_dt = chrono::DateTime::parse_from_rfc3339(&now)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| anyhow::anyhow!("failed to parse poll timestamp '{now}': {e}"))?;
            let stale_threshold = now_dt - chrono::Duration::seconds(stale_secs);
            let stale_cutoff = stale_threshold.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            conn.execute(
                "UPDATE presence_windows SET closed = 1 WHERE host = ?1 AND closed = 0 AND last_observed < ?2",
                params![host, stale_cutoff],
            )?;

            // Step 2: Get remaining active windows for this host
            let mut stmt = conn.prepare(
                "SELECT window_id, peer_id FROM presence_windows WHERE host = ?1 AND closed = 0",
            )?;
            let active_windows: Vec<(i64, i64)> = stmt
                .query_map(params![host], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;

            let seen_set: std::collections::HashSet<i64> =
                seen_peer_ids.iter().copied().collect();

            // Step 3: Disappeared peers — close their windows
            for (window_id, peer_id) in &active_windows {
                if !seen_set.contains(peer_id) {
                    conn.execute(
                        "UPDATE presence_windows SET closed = 1 WHERE window_id = ?1",
                        params![window_id],
                    )?;
                }
            }

            let active_peer_ids: std::collections::HashSet<i64> =
                active_windows.iter().map(|(_, pid)| *pid).collect();

            // Step 4: Continuing peers — update last_observed
            for peer_id in &seen_set {
                if active_peer_ids.contains(peer_id) {
                    conn.execute(
                        "UPDATE presence_windows SET last_observed = ?1 WHERE peer_id = ?2 AND host = ?3 AND closed = 0",
                        params![now, peer_id, host],
                    )?;
                }
            }

            // Step 5: New peers — insert new windows
            for peer_id in &seen_set {
                if !active_peer_ids.contains(peer_id) {
                    conn.execute(
                        "INSERT INTO presence_windows (peer_id, host, first_observed, last_observed, closed) VALUES (?1, ?2, ?3, ?3, 0)",
                        params![peer_id, host, now],
                    )?;
                }
            }

            Ok(())
        })
        .await?
    }

    /// Process an entire host poll atomically in a single SQLite transaction.
    ///
    /// For each peer: upserts the peer row, inserts an observation, and detects
    /// software changes. Then updates presence windows and host poll status.
    /// If any step fails, the entire transaction is rolled back.
    pub async fn process_host_poll(
        &self,
        host: &str,
        now: &str,
        peers: Vec<super::models::ParsedPeer>,
        poll_interval_secs: u64,
    ) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        let host = host.to_string();
        let now = now.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = conn.lock().unwrap();
            let tx = conn.transaction()?;

            let mut seen_peer_ids = std::collections::HashSet::new();

            for peer in &peers {
                // Upsert peer
                tx.execute(
                    "INSERT OR IGNORE INTO peers (address, network, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
                    params![peer.address, peer.network, now],
                )?;
                tx.execute(
                    "UPDATE peers SET last_seen = ?1 WHERE address = ?2 AND network = ?3",
                    params![now, peer.address, peer.network],
                )?;
                let peer_id: i64 = tx.query_row(
                    "SELECT peer_id FROM peers WHERE address = ?1 AND network = ?2",
                    params![peer.address, peer.network],
                    |row| row.get(0),
                )?;
                seen_peer_ids.insert(peer_id);

                // Insert observation
                tx.execute(
                    "INSERT INTO observations (peer_id, host, observed_at, addr_with_port, inbound, connection_type, conntime, starting_height, synced_headers, synced_blocks) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![peer_id, host, now, peer.addr_with_port, peer.inbound as i32, peer.connection_type, peer.conntime, peer.starting_height, peer.synced_headers, peer.synced_blocks],
                )?;

                // Software change detection — only treat "no rows" as None;
                // propagate real DB errors to roll back the transaction.
                let latest: Option<(String, i64, String)> = match tx.query_row(
                    "SELECT subversion, version, services FROM software_history WHERE peer_id = ?1 AND host = ?2 ORDER BY observed_at DESC LIMIT 1",
                    params![peer_id, host],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                ) {
                    Ok(row) => Some(row),
                    Err(rusqlite::Error::QueryReturnedNoRows) => None,
                    Err(e) => return Err(anyhow::Error::from(e)),
                };

                let changed = match latest {
                    None => true,
                    Some((prev_sub, prev_ver, prev_svc)) => {
                        prev_sub != peer.subversion || prev_ver != peer.version || prev_svc != peer.services
                    }
                };

                if changed {
                    tx.execute(
                        "INSERT INTO software_history (peer_id, host, observed_at, subversion, version, services) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![peer_id, host, now, peer.subversion, peer.version, peer.services],
                    )?;
                }
            }

            // ── Presence window tracking ──────────────────────────────
            let seen_vec: Vec<i64> = seen_peer_ids.iter().copied().collect();

            // Step 1: Stale window recovery
            let now_dt = chrono::DateTime::parse_from_rfc3339(&now)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| anyhow::anyhow!("failed to parse poll timestamp '{now}': {e}"))?;
            let stale_threshold = now_dt - chrono::Duration::seconds((poll_interval_secs * 2) as i64);
            let stale_cutoff = stale_threshold.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            tx.execute(
                "UPDATE presence_windows SET closed = 1 WHERE host = ?1 AND closed = 0 AND last_observed < ?2",
                params![host, stale_cutoff],
            )?;

            // Step 2: Get remaining active windows
            let mut stmt = tx.prepare(
                "SELECT window_id, peer_id FROM presence_windows WHERE host = ?1 AND closed = 0",
            )?;
            let active_windows: Vec<(i64, i64)> = stmt
                .query_map(params![host], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);

            let active_peer_ids: std::collections::HashSet<i64> =
                active_windows.iter().map(|(_, pid)| *pid).collect();

            // Step 3: Disappeared peers — close their windows
            for (window_id, peer_id) in &active_windows {
                if !seen_peer_ids.contains(peer_id) {
                    tx.execute(
                        "UPDATE presence_windows SET closed = 1 WHERE window_id = ?1",
                        params![window_id],
                    )?;
                }
            }

            // Step 4: Continuing peers — update last_observed
            for peer_id in &seen_vec {
                if active_peer_ids.contains(peer_id) {
                    tx.execute(
                        "UPDATE presence_windows SET last_observed = ?1 WHERE peer_id = ?2 AND host = ?3 AND closed = 0",
                        params![now, peer_id, host],
                    )?;
                }
            }

            // Step 5: New peers — insert new windows
            for peer_id in &seen_vec {
                if !active_peer_ids.contains(peer_id) {
                    tx.execute(
                        "INSERT INTO presence_windows (peer_id, host, first_observed, last_observed, closed) VALUES (?1, ?2, ?3, ?3, 0)",
                        params![peer_id, host, now],
                    )?;
                }
            }

            // Update host poll status (inside transaction so freshness is
            // only recorded when data is committed)
            tx.execute(
                "INSERT INTO host_poll_status (host, last_polled_at) VALUES (?1, ?2) ON CONFLICT(host) DO UPDATE SET last_polled_at = excluded.last_polled_at",
                params![host, now],
            )?;

            tx.commit()?;
            Ok(())
        })
        .await?
    }

    /// Delete observations older than the given ISO 8601 cutoff, in batches.
    /// Returns the total number of rows deleted.
    pub async fn prune_observations(&self, cutoff: &str) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        let cutoff = cutoff.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut total_deleted = 0usize;
            loop {
                let deleted = conn.execute(
                    "DELETE FROM observations WHERE observation_id IN (SELECT observation_id FROM observations WHERE observed_at < ?1 LIMIT 10000)",
                    params![cutoff],
                )?;
                total_deleted += deleted;
                if deleted < 10000 {
                    break;
                }
            }
            Ok(total_deleted)
        })
        .await?
    }

    /// Delete closed presence windows older than the given ISO 8601 cutoff, in batches.
    /// Returns the total number of rows deleted.
    pub async fn prune_closed_presence_windows(&self, cutoff: &str) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        let cutoff = cutoff.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut total_deleted = 0usize;
            loop {
                let deleted = conn.execute(
                    "DELETE FROM presence_windows WHERE window_id IN (SELECT window_id FROM presence_windows WHERE closed = 1 AND last_observed < ?1 LIMIT 10000)",
                    params![cutoff],
                )?;
                total_deleted += deleted;
                if deleted < 10000 {
                    break;
                }
            }
            Ok(total_deleted)
        })
        .await?
    }

    /// Delete software history entries older than the given ISO 8601 cutoff, in batches.
    /// Preserves the most recent row per (peer_id, host) to prevent false re-detection
    /// of unchanged software after pruning.
    /// Returns the total number of rows deleted.
    pub async fn prune_software_history(&self, cutoff: &str) -> Result<usize> {
        let conn = Arc::clone(&self.conn);
        let cutoff = cutoff.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut total_deleted = 0usize;
            loop {
                let deleted = conn.execute(
                    "DELETE FROM software_history WHERE history_id IN (
                        SELECT sh.history_id FROM software_history sh
                        WHERE sh.observed_at < ?1
                        AND EXISTS (
                            SELECT 1 FROM software_history sh2
                            WHERE sh2.peer_id = sh.peer_id AND sh2.host = sh.host
                            AND sh2.observed_at > sh.observed_at
                        )
                        LIMIT 10000
                    )",
                    params![cutoff],
                )?;
                total_deleted += deleted;
                if deleted < 10000 {
                    break;
                }
            }
            Ok(total_deleted)
        })
        .await?
    }

    /// Run `PRAGMA incremental_vacuum` to reclaim space after large deletes.
    pub async fn incremental_vacuum(&self) -> Result<()> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute_batch("PRAGMA incremental_vacuum")?;
            Ok(())
        })
        .await?
    }

    // ── Read operations (used by API) ─────────────────────────────────

    /// List peer summaries with optional filters.
    pub async fn list_peers(
        &self,
        network: Option<&str>,
        host: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PeerSummary>> {
        let conn = Arc::clone(&self.conn);
        let network = network.map(|s| s.to_string());
        let host = host.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // Build dynamic query
            let mut conditions = Vec::new();
            let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref net) = network {
                conditions.push("p.network = ?");
                bind_values.push(Box::new(net.clone()));
            }

            if let Some(ref h) = host {
                // Filters to peers ever observed on this host (not just currently active).
                conditions.push("EXISTS (SELECT 1 FROM presence_windows pw WHERE pw.peer_id = p.peer_id AND pw.host = ?)");
                bind_values.push(Box::new(h.clone()));
            }

            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            let sql = format!(
                "SELECT p.peer_id, p.address, p.network, p.first_seen, p.last_seen,
                        (SELECT sh.subversion FROM software_history sh WHERE sh.peer_id = p.peer_id ORDER BY sh.observed_at DESC LIMIT 1) as latest_subversion,
                        (SELECT COUNT(*) FROM observations o WHERE o.peer_id = p.peer_id) as obs_count
                 FROM peers p
                 {where_clause}
                 ORDER BY p.last_seen DESC
                 LIMIT ? OFFSET ?"
            );

            bind_values.push(Box::new(limit as i64));
            bind_values.push(Box::new(offset as i64));

            let params_ref: Vec<&dyn rusqlite::types::ToSql> =
                bind_values.iter().map(|b| b.as_ref()).collect();

            let mut stmt = conn.prepare(&sql)?;
            let peers: Vec<_> = stmt
                .query_map(params_ref.as_slice(), |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            // Batch-fetch active hosts for all returned peers in a single query
            // to avoid N+1 while holding the mutex.
            let peer_ids: Vec<i64> = peers.iter().map(|(id, ..)| *id).collect();
            let mut hosts_map: std::collections::HashMap<i64, Vec<String>> =
                std::collections::HashMap::new();

            if !peer_ids.is_empty() {
                let placeholders: String = peer_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let hosts_sql = format!(
                    "SELECT DISTINCT peer_id, host FROM presence_windows WHERE peer_id IN ({placeholders}) AND closed = 0"
                );
                let mut host_stmt = conn.prepare(&hosts_sql)?;
                let host_params: Vec<&dyn rusqlite::types::ToSql> =
                    peer_ids.iter().map(|id| id as &dyn rusqlite::types::ToSql).collect();
                let rows = host_stmt
                    .query_map(host_params.as_slice(), |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                for (pid, host) in rows {
                    hosts_map.entry(pid).or_default().push(host);
                }
            }

            let mut result = Vec::with_capacity(peers.len());
            for (peer_id, address, net, first_seen, last_seen, latest_sub, obs_count) in peers {
                result.push(PeerSummary {
                    peer_id,
                    address,
                    network: net,
                    first_seen,
                    last_seen,
                    latest_subversion: latest_sub,
                    observation_count: obs_count,
                    active_on_hosts: hosts_map.remove(&peer_id).unwrap_or_default(),
                });
            }

            Ok(result)
        })
        .await?
    }

    /// Get a full peer profile by peer_id.
    pub async fn get_peer_profile(&self, peer_id: i64) -> Result<Option<PeerProfile>> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            // Fetch peer
            let peer = conn
                .query_row(
                    "SELECT peer_id, address, network, first_seen, last_seen FROM peers WHERE peer_id = ?1",
                    params![peer_id],
                    |row| {
                        Ok(Peer {
                            peer_id: row.get(0)?,
                            address: row.get(1)?,
                            network: row.get(2)?,
                            first_seen: row.get(3)?,
                            last_seen: row.get(4)?,
                        })
                    },
                )
                .ok();

            let Some(peer) = peer else {
                return Ok(None);
            };

            // Recent observations (last 100)
            let mut obs_stmt = conn.prepare(
                "SELECT observation_id, peer_id, host, observed_at, addr_with_port, inbound, connection_type, conntime, starting_height, synced_headers, synced_blocks FROM observations WHERE peer_id = ?1 ORDER BY observed_at DESC LIMIT 100"
            )?;
            let recent_observations: Vec<Observation> = obs_stmt
                .query_map(params![peer_id], |row| {
                    Ok(Observation {
                        observation_id: row.get(0)?,
                        peer_id: row.get(1)?,
                        host: row.get(2)?,
                        observed_at: row.get(3)?,
                        addr_with_port: row.get(4)?,
                        inbound: row.get::<_, i32>(5)? != 0,
                        connection_type: row.get(6)?,
                        conntime: row.get(7)?,
                        starting_height: row.get(8)?,
                        synced_headers: row.get(9)?,
                        synced_blocks: row.get(10)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            // Software history
            let mut sw_stmt = conn.prepare(
                "SELECT history_id, peer_id, host, observed_at, subversion, version, services FROM software_history WHERE peer_id = ?1 ORDER BY observed_at DESC LIMIT 200"
            )?;
            let software_history: Vec<SoftwareChange> = sw_stmt
                .query_map(params![peer_id], |row| {
                    Ok(SoftwareChange {
                        history_id: row.get(0)?,
                        peer_id: row.get(1)?,
                        host: row.get(2)?,
                        observed_at: row.get(3)?,
                        subversion: row.get(4)?,
                        version: row.get(5)?,
                        services: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            // Presence windows (last 50)
            let mut pw_stmt = conn.prepare(
                "SELECT window_id, peer_id, host, first_observed, last_observed, closed FROM presence_windows WHERE peer_id = ?1 ORDER BY first_observed DESC LIMIT 50"
            )?;
            let presence_windows: Vec<PresenceWindow> = pw_stmt
                .query_map(params![peer_id], |row| {
                    Ok(PresenceWindow {
                        window_id: row.get(0)?,
                        peer_id: row.get(1)?,
                        host: row.get(2)?,
                        first_observed: row.get(3)?,
                        last_observed: row.get(4)?,
                        closed: row.get::<_, i32>(5)? != 0,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Some(PeerProfile {
                peer,
                recent_observations,
                software_history,
                presence_windows,
            }))
        })
        .await?
    }

    /// Get aggregate statistics.
    pub async fn get_stats(
        &self,
        configured_hosts: Vec<String>,
        poll_interval_secs: u64,
    ) -> Result<ProfileStats> {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();

            let total_peers: i64 =
                conn.query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?;

            let mut net_stmt =
                conn.prepare("SELECT network, COUNT(*) FROM peers GROUP BY network")?;
            let peers_by_network: Vec<NetworkCount> = net_stmt
                .query_map([], |row| {
                    Ok(NetworkCount {
                        network: row.get(0)?,
                        count: row.get(1)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let total_observations: i64 =
                conn.query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))?;

            let now = chrono::Utc::now();
            let stale_threshold = now - chrono::Duration::seconds((poll_interval_secs * 2) as i64);
            let stale_cutoff = stale_threshold.format("%Y-%m-%dT%H:%M:%SZ").to_string();

            // Build host statuses from configured hosts
            let mut hosts = Vec::with_capacity(configured_hosts.len());
            let mut active_windows: i64 = 0;
            let mut stale_windows: i64 = 0;

            for host_name in &configured_hosts {
                let last_polled: Option<String> = conn
                    .query_row(
                        "SELECT last_polled_at FROM host_poll_status WHERE host = ?1",
                        params![host_name],
                        |row| row.get(0),
                    )
                    .ok();

                let is_stale = match &last_polled {
                    None => true,
                    Some(ts) => ts < &stale_cutoff,
                };

                // Count active windows for this host
                let host_active: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM presence_windows WHERE host = ?1 AND closed = 0",
                    params![host_name],
                    |row| row.get(0),
                )?;

                if is_stale {
                    stale_windows += host_active;
                } else {
                    active_windows += host_active;
                }

                hosts.push(HostStatus {
                    host: host_name.clone(),
                    last_polled_at: last_polled,
                    stale: is_stale,
                });
            }

            Ok(ProfileStats {
                total_peers,
                peers_by_network,
                total_observations,
                active_windows,
                stale_windows,
                hosts,
            })
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn temp_db_path() -> (NamedTempFile, String) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_string_lossy().to_string();
        (f, path)
    }

    #[tokio::test]
    async fn open_creates_schema() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        // Verify tables exist by querying them
        let conn = db.conn.lock().unwrap();
        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[tokio::test]
    async fn open_idempotent() {
        let (_f, path) = temp_db_path();
        ProfileDb::open(&path).unwrap();
        // Opening again should succeed (version 1 → no-op)
        ProfileDb::open(&path).unwrap();
    }

    #[tokio::test]
    async fn upsert_peer_creates_and_updates() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        let id1 = db
            .upsert_peer("1.2.3.4", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();
        let id2 = db
            .upsert_peer("1.2.3.4", "ipv4", "2025-01-01T01:00:00Z")
            .await
            .unwrap();
        assert_eq!(id1, id2, "same address+network should return same peer_id");

        // Different address gets different id
        let id3 = db
            .upsert_peer("5.6.7.8", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn software_change_detection() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        let pid = db
            .upsert_peer("1.2.3.4", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // First record always inserted
        db.record_software_change(
            pid,
            "host1",
            "2025-01-01T00:00:00Z",
            "/Satoshi:27.0.0/",
            270000,
            "0x0409",
        )
        .await
        .unwrap();

        // Same software — should not insert
        db.record_software_change(
            pid,
            "host1",
            "2025-01-01T00:05:00Z",
            "/Satoshi:27.0.0/",
            270000,
            "0x0409",
        )
        .await
        .unwrap();

        // Different subversion — should insert
        db.record_software_change(
            pid,
            "host1",
            "2025-01-01T00:10:00Z",
            "/Satoshi:28.0.0/",
            280000,
            "0x0409",
        )
        .await
        .unwrap();

        let conn = db.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM software_history WHERE peer_id = ?1",
                params![pid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2, "should have 2 software history entries");
    }

    #[tokio::test]
    async fn presence_window_lifecycle() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        let pid1 = db
            .upsert_peer("1.2.3.4", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();
        let pid2 = db
            .upsert_peer("5.6.7.8", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // Poll 1: both peers seen
        db.update_presence_windows("host1", "2025-01-01T00:00:00Z", vec![pid1, pid2], 300)
            .await
            .unwrap();

        {
            let conn = db.conn.lock().unwrap();
            let active: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 0",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(active, 2);
        }

        // Poll 2: only pid1 seen — pid2 should be closed
        db.update_presence_windows("host1", "2025-01-01T00:05:00Z", vec![pid1], 300)
            .await
            .unwrap();

        {
            let conn = db.conn.lock().unwrap();
            let active: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 0",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(active, 1);

            let closed: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(closed, 1);
        }
    }

    #[tokio::test]
    async fn prune_observations_works() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        let pid = db
            .upsert_peer("1.2.3.4", "ipv4", "2025-01-01T00:00:00Z")
            .await
            .unwrap();

        // Insert observations
        for i in 0..5 {
            db.insert_observation(
                pid,
                "host1",
                &format!("2025-01-0{}T00:00:00Z", i + 1),
                "1.2.3.4:8333",
                false,
                "outbound-full-relay",
                1000,
                Some(800000),
                Some(800000),
                Some(800000),
            )
            .await
            .unwrap();
        }

        // Prune observations older than day 3
        let deleted = db.prune_observations("2025-01-03T00:00:00Z").await.unwrap();
        assert_eq!(deleted, 2);

        let conn = db.conn.lock().unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 3);
    }

    #[tokio::test]
    async fn get_peer_profile_returns_none_for_missing() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();
        let result = db.get_peer_profile(999).await.unwrap();
        assert!(result.is_none());
    }

    // ── process_host_poll (production write path) ─────────────────────

    fn make_parsed_peer(
        addr: &str,
        network: &str,
        subversion: &str,
    ) -> crate::profiles::models::ParsedPeer {
        crate::profiles::models::ParsedPeer {
            address: addr.to_string(),
            network: network.to_string(),
            addr_with_port: format!("{addr}:8333"),
            inbound: false,
            connection_type: "outbound-full-relay".to_string(),
            conntime: 1000,
            starting_height: Some(800000),
            synced_headers: Some(800000),
            synced_blocks: Some(800000),
            subversion: subversion.to_string(),
            version: 270000,
            services: "0x0409".to_string(),
        }
    }

    #[tokio::test]
    async fn process_host_poll_inserts_peers_and_observations() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        let peers = vec![
            make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/"),
            make_parsed_peer("5.6.7.8", "ipv4", "/Satoshi:28.0.0/"),
        ];

        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers, 300)
            .await
            .unwrap();

        let conn = db.conn.lock().unwrap();
        let peer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(peer_count, 2);

        let obs_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(obs_count, 2);

        let sw_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM software_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            sw_count, 2,
            "first poll should create software_history for each peer"
        );

        let active_windows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_windows, 2);

        let poll_ts: String = conn
            .query_row(
                "SELECT last_polled_at FROM host_poll_status WHERE host = 'host1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(poll_ts, "2025-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn process_host_poll_deduplicates_same_peer_identity() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        // Same bare IP appears twice (inbound + outbound connections)
        let mut peer1 = make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/");
        peer1.addr_with_port = "1.2.3.4:8333".to_string();
        peer1.inbound = false;

        let mut peer2 = make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/");
        peer2.addr_with_port = "1.2.3.4:12345".to_string();
        peer2.inbound = true;

        db.process_host_poll("host1", "2025-01-01T00:00:00Z", vec![peer1, peer2], 300)
            .await
            .unwrap();

        let conn = db.conn.lock().unwrap();
        // Should have 1 peer (deduplicated by bare IP)
        let peer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))
            .unwrap();
        assert_eq!(peer_count, 1);

        // Should have 2 observations (one per connection)
        let obs_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(obs_count, 2);

        // Should have only 1 active presence window (not 2 — unique index enforced)
        let windows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM presence_windows WHERE closed = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            windows, 1,
            "duplicate peer identity should produce one presence window"
        );
    }

    #[tokio::test]
    async fn process_host_poll_detects_software_changes() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        // Poll 1: peer with version 27
        let peers1 = vec![make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/")];
        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers1, 300)
            .await
            .unwrap();

        // Poll 2: same software — should NOT insert a new software_history row
        let peers2 = vec![make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/")];
        db.process_host_poll("host1", "2025-01-01T00:05:00Z", peers2, 300)
            .await
            .unwrap();

        // Poll 3: upgraded to version 28 — should insert a new row
        let peers3 = vec![make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:28.0.0/")];
        db.process_host_poll("host1", "2025-01-01T00:10:00Z", peers3, 300)
            .await
            .unwrap();

        let conn = db.conn.lock().unwrap();
        let sw_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM software_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            sw_count, 2,
            "should have exactly 2 software history entries (initial + change)"
        );
    }

    #[tokio::test]
    async fn process_host_poll_closes_disappeared_peers() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        // Poll 1: two peers
        let peers1 = vec![
            make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/"),
            make_parsed_peer("5.6.7.8", "ipv4", "/Satoshi:27.0.0/"),
        ];
        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers1, 300)
            .await
            .unwrap();

        // Poll 2: only first peer — second should get its window closed
        let peers2 = vec![make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/")];
        db.process_host_poll("host1", "2025-01-01T00:05:00Z", peers2, 300)
            .await
            .unwrap();

        let conn = db.conn.lock().unwrap();
        let active: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);

        let closed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM presence_windows WHERE host = 'host1' AND closed = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(closed, 1);
    }

    #[tokio::test]
    async fn process_host_poll_updates_host_freshness_atomically() {
        let (_f, path) = temp_db_path();
        let db = ProfileDb::open(&path).unwrap();

        // Before any poll, host_poll_status should be empty
        {
            let conn = db.conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM host_poll_status", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }

        let peers = vec![make_parsed_peer("1.2.3.4", "ipv4", "/Satoshi:27.0.0/")];
        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers, 300)
            .await
            .unwrap();

        // After poll, host should have a freshness timestamp
        {
            let conn = db.conn.lock().unwrap();
            let ts: String = conn
                .query_row(
                    "SELECT last_polled_at FROM host_poll_status WHERE host = 'host1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ts, "2025-01-01T00:00:00Z");
        }
    }
}
