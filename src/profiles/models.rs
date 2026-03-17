//! Data models for peer profiles — Rust structs with serde derives for API serialization.

use serde::Serialize;

/// A tracked peer identity.
#[derive(Debug, Clone, Serialize)]
pub struct Peer {
    pub peer_id: i64,
    pub address: String,
    pub network: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// A single connection snapshot observation.
#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub observation_id: i64,
    pub peer_id: i64,
    pub host: String,
    pub observed_at: String,
    pub addr_with_port: String,
    pub inbound: bool,
    pub connection_type: String,
    pub conntime: i64,
    pub starting_height: Option<i64>,
    pub synced_headers: Option<i64>,
    pub synced_blocks: Option<i64>,
}

/// A software version change event.
#[derive(Debug, Clone, Serialize)]
pub struct SoftwareChange {
    pub history_id: i64,
    pub peer_id: i64,
    pub host: String,
    pub observed_at: String,
    pub subversion: String,
    pub version: i64,
    pub services: String,
}

/// A presence window tracking when a peer was continuously observed.
#[derive(Debug, Clone, Serialize)]
pub struct PresenceWindow {
    pub window_id: i64,
    pub peer_id: i64,
    pub host: String,
    pub first_observed: String,
    pub last_observed: String,
    pub closed: bool,
}

/// Summary of a peer for the list endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct PeerSummary {
    pub peer_id: i64,
    pub address: String,
    pub network: String,
    pub first_seen: String,
    pub last_seen: String,
    pub latest_subversion: Option<String>,
    pub observation_count: i64,
    pub active_on_hosts: Vec<String>,
}

/// Full peer profile for the detail endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct PeerProfile {
    pub peer: Peer,
    pub recent_observations: Vec<Observation>,
    pub software_history: Vec<SoftwareChange>,
    pub presence_windows: Vec<PresenceWindow>,
}

/// Per-host poll status for the stats endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    pub host: String,
    pub last_polled_at: Option<String>,
    pub stale: bool,
}

/// Aggregate statistics for the stats endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileStats {
    pub total_peers: i64,
    pub peers_by_network: Vec<NetworkCount>,
    pub total_observations: i64,
    pub active_windows: i64,
    pub stale_windows: i64,
    pub hosts: Vec<HostStatus>,
}

/// Network peer count for stats.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkCount {
    pub network: String,
    pub count: i64,
}

/// Parsed peer data from a single getpeerinfo entry, ready for DB insertion.
/// Shared between `poller` (produces) and `db` (consumes via `process_host_poll`).
pub struct ParsedPeer {
    pub address: String,
    pub network: String,
    pub addr_with_port: String,
    pub inbound: bool,
    pub connection_type: String,
    pub conntime: i64,
    pub starting_height: Option<i64>,
    pub synced_headers: Option<i64>,
    pub synced_blocks: Option<i64>,
    pub subversion: String,
    pub version: i64,
    pub services: String,
}
