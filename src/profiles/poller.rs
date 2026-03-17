//! Background polling task — periodically fetches `getpeerinfo` from all configured
//! hosts and updates the peer profiles database.

use anyhow::Result;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use super::db::ProfileDb;
use super::identity::peer_identity;
use super::models::ParsedPeer;
use crate::rpc::RpcClient;

/// Start the background poller. Runs immediately on first tick, then every `poll_interval`.
pub fn start_poller(
    db: Arc<ProfileDb>,
    rpc_client: Arc<RpcClient>,
    poll_interval: Duration,
    retention_days: u64,
) {
    tokio::spawn(async move {
        let mut ticker = interval(poll_interval);
        let mut poll_count: u64 = 0;

        loop {
            ticker.tick().await;
            poll_count += 1;

            let hosts = rpc_client.host_names();
            info!(host_count = hosts.len(), "starting profile poll cycle");

            for host in &hosts {
                if let Err(e) = poll_host(&db, &rpc_client, host, poll_interval.as_secs()).await {
                    warn!(host = %host, error = %e, "profile poll failed for host");
                }
            }

            // Retention pruning after all hosts are polled
            let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
            let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string();
            match db.prune_observations(&cutoff_str).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned old observations");
                }
                Err(e) => {
                    warn!(error = %e, "observation retention pruning failed");
                }
                _ => {}
            }

            match db.prune_closed_presence_windows(&cutoff_str).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned old closed presence windows");
                }
                Err(e) => {
                    warn!(error = %e, "presence window retention pruning failed");
                }
                _ => {}
            }

            match db.prune_software_history(&cutoff_str).await {
                Ok(deleted) if deleted > 0 => {
                    info!(deleted, "pruned old software history");
                }
                Err(e) => {
                    warn!(error = %e, "software history retention pruning failed");
                }
                _ => {}
            }

            // Weekly incremental vacuum — compute polls-per-week from actual interval
            let polls_per_week = if poll_interval.as_secs() == 0 {
                1
            } else {
                (7 * 24 * 3600 / poll_interval.as_secs()).max(1)
            };
            if poll_count.is_multiple_of(polls_per_week) {
                if let Err(e) = db.incremental_vacuum().await {
                    warn!(error = %e, "incremental vacuum failed");
                }
            }
        }
    });
}

/// Poll a single host: fetch getpeerinfo, parse peer data, then commit
/// everything atomically in a single SQLite transaction.
async fn poll_host(
    db: &ProfileDb,
    rpc_client: &RpcClient,
    host: &str,
    poll_interval_secs: u64,
) -> Result<()> {
    let peers_json = rpc_client.getpeerinfo_raw(host).await?;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let peers = peers_json
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("getpeerinfo did not return an array"))?;

    // Parse all peer data outside the DB transaction
    let mut parsed_peers = Vec::with_capacity(peers.len());
    for peer in peers {
        let addr = peer["addr"].as_str().unwrap_or_default();
        let network = peer["network"].as_str().unwrap_or("unknown");
        if addr.is_empty() {
            continue;
        }

        let identity = peer_identity(addr, network);

        // Skip peers with unknown network types to avoid identity collisions.
        if !identity.network.is_known() {
            continue;
        }

        let subversion = peer["subver"].as_str().unwrap_or("").to_string();
        let version = peer["version"].as_i64().unwrap_or(0);
        let services = peer["servicesnames"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                peer["services"]
                    .as_str()
                    .unwrap_or("0x0000000000000000")
                    .to_string()
            });

        parsed_peers.push(ParsedPeer {
            address: identity.address,
            network: identity.network.as_str().to_string(),
            addr_with_port: addr.to_string(),
            inbound: peer["inbound"].as_bool().unwrap_or(false),
            connection_type: peer["connection_type"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            conntime: peer["conntime"].as_i64().unwrap_or(0),
            starting_height: peer["startingheight"].as_i64(),
            synced_headers: peer["synced_headers"].as_i64(),
            synced_blocks: peer["synced_blocks"].as_i64(),
            subversion,
            version,
            services,
        });
    }

    let peer_count = parsed_peers.len();

    // Commit all data atomically in a single transaction
    db.process_host_poll(host, &now, parsed_peers, poll_interval_secs)
        .await?;

    info!(
        host = %host,
        peers_count = peer_count,
        "profile poll completed"
    );

    Ok(())
}
