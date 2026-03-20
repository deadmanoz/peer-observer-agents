use crate::cooldown::DEFAULT_COOLDOWN_SECS;
use crate::state::AppState;
use crate::{debug_logs, parca, profiles, rpc};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;
use std::{env, net::SocketAddr};
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Default HTTP client timeout for Grafana API calls.
pub(crate) const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// Default maximum wall-clock time for a Claude CLI investigation.
pub(crate) const DEFAULT_CLAUDE_TIMEOUT_SECS: u64 = 600;

/// Default maximum number of concurrent Claude investigations.
pub(crate) const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Fully resolved runtime configuration, ready to start the server.
pub(crate) struct RuntimeConfig {
    pub(crate) listen_addr: SocketAddr,
    pub(crate) state: AppState,
}

/// Parse all `ANNOTATION_AGENT_*` env vars, build clients, and return a
/// [`RuntimeConfig`] ready for the HTTP server.
pub(crate) fn load() -> Result<RuntimeConfig> {
    let listen_addr: SocketAddr = env::var("ANNOTATION_AGENT_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9099".to_string())
        .parse()
        .context("invalid listen address")?;

    let http_timeout_secs: u64 = env::var("ANNOTATION_AGENT_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS);

    let claude_timeout_secs: u64 = env::var("ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CLAUDE_TIMEOUT_SECS);

    let max_concurrent: usize = env::var("ANNOTATION_AGENT_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONCURRENT)
        .max(1); // Prevent deadlock: 0 permits would block all investigations forever.

    let cooldown_secs: u64 = env::var("ANNOTATION_AGENT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_COOLDOWN_SECS);

    // Bitcoin Core RPC client: enabled when ANNOTATION_AGENT_RPC_HOSTS is set.
    // Partial/malformed config fails fast at startup.
    let rpc_client = match env::var("ANNOTATION_AGENT_RPC_HOSTS") {
        Ok(hosts_json) => {
            let rpc_password = env::var("ANNOTATION_AGENT_RPC_PASSWORD").context(
                "ANNOTATION_AGENT_RPC_PASSWORD must be set when ANNOTATION_AGENT_RPC_HOSTS is set",
            )?;
            anyhow::ensure!(
                !rpc_password.is_empty(),
                "ANNOTATION_AGENT_RPC_PASSWORD must not be empty"
            );
            let rpc_user = env::var("ANNOTATION_AGENT_RPC_USER")
                .unwrap_or_else(|_| "rpc-extractor".to_string());
            anyhow::ensure!(
                !rpc_user.is_empty(),
                "ANNOTATION_AGENT_RPC_USER must not be empty"
            );
            let rpc_port: u16 = match env::var("ANNOTATION_AGENT_RPC_PORT") {
                Ok(v) => {
                    let p: u16 = v.parse().with_context(|| {
                        format!("ANNOTATION_AGENT_RPC_PORT '{v}' is not a valid port number")
                    })?;
                    anyhow::ensure!(p != 0, "ANNOTATION_AGENT_RPC_PORT must not be 0");
                    p
                }
                Err(_) => 9000,
            };
            let client = rpc::RpcClient::new(&hosts_json, rpc_user, rpc_password, rpc_port)
                .context("invalid RPC configuration")?;
            info!("RPC prefetch enabled");
            Some(client)
        }
        Err(_) => {
            info!("RPC prefetch disabled (ANNOTATION_AGENT_RPC_HOSTS not set)");
            None
        }
    };

    // Parca profiling client: enabled when ANNOTATION_AGENT_PARCA_HOSTS is set.
    // Each node runs its own Parca server; PARCA_HOSTS maps alert host names to
    // per-node Parca base URLs.
    let parca_client = match env::var("ANNOTATION_AGENT_PARCA_HOSTS") {
        Ok(hosts_json) => {
            let profile_type = env::var("ANNOTATION_AGENT_PARCA_PROFILE_TYPE")
                .context("ANNOTATION_AGENT_PARCA_PROFILE_TYPE required when PARCA_HOSTS is set")?;
            let process_filter = env::var("ANNOTATION_AGENT_PARCA_PROCESS_FILTER").context(
                "ANNOTATION_AGENT_PARCA_PROCESS_FILTER required when PARCA_HOSTS is set \
                 (e.g., comm=\"bitcoind\")",
            )?;
            let top_n: usize = match env::var("ANNOTATION_AGENT_PARCA_TOP_N") {
                Ok(v) => v
                    .parse()
                    .context("ANNOTATION_AGENT_PARCA_TOP_N must be a positive integer")?,
                Err(_) => 15,
            };
            let client = parca::ParcaClient::new(&hosts_json, profile_type, process_filter, top_n)
                .context("invalid Parca configuration")?;
            info!("Parca profiling prefetch enabled");
            Some(client)
        }
        Err(_) => None,
    };

    // Debug log client: enabled when ANNOTATION_AGENT_DEBUG_LOGS_ENABLED is set.
    // Requires RPC_HOSTS for WireGuard IP mapping and nginx port.
    let debug_log_client = match env::var("ANNOTATION_AGENT_DEBUG_LOGS_ENABLED") {
        Ok(v) if v == "true" || v == "1" => {
            let Some(ref rpc) = rpc_client else {
                anyhow::bail!(
                    "ANNOTATION_AGENT_DEBUG_LOGS_ENABLED requires ANNOTATION_AGENT_RPC_HOSTS \
                     (debug logs are fetched from the same WireGuard nginx as RPC)"
                );
            };
            let max_bytes: u64 = env::var("ANNOTATION_AGENT_DEBUG_LOGS_MAX_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1_048_576);
            let window_secs: u64 = env::var("ANNOTATION_AGENT_DEBUG_LOGS_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300);
            let max_lines: usize = env::var("ANNOTATION_AGENT_DEBUG_LOGS_MAX_LINES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(200);
            let client = debug_logs::DebugLogClient::new(
                rpc.hosts().clone(),
                rpc.port(),
                max_bytes,
                window_secs,
                max_lines,
            )?;
            info!("debug log prefetch enabled");
            Some(client)
        }
        _ => None,
    };

    // Peer profiles configuration
    let profiles_poll_interval_secs: u64 = env::var("ANNOTATION_AGENT_PROFILES_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    let profiles_retention_days: u64 = env::var("ANNOTATION_AGENT_PROFILES_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);

    let profile_db = match env::var("ANNOTATION_AGENT_PROFILES_DB") {
        Ok(db_path) if !db_path.is_empty() => {
            let db = profiles::ProfileDb::open(&db_path)
                .with_context(|| format!("failed to open profiles DB at {db_path}"))?;
            if rpc_client.is_none() {
                warn!("profiles DB configured but no RPC hosts — poller disabled");
            }
            info!(path = %db_path, "peer profiles DB opened");
            Some(db)
        }
        _ => {
            info!("peer profiles disabled (ANNOTATION_AGENT_PROFILES_DB not set)");
            None
        }
    };

    let state = AppState {
        grafana_url: env::var("ANNOTATION_AGENT_GRAFANA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9321".to_string()),
        grafana_api_key: {
            let key = env::var("ANNOTATION_AGENT_GRAFANA_API_KEY")
                .context("ANNOTATION_AGENT_GRAFANA_API_KEY must be set")?;
            anyhow::ensure!(
                !key.is_empty(),
                "ANNOTATION_AGENT_GRAFANA_API_KEY must not be empty"
            );
            key
        },
        claude_bin: env::var("ANNOTATION_AGENT_CLAUDE_BIN")
            .unwrap_or_else(|_| "claude".to_string()),
        claude_model: env::var("ANNOTATION_AGENT_CLAUDE_MODEL")
            .unwrap_or_else(|_| "claude-sonnet-4-6".to_string()),
        mcp_config: {
            let path = env::var("ANNOTATION_AGENT_MCP_CONFIG")
                .context("ANNOTATION_AGENT_MCP_CONFIG must be set")?;
            anyhow::ensure!(
                std::path::Path::new(&path).exists(),
                "ANNOTATION_AGENT_MCP_CONFIG path does not exist: {path}"
            );
            path
        },
        log_file: env::var("ANNOTATION_AGENT_LOG_FILE")
            .ok()
            .filter(|v| !v.is_empty()),
        viewer_auth_token: env::var("ANNOTATION_AGENT_VIEWER_AUTH_TOKEN")
            .ok()
            .filter(|v| !v.is_empty()),
        log_write_mutex: tokio::sync::Mutex::new(()),
        claude_timeout: Duration::from_secs(claude_timeout_secs),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(http_timeout_secs))
            .build()
            .context("failed to build HTTP client")?,
        rpc_client,
        parca_client,
        debug_log_client,
        investigation_semaphore: Semaphore::new(max_concurrent),
        max_concurrent,
        cooldown: Duration::from_secs(cooldown_secs),
        cooldown_map: std::sync::Mutex::new(HashMap::new()),
        profile_db,
        profiles_poll_interval: Duration::from_secs(profiles_poll_interval_secs),
        profiles_retention_days,
    };

    Ok(RuntimeConfig { listen_addr, state })
}
