mod annotation;
mod cooldown;
mod correlation;
mod debug_logs;
mod grafana;
mod investigation;
mod parca;
mod profiles;
mod prompt;
mod rpc;
mod state;
mod types;
mod viewer;

use crate::annotation::{
    parse_structured_annotation, render_annotation_html, sanitize_raw_fallback, AnnotationError,
    POLICY_VIOLATION_STUB,
};
use crate::cooldown::{try_claim_cooldown, CooldownKey, SuppressReason, DEFAULT_COOLDOWN_SECS};
use crate::correlation::AlertId;
use crate::grafana::post_grafana_annotation;
use crate::investigation::call_claude;
use crate::state::AppState;
use crate::types::AlertmanagerPayload;
use crate::viewer::{LogEntry, Telemetry};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

/// Default HTTP client timeout for Grafana API calls.
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// Default maximum wall-clock time for a Claude CLI investigation.
const DEFAULT_CLAUDE_TIMEOUT_SECS: u64 = 600;

/// Default maximum number of concurrent Claude investigations.
const DEFAULT_MAX_CONCURRENT: usize = 4;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "peer_observer_agent=info".into()),
        )
        .init();

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

    let state = Arc::new(AppState {
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
        cooldown: Duration::from_secs(cooldown_secs),
        cooldown_map: std::sync::Mutex::new(HashMap::new()),
        profile_db,
        profiles_poll_interval: Duration::from_secs(profiles_poll_interval_secs),
        profiles_retention_days,
    });

    if state.cooldown.is_zero() {
        info!("cooldown suppression disabled");
    } else {
        info!(
            cooldown_secs = state.cooldown.as_secs(),
            "cooldown suppression enabled"
        );
    }

    // Start profiles poller if both DB and RPC are configured
    if let (Some(ref db), Some(ref rpc)) = (&state.profile_db, &state.rpc_client) {
        profiles::poller::start_poller(
            Arc::clone(db),
            Arc::new(rpc.clone()),
            state.profiles_poll_interval,
            state.profiles_retention_days,
        );
        info!(
            poll_interval_secs = profiles_poll_interval_secs,
            retention_days = profiles_retention_days,
            "peer profiles poller started"
        );
    }

    let viewer_enabled = state.log_file.is_some() && state.viewer_auth_token.is_some();
    let profiles_viewer_enabled = state.profile_db.is_some() && state.viewer_auth_token.is_some();

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/webhook", post(handle_webhook));

    if viewer_enabled {
        app = app
            .route("/logs", get(viewer::logs_page))
            .route("/api/logs", get(viewer::api_logs));
        info!("viewer enabled at /logs and /api/logs");
    }

    if viewer_enabled || profiles_viewer_enabled {
        app = app.route("/api/version", get(api_version));
    }

    if profiles_viewer_enabled {
        app = app
            .route("/peers", get(profiles::api::peers_page))
            .route("/api/peers", get(profiles::api::api_peers))
            .route("/api/peers/stats", get(profiles::api::api_peers_stats))
            .route("/api/peers/{id}", get(profiles::api::api_peer_detail));
        info!("peer profiles viewer enabled at /peers and /api/peers/*");
    }

    let app = app.with_state(state);

    info!("annotation-agent listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn api_version(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let token = state
        .viewer_auth_token
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    viewer::check_auth(&headers, token)?;
    Ok((
        [("cache-control", "no-store")],
        Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })),
    ))
}

async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertmanagerPayload>,
) -> StatusCode {
    let firing: Vec<_> = payload
        .alerts
        .into_iter()
        .filter(|a| a.status == "firing")
        .collect();
    info!("received webhook with {} firing alerts", firing.len());

    // Process all firing alerts concurrently (but not detached — we await
    // them so failures propagate back as HTTP 500, preserving Alertmanager's
    // retry semantics).
    let mut tasks = JoinSet::new();
    for alert in firing {
        let state = Arc::clone(&state);
        tasks.spawn(async move {
            let aid = AlertId::from_alert(&alert);
            if let Err(e) = process_alert(&state, &alert, &aid).await {
                error!(alert_id = %aid, "failed to process alert: {e:#}");
                return Err(());
            }
            Ok(())
        });
    }

    let mut had_failure = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Err(())) | Err(_) => had_failure = true,
            Ok(Ok(())) => {}
        }
    }

    if had_failure {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

async fn process_alert(state: &AppState, alert: &types::Alert, aid: &AlertId) -> Result<()> {
    // Cooldown suppression: coalesce retriggers of the same (alertname, host, threadname)
    // within the cooldown window. Checked before the semaphore to avoid holding
    // a concurrency slot for suppressed alerts.
    let cooldown_guard = if !state.cooldown.is_zero() {
        let key: CooldownKey = (
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
        );
        match try_claim_cooldown(key, &state.cooldown_map, state.cooldown) {
            Ok(guard) => Some(guard),
            Err(SuppressReason::InFlight) => {
                info!(alert_id = %aid, "skipping: investigation already in flight");
                return Ok(());
            }
            Err(SuppressReason::RecentlyCompleted { ago }) => {
                info!(
                    alert_id = %aid,
                    cooldown_secs = state.cooldown.as_secs(),
                    elapsed_secs = ago.as_secs(),
                    "skipping: recent investigation within cooldown window"
                );
                return Ok(());
            }
        }
    } else {
        None
    };

    let _permit = state
        .investigation_semaphore
        .acquire()
        .await
        .context("investigation semaphore closed")?;
    let claude_output = call_claude(state, alert, aid).await?;
    let telemetry = Telemetry::from(&claude_output);

    match parse_structured_annotation(&claude_output.result) {
        Ok(ann) => {
            let html = render_annotation_html(&ann);
            post_grafana_annotation(state, alert, aid, &html, Some(&ann.verdict)).await?;
            append_log(state, alert, aid, Some(&ann), None, &telemetry).await;
            info!(alert_id = %aid, verdict = %ann.verdict, "annotation posted successfully");
        }
        Err(AnnotationError::PolicyViolation(msg)) => {
            // Structured path detected a policy violation (e.g., via deserialized
            // fields that resolved JSON Unicode escapes). Force redaction regardless
            // of whether the raw scan also catches it.
            warn!(
                alert_id = %aid,
                error = %msg,
                "structured annotation rejected by peer-intervention policy"
            );
            // Log full original output for forensic audit — only to tracing,
            // never persisted in Grafana or the /logs viewer.
            warn!(
                alert_id = %aid,
                raw_output = %claude_output.result,
                "original output for policy violation (not posted to Grafana)"
            );
            post_grafana_annotation(
                state,
                alert,
                aid,
                &format!("<b>POLICY VIOLATION:</b> {POLICY_VIOLATION_STUB}"),
                None,
            )
            .await?;
            append_log(
                state,
                alert,
                aid,
                None,
                Some(POLICY_VIOLATION_STUB),
                &telemetry,
            )
            .await;
            info!(alert_id = %aid, "annotation posted (policy violation stub)");
        }
        Err(AnnotationError::ParseError(e)) => {
            warn!(
                alert_id = %aid,
                error = %e,
                "failed to parse structured annotation, using raw text"
            );
            let fallback = sanitize_raw_fallback(&claude_output.result);
            if fallback.policy_violated {
                warn!(
                    alert_id = %aid,
                    pattern = fallback.matched_pattern.unwrap_or("unknown"),
                    "raw annotation redacted: peer-intervention command detected"
                );
                // Forensic audit — mirrors the structured PolicyViolation path.
                warn!(
                    alert_id = %aid,
                    raw_output = %claude_output.result,
                    "original output for policy violation (not posted to Grafana)"
                );
            }
            post_grafana_annotation(state, alert, aid, &fallback.grafana_body, None).await?;
            append_log(
                state,
                alert,
                aid,
                None,
                Some(&fallback.log_text),
                &telemetry,
            )
            .await;
            if fallback.policy_violated {
                info!(alert_id = %aid, "annotation posted (policy violation stub)");
            } else {
                info!(alert_id = %aid, "annotation posted successfully (raw fallback)");
            }
        }
    }

    // Mark cooldown as completed only after both Claude AND Grafana succeed.
    // If Grafana fails, the guard drops without complete(), clearing the
    // InFlight entry so Alertmanager retries are not suppressed.
    //
    // Trade-off: during a sustained Grafana outage, every Alertmanager retry
    // re-invokes Claude (expensive) because the cooldown is never committed.
    // This is intentional — the alternative (completing after Claude only)
    // silently drops annotations when Grafana recovers, because the cooldown
    // suppresses the retry before `annotation_exists` is ever reached.
    if let Some(guard) = cooldown_guard {
        guard.complete();
    }

    Ok(())
}

async fn append_log(
    state: &AppState,
    alert: &types::Alert,
    aid: &AlertId,
    ann: Option<&annotation::StructuredAnnotation>,
    raw_text: Option<&str>,
    telemetry: &Telemetry,
) {
    let Some(ref path) = state.log_file else {
        return;
    };
    let entry = match ann {
        Some(ann) => LogEntry::structured(
            alert.starts_at,
            aid.to_string(),
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
            ann.verdict.as_tag(),
            ann.action.clone(),
            ann.summary.clone(),
            ann.cause.clone(),
            ann.scope.clone(),
            ann.evidence.clone(),
            telemetry.clone(),
        ),
        None => LogEntry::raw_fallback(
            alert.starts_at,
            aid.to_string(),
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
            raw_text.unwrap_or("").to_string(),
            telemetry.clone(),
        ),
    };
    viewer::append_jsonl_log(path, &entry, &state.log_write_mutex).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cooldown::CooldownState;
    use std::time::Instant;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(DEFAULT_MAX_CONCURRENT),
            cooldown: Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(HashMap::new()),
            viewer_auth_token: None,
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: Duration::from_secs(300),
            profiles_retention_days: 90,
        })
    }

    // ── Webhook handler (integration test with axum) ───────────────────

    #[tokio::test]
    async fn webhook_returns_ok_for_resolved_only() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        // Only resolved alerts — should return 200 with no processing
        let body = r#"{"alerts": [{"status": "resolved", "labels": {}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn webhook_returns_error_when_processing_fails() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        // A firing alert that will fail (claude_bin is "echo", Grafana is unreachable)
        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "firing alert with unreachable backends should return 500"
        );
    }

    #[tokio::test]
    async fn webhook_rejects_invalid_payload() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Build a test state with cooldown enabled and a pre-populated cooldown map.
    fn test_state_with_cooldown(key: CooldownKey, entry: CooldownState) -> Arc<AppState> {
        let mut map = HashMap::new();
        map.insert(key, entry);
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(DEFAULT_MAX_CONCURRENT),
            cooldown: Duration::from_secs(1800),
            cooldown_map: std::sync::Mutex::new(map),
            viewer_auth_token: None,
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: Duration::from_secs(300),
            profiles_retention_days: 90,
        })
    }

    #[tokio::test]
    async fn webhook_suppresses_recently_completed_alert() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Pre-populate: TestAlert on "unknown" host was just investigated.
        let state = test_state_with_cooldown(
            ("TestAlert".into(), "unknown".into(), String::new()),
            CooldownState::Completed(Instant::now()),
        );
        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(state);

        // Same alert fires again — without cooldown this would return 500
        // (unreachable Claude/Grafana), but cooldown suppresses it → 200.
        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "recently-completed alert should be suppressed and return 200"
        );
    }

    #[tokio::test]
    async fn webhook_suppresses_inflight_alert() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Pre-populate: TestAlert on "unknown" host is currently being investigated.
        let state = test_state_with_cooldown(
            ("TestAlert".into(), "unknown".into(), String::new()),
            CooldownState::InFlight,
        );
        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(state);

        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "in-flight alert should be suppressed and return 200"
        );
    }

    // ── Health endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn healthz_returns_ok() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── /api/version endpoint ─────────────────────────────────────────

    fn test_state_with_auth() -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(DEFAULT_MAX_CONCURRENT),
            cooldown: Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(HashMap::new()),
            viewer_auth_token: Some("test-token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: Duration::from_secs(300),
            profiles_retention_days: 90,
        })
    }

    #[tokio::test]
    async fn api_version_returns_version_when_authenticated() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/api/version", get(api_version))
            .with_state(test_state_with_auth());

        let req = Request::builder()
            .method("GET")
            .uri("/api/version")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn api_version_returns_401_without_auth() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/api/version", get(api_version))
            .with_state(test_state_with_auth());

        let req = Request::builder()
            .method("GET")
            .uri("/api/version")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn api_version_returns_404_when_no_viewer() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // test_state() has viewer_auth_token: None
        let app = Router::new()
            .route("/api/version", get(api_version))
            .with_state(test_state());

        let req = Request::builder()
            .method("GET")
            .uri("/api/version")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
