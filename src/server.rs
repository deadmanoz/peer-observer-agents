use crate::config::RuntimeConfig;
use crate::correlation::AlertId;
use crate::state::AppState;
use crate::types::AlertmanagerPayload;
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Start the HTTP server with all configured routes.
pub(crate) async fn run(config: RuntimeConfig) -> Result<()> {
    let listen_addr = config.listen_addr;
    let state = Arc::new(config.state);

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
        crate::profiles::poller::start_poller(
            Arc::clone(db),
            Arc::new(rpc.clone()),
            state.profiles_poll_interval,
            state.profiles_retention_days,
        );
        info!(
            poll_interval_secs = state.profiles_poll_interval.as_secs(),
            retention_days = state.profiles_retention_days,
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
            .route("/logs", get(crate::viewer::logs_page))
            .route("/api/logs", get(crate::viewer::api_logs));
        info!("viewer enabled at /logs and /api/logs");
    }

    if viewer_enabled || profiles_viewer_enabled {
        app = app
            .route("/", get(home_page))
            .route("/api/version", get(api_version))
            .route("/api/status", get(api_status));
    }

    if profiles_viewer_enabled {
        app = app
            .route("/peers", get(crate::profiles::api::peers_page))
            .route("/api/peers", get(crate::profiles::api::api_peers))
            .route(
                "/api/peers/stats",
                get(crate::profiles::api::api_peers_stats),
            )
            .route(
                "/api/peers/{id}",
                get(crate::profiles::api::api_peer_detail),
            );
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
    crate::viewer::check_auth(&headers, token)?;
    Ok((
        [("cache-control", "no-store")],
        Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") })),
    ))
}

async fn home_page() -> impl axum::response::IntoResponse {
    (
        [
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            ("content-security-policy", crate::viewer::VIEWER_CSP),
        ],
        Html(include_str!("home.html")),
    )
}

async fn api_status(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let token = state
        .viewer_auth_token
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    crate::viewer::check_auth(&headers, token)?;

    // Build hosts from the union of all configured sources so Parca-only
    // or RPC-only deployments still surface per-node visibility.
    let mut host_map: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();

    let debug_log_enabled = state.debug_log_client.is_some();

    if let Some(ref rpc) = state.rpc_client {
        for (name, ip) in rpc.hosts() {
            host_map.insert(
                name.clone(),
                serde_json::json!({
                    "name": name,
                    "ip": ip.to_string(),
                    "rpc": true,
                    "parca": false,
                    "debug_log": debug_log_enabled,
                }),
            );
        }
    }

    if let Some(ref parca) = state.parca_client {
        for name in parca.host_names() {
            host_map
                .entry(name.clone())
                .and_modify(|h| h["parca"] = serde_json::json!(true))
                .or_insert_with(|| {
                    serde_json::json!({
                        "name": name,
                        "ip": "",
                        "rpc": false,
                        "parca": true,
                        "debug_log": false,
                    })
                });
        }
    }

    let hosts: Vec<_> = host_map.into_values().collect();

    Ok((
        [("cache-control", "no-store")],
        Json(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "features": {
                "rpc": state.rpc_client.is_some(),
                "parca": state.parca_client.is_some(),
                "debug_logs": state.debug_log_client.is_some(),
                "profiles": state.profile_db.is_some(),
                "viewer": state.log_file.is_some(),
            },
            "hosts": hosts,
            "cooldown_secs": state.cooldown.as_secs(),
            "max_concurrent": state.max_concurrent,
            "claude_timeout_secs": state.claude_timeout.as_secs(),
            "claude_model": state.claude_model,
        })),
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
            if let Err(e) = crate::processor::process_alert(&state, &alert, &aid).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cooldown::{CooldownKey, CooldownState};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(crate::config::DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(crate::config::DEFAULT_MAX_CONCURRENT),
            max_concurrent: crate::config::DEFAULT_MAX_CONCURRENT,
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
            claude_timeout: Duration::from_secs(crate::config::DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(crate::config::DEFAULT_MAX_CONCURRENT),
            max_concurrent: crate::config::DEFAULT_MAX_CONCURRENT,
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

        let state = test_state_with_cooldown(
            ("TestAlert".into(), "unknown".into(), String::new()),
            CooldownState::Completed(Instant::now()),
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
            "recently-completed alert should be suppressed and return 200"
        );
    }

    #[tokio::test]
    async fn webhook_suppresses_inflight_alert() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

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
            claude_timeout: Duration::from_secs(crate::config::DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            debug_log_client: None,
            investigation_semaphore: Semaphore::new(crate::config::DEFAULT_MAX_CONCURRENT),
            max_concurrent: crate::config::DEFAULT_MAX_CONCURRENT,
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
