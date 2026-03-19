//! API endpoints for peer profiles — `/api/peers`, `/api/peers/{id}`, `/api/peers/stats`.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use super::db::ProfileDb;
use crate::state::AppState;
use crate::viewer::check_auth;

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;

#[derive(Debug, Deserialize)]
pub(crate) struct PeersQuery {
    network: Option<String>,
    host: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Wrap a JSON value with `Cache-Control: no-store` to prevent caching of authenticated data.
fn json_no_cache(value: serde_json::Value) -> impl IntoResponse {
    ([("cache-control", "no-store")], Json(value))
}

fn get_db_and_auth(state: &AppState, headers: &HeaderMap) -> Result<Arc<ProfileDb>, StatusCode> {
    let db = state.profile_db.as_ref().ok_or(StatusCode::NOT_FOUND)?;
    let token = state
        .viewer_auth_token
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    check_auth(headers, token)?;
    Ok(Arc::clone(db))
}

/// `GET /api/peers` — list peer summaries with optional filters.
pub(crate) async fn api_peers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<PeersQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let db = get_db_and_auth(&state, &headers)?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let peers = db
        .list_peers(
            params.network.as_deref(),
            params.host.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list peers");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(json_no_cache(serde_json::to_value(peers).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize peers");
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// `GET /api/peers/stats` — aggregate stats.
pub(crate) async fn api_peers_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let db = get_db_and_auth(&state, &headers)?;

    let configured_hosts = state
        .rpc_client
        .as_ref()
        .map(|c| c.host_names())
        .unwrap_or_default();

    let poll_interval = state.profiles_poll_interval.as_secs();

    let stats = db
        .get_stats(configured_hosts, poll_interval)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get profile stats");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(json_no_cache(serde_json::to_value(stats).map_err(|e| {
        tracing::error!(error = %e, "failed to serialize stats");
        StatusCode::INTERNAL_SERVER_ERROR
    })?))
}

/// `GET /api/peers/{id}` — full peer profile.
pub(crate) async fn api_peer_detail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let db = get_db_and_auth(&state, &headers)?;

    let profile = db.get_peer_profile(peer_id).await.map_err(|e| {
        tracing::error!(error = %e, peer_id = peer_id, "failed to get peer profile");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match profile {
        Some(p) => Ok(json_no_cache(serde_json::to_value(p).map_err(|e| {
            tracing::error!(error = %e, peer_id = peer_id, "failed to serialize peer profile");
            StatusCode::INTERNAL_SERVER_ERROR
        })?)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// `GET /peers` — serves the self-contained HTML peer profiles viewer.
///
/// Intentionally unauthenticated: the HTML shell contains no profile data.
/// The bearer token is entered client-side and passed via `Authorization` header
/// on `/api/peers/*` fetch calls.
pub(crate) async fn peers_page(
    State(state): State<Arc<AppState>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    if state.profile_db.is_none() || state.viewer_auth_token.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok((
        [
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            (
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
            ),
        ],
        axum::response::Html(include_str!("viewer.html")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::ProfileDb;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state_with_db(db: Arc<ProfileDb>) -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("test-token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: Some(db),
            profiles_poll_interval: std::time::Duration::from_secs(300),
            profiles_retention_days: 90,
        })
    }

    fn test_state_without_db() -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            parca_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("test-token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: std::time::Duration::from_secs(300),
            profiles_retention_days: 90,
        })
    }

    fn profiles_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/peers", get(peers_page))
            .route("/api/peers", get(api_peers))
            .route("/api/peers/stats", get(api_peers_stats))
            .route("/api/peers/{id}", get(api_peer_detail))
            .with_state(state)
    }

    #[tokio::test]
    async fn peers_page_returns_html_when_enabled() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();
        let app = profiles_router(test_state_with_db(db));

        let req = Request::builder()
            .method("GET")
            .uri("/peers")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Peer Profiles"));
        assert!(html.contains(r#"id="version-badge""#));
    }

    #[tokio::test]
    async fn peers_page_returns_404_when_no_db() {
        let app = profiles_router(test_state_without_db());

        let req = Request::builder()
            .method("GET")
            .uri("/peers")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_peers_requires_auth() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();
        let app = profiles_router(test_state_with_db(db));

        // No auth header
        let req = Request::builder()
            .method("GET")
            .uri("/api/peers")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid auth
        let req = Request::builder()
            .method("GET")
            .uri("/api/peers")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_peers_returns_correct_field_names() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();

        // Insert a peer via process_host_poll
        let peers = vec![super::super::models::ParsedPeer {
            address: "1.2.3.4".into(),
            network: "ipv4".into(),
            addr_with_port: "1.2.3.4:8333".into(),
            inbound: false,
            connection_type: "outbound-full-relay".into(),
            conntime: 1000,
            starting_height: Some(800000),
            synced_headers: Some(800000),
            synced_blocks: Some(800000),
            subversion: "/Satoshi:27.0.0/".into(),
            version: 270000,
            services: "0x0409".into(),
        }];
        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers, 300)
            .await
            .unwrap();

        let app = profiles_router(test_state_with_db(db));

        let req = Request::builder()
            .method("GET")
            .uri("/api/peers")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let peers = data.as_array().expect("should be an array");
        assert_eq!(peers.len(), 1);

        let p = &peers[0];
        // Verify field names match what viewer.html expects
        assert!(p.get("peer_id").is_some(), "missing peer_id");
        assert!(p.get("address").is_some(), "missing address");
        assert!(p.get("network").is_some(), "missing network");
        assert!(
            p.get("observation_count").is_some(),
            "missing observation_count"
        );
        assert!(
            p.get("active_on_hosts").is_some(),
            "missing active_on_hosts"
        );
        assert!(
            p["active_on_hosts"].is_array(),
            "active_on_hosts should be array"
        );
        assert!(
            p.get("latest_subversion").is_some(),
            "missing latest_subversion"
        );
    }

    #[tokio::test]
    async fn api_peers_stats_returns_correct_field_names() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();
        let app = profiles_router(test_state_with_db(db));

        let req = Request::builder()
            .method("GET")
            .uri("/api/peers/stats")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify field names match what viewer.html expects
        assert!(data.get("total_peers").is_some(), "missing total_peers");
        assert!(
            data.get("total_observations").is_some(),
            "missing total_observations"
        );
        assert!(
            data.get("peers_by_network").is_some(),
            "missing peers_by_network"
        );
        assert!(
            data["peers_by_network"].is_array(),
            "peers_by_network should be array"
        );
        assert!(
            data.get("active_windows").is_some(),
            "missing active_windows"
        );
        assert!(data.get("hosts").is_some(), "missing hosts");
    }

    #[tokio::test]
    async fn api_peer_detail_returns_nested_structure() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();

        let peers = vec![super::super::models::ParsedPeer {
            address: "1.2.3.4".into(),
            network: "ipv4".into(),
            addr_with_port: "1.2.3.4:8333".into(),
            inbound: false,
            connection_type: "outbound-full-relay".into(),
            conntime: 1000,
            starting_height: Some(800000),
            synced_headers: Some(800000),
            synced_blocks: Some(800000),
            subversion: "/Satoshi:27.0.0/".into(),
            version: 270000,
            services: "0x0409".into(),
        }];
        db.process_host_poll("host1", "2025-01-01T00:00:00Z", peers, 300)
            .await
            .unwrap();

        let app = profiles_router(test_state_with_db(db));

        let req = Request::builder()
            .method("GET")
            .uri("/api/peers/1")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify nested structure matches what viewer.html expects
        assert!(data.get("peer").is_some(), "missing nested peer object");
        let peer = &data["peer"];
        assert!(peer.get("address").is_some(), "missing peer.address");
        assert!(peer.get("network").is_some(), "missing peer.network");
        assert!(peer.get("first_seen").is_some(), "missing peer.first_seen");

        assert!(
            data.get("recent_observations").is_some(),
            "missing recent_observations"
        );
        assert!(data["recent_observations"].is_array());

        assert!(
            data.get("software_history").is_some(),
            "missing software_history"
        );
        assert!(data["software_history"].is_array());

        assert!(
            data.get("presence_windows").is_some(),
            "missing presence_windows"
        );
        assert!(data["presence_windows"].is_array());

        // Verify observation field names
        let obs = &data["recent_observations"][0];
        assert!(
            obs.get("inbound").is_some(),
            "missing obs.inbound (not 'direction')"
        );
        assert!(obs.get("observed_at").is_some(), "missing obs.observed_at");
        assert!(
            obs.get("synced_headers").is_some(),
            "missing obs.synced_headers"
        );
        assert!(
            obs.get("synced_blocks").is_some(),
            "missing obs.synced_blocks"
        );

        // Verify presence window field names
        let pw = &data["presence_windows"][0];
        assert!(
            pw.get("closed").is_some(),
            "missing pw.closed (not 'status')"
        );
        assert!(pw.get("host").is_some(), "missing pw.host");
    }

    #[tokio::test]
    async fn api_peer_detail_returns_404_for_missing() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let db = ProfileDb::open(&f.path().to_string_lossy()).unwrap();
        let app = profiles_router(test_state_with_db(db));

        let req = Request::builder()
            .method("GET")
            .uri("/api/peers/999")
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
