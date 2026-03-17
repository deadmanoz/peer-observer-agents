//! `/logs` HTML page — serves the self-contained log viewer.

use axum::{extract::State, http::StatusCode, response::Html};
use std::sync::Arc;

use crate::state::AppState;

/// `GET /logs` — serves the self-contained HTML log viewer.
///
/// Intentionally unauthenticated: the HTML shell contains no investigation data.
/// The bearer token is entered client-side and passed via `Authorization` header
/// on `/api/logs` fetch calls. This means unauthenticated visitors can see that
/// the viewer exists and learn the API endpoint URL, but cannot access log data
/// without a valid token.
pub(crate) async fn logs_page(
    State(state): State<Arc<AppState>>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    // Feature gate: only serve when both log file and auth token are configured.
    // This is NOT an auth check — see doc comment above.
    if state.viewer_auth_token.is_none() || state.log_file.is_none() {
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
        Html(include_str!("../viewer.html")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logs_page_returns_html_when_enabled() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some("/tmp/test.jsonl".into()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: std::time::Duration::from_secs(300),
            profiles_retention_days: 90,
        });

        let app = Router::new()
            .route("/logs", get(logs_page))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/logs")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Annotation Log"));
    }

    #[tokio::test]
    async fn logs_page_returns_404_when_disabled() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        // No viewer_auth_token
        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some("/tmp/test.jsonl".into()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: None,
            log_write_mutex: tokio::sync::Mutex::new(()),
            profile_db: None,
            profiles_poll_interval: std::time::Duration::from_secs(300),
            profiles_retention_days: 90,
        });

        let app = Router::new()
            .route("/logs", get(logs_page))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/logs")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
