//! `/api/logs` endpoint — reads the JSONL log file, applies server-side filters,
//! returns newest-first entries as pure JSONL.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tracing::warn;

use super::cursor::{decode_cursor, encode_cursor, HeapEntry};
use super::log_schema::{EntryKind, LogEntry};
use crate::state::AppState;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
pub(crate) struct LogsQuery {
    limit: Option<usize>,
    before_cursor: Option<String>,
    verdict: Option<String>,
    host: Option<String>,
    alertname: Option<String>,
    threadname: Option<String>,
    /// Inclusive lower bound on `logged_at` (RFC 3339 with offset).
    /// Entries with `logged_at >= logged_after` pass.
    logged_after: Option<String>,
    /// Exclusive upper bound on `logged_at` (RFC 3339 with offset).
    /// Entries with `logged_at < logged_before` pass.
    logged_before: Option<String>,
}

/// Validate the Bearer token from the Authorization header.
/// Uses constant-time comparison to prevent timing attacks.
fn check_auth(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // Accept "Bearer" and "bearer" prefixes. Other capitalizations are
    // theoretically valid per RFC 7235 §2.1 but not seen in practice.
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

/// Constant-time byte slice comparison to prevent timing side-channels.
/// Always iterates `expected.len()` times regardless of `submitted` length,
/// so the only timing signal is the expected token's length (which is fixed
/// per deployment, not attacker-controlled). Uses `black_box` to prevent
/// LLVM from proving early-exit optimisations on the accumulator.
fn constant_time_eq(submitted: &[u8], expected: &[u8]) -> bool {
    use std::hint::black_box;
    let mut acc = if submitted.len() == expected.len() {
        0u8
    } else {
        1u8
    };
    for (i, y) in expected.iter().enumerate() {
        acc |= black_box(submitted.get(i).copied().unwrap_or(0) ^ y);
    }
    black_box(acc) == 0
}

/// `GET /api/logs` — reads the JSONL log file, applies server-side filters,
/// returns newest-first entries as pure JSONL (`application/x-ndjson`).
/// Pagination cursor is in the `X-Next-Cursor` response header.
pub(crate) async fn api_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<LogsQuery>,
) -> Result<axum::response::Response, StatusCode> {
    use axum::response::IntoResponse;

    let token = state
        .viewer_auth_token
        .as_deref()
        .ok_or(StatusCode::NOT_FOUND)?;
    check_auth(&headers, token)?;

    let path = state.log_file.as_deref().ok_or(StatusCode::NOT_FOUND)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    // Reject malformed cursors with 400 instead of silently falling back to page 1.
    let before = match &query.before_cursor {
        Some(cursor) => Some(decode_cursor(cursor).ok_or(StatusCode::BAD_REQUEST)?),
        None => None,
    };

    // Parse date range filters. Reject malformed dates with 400.
    // Empty strings are treated as absent (same as omitting the parameter).
    // Parse via FixedOffset to explicitly handle any RFC 3339 offset, then
    // convert to Utc — avoids relying on undocumented DateTime<Utc>::FromStr
    // behaviour for non-UTC offsets.
    let logged_after: Option<DateTime<Utc>> = match &query.logged_after {
        Some(s) if !s.is_empty() => Some(
            s.parse::<chrono::DateTime<chrono::FixedOffset>>()
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        ),
        _ => None,
    };
    let logged_before: Option<DateTime<Utc>> = match &query.logged_before {
        Some(s) if !s.is_empty() => Some(
            s.parse::<chrono::DateTime<chrono::FixedOffset>>()
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        ),
        _ => None,
    };

    // Reject inverted ranges with 400. A zero-width interval [T, T) is valid
    // (returns empty 200), consistent with other no-match filter combinations.
    if let (Some(ref after), Some(ref before)) = (&logged_after, &logged_before) {
        if after > before {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Forward-scan the file, collecting all matching entries.
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // File not created yet (no annotations posted). Return empty page.
            return Ok((
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "application/x-ndjson; charset=utf-8",
                    ),
                    (axum::http::header::CACHE_CONTROL, "no-store"),
                ],
                String::new(),
            )
                .into_response());
        }
        Err(e) => {
            warn!(path, error = %e, "failed to open log file");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();

    // Bounded collection: use a min-heap of size `limit + 1` keyed on
    // (logged_at, alert_id) so we keep the top-N entries by the same total
    // order the cursor uses. Memory is O(limit), not O(total file size).
    // The extra +1 entry lets us detect whether a next page exists.
    let collect_count = limit + 1;
    let mut heap: std::collections::BinaryHeap<std::cmp::Reverse<HeapEntry>> =
        std::collections::BinaryHeap::with_capacity(collect_count + 1);

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break, // EOF
            Err(e) => {
                warn!(path, error = %e, "error reading log file mid-stream");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry: LogEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                warn!(path, error = %e, "skipping malformed JSONL line");
                continue;
            }
        };

        // Apply before_cursor filter — uses the same (logged_at, alert_id)
        // total order as the heap key, so cursor semantics are consistent.
        // INVARIANT: (logged_at, alert_id) must be unique across entries.
        // logged_at is Utc::now() at append time (nanosecond resolution) and
        // alert_id includes startsAt, so duplicates are vanishingly unlikely
        // in normal operation. If a duplicate exists, one occurrence will be
        // silently excluded from pagination.
        if let Some((ref cursor_ts, ref cursor_id)) = before {
            if (entry.logged_at, &entry.alert_id) >= (*cursor_ts, cursor_id) {
                continue;
            }
        }

        // Apply date range filters (half-open interval on logged_at).
        if let Some(ref after) = logged_after {
            if entry.logged_at < *after {
                continue;
            }
        }
        if let Some(ref before_ts) = logged_before {
            if entry.logged_at >= *before_ts {
                continue;
            }
        }

        // Apply server-side filters.
        // ?verdict=raw_fallback matches entries with entry_kind == RawFallback.
        // Other verdict values match structured entries by verdict field.
        if let Some(ref v) = query.verdict {
            if v == "raw_fallback" {
                if entry.entry_kind != EntryKind::RawFallback {
                    continue;
                }
            } else {
                match &entry.verdict {
                    Some(ev) if ev == v => {}
                    _ => continue,
                }
            }
        }
        if let Some(ref h) = query.host {
            if entry.host != *h {
                continue;
            }
        }
        if let Some(ref a) = query.alertname {
            if entry.alertname != *a {
                continue;
            }
        }
        if let Some(ref t) = query.threadname {
            if entry.threadname != *t {
                continue;
            }
        }

        heap.push(std::cmp::Reverse(HeapEntry::from_log_entry(entry)));
        if heap.len() > collect_count {
            heap.pop(); // evict the smallest (oldest by total order)
        }
    }

    // Extract from heap and sort descending by (logged_at, alert_id).
    let mut entries: Vec<LogEntry> = heap
        .into_iter()
        .map(|std::cmp::Reverse(he)| he.entry)
        .collect();
    entries.sort_by(|a, b| (&b.logged_at, &b.alert_id).cmp(&(&a.logged_at, &a.alert_id)));

    // If we collected more than `limit`, there's a next page.
    let has_more = entries.len() > limit;
    entries.truncate(limit);

    // Build pure JSONL body (one LogEntry per line).
    let mut body = String::new();
    for entry in &entries {
        if let Ok(line) = serde_json::to_string(entry) {
            body.push_str(&line);
            body.push('\n');
        }
    }

    // Emit cursor only when there are actually more entries beyond this page.
    let next_cursor = if has_more {
        entries
            .last()
            .map(|e| encode_cursor(&e.logged_at, &e.alert_id))
    } else {
        None
    };

    let mut resp = (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-ndjson; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response();

    if let Some(cursor) = next_cursor {
        if let Ok(hval) = cursor.parse() {
            resp.headers_mut().insert("x-next-cursor", hval);
        }
    }

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::super::log_file::append_jsonl_log;
    use super::super::log_schema::tests::{sample_structured_entry, sample_telemetry};
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn check_auth_valid_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token-123".parse().unwrap());
        assert!(check_auth(&headers, "test-token-123").is_ok());
    }

    #[test]
    fn check_auth_wrong_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());
        assert_eq!(
            check_auth(&headers, "test-token-123"),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn check_auth_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(
            check_auth(&headers, "test-token-123"),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn check_auth_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(
            check_auth(&headers, "test-token-123"),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn api_logs_requires_auth() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-api-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("api-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();

        // Write a test entry
        let entry = sample_structured_entry();
        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(&log_path_str, &entry, &test_mutex).await;

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("secret-token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // No auth header -> 401
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token -> 401
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid token -> 200
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_returns_newest_first() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-order-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("order-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        // Write three entries with different alert_starts_at but sequential logged_at
        let test_mutex = tokio::sync::Mutex::new(());
        for i in 0u32..3 {
            let mut entry = LogEntry::structured(
                Utc.with_ymd_and_hms(2025, 6, 15, 12 + i, 0, 0).unwrap(),
                format!("Alert{}:host:ts", i),
                format!("Alert{}", i),
                "bitcoin-03".into(),
                String::new(),
                "benign",
                None,
                format!("Summary {}", i),
                "cause".into(),
                "scope".into(),
                vec!["e1".into(), "e2".into()],
                sample_telemetry(),
            );
            // Override logged_at to be deterministic
            entry.logged_at = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, i).unwrap();
            append_jsonl_log(&log_path_str, &entry, &test_mutex).await;
        }

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let lines: Vec<&str> = body_str.lines().filter(|l| !l.is_empty()).collect();

        // Pure JSONL: 3 entries, no metadata line
        assert_eq!(lines.len(), 3);

        // Entries should be newest-first (Alert2, Alert1, Alert0)
        let e1: LogEntry = serde_json::from_str(lines[0]).unwrap();
        let e2: LogEntry = serde_json::from_str(lines[1]).unwrap();
        let e3: LogEntry = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(e1.alertname, "Alert2");
        assert_eq!(e2.alertname, "Alert1");
        assert_eq!(e3.alertname, "Alert0");

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_pagination_with_same_timestamp() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-sameTs-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("same-ts-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        // Write 4 entries with the SAME logged_at but different alert_ids.
        // alert_ids are chosen so lexicographic order differs from append order.
        let same_ts = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, 0).unwrap();
        let test_mutex = tokio::sync::Mutex::new(());
        for id in ["Charlie", "Alpha", "Delta", "Bravo"] {
            let mut entry = LogEntry::structured(
                same_ts,
                format!("{}:host:ts", id),
                id.to_string(),
                "bitcoin-03".into(),
                String::new(),
                "benign",
                None,
                format!("Summary {}", id),
                "cause".into(),
                "scope".into(),
                vec!["e1".into(), "e2".into()],
                sample_telemetry(),
            );
            entry.logged_at = same_ts;
            append_jsonl_log(&log_path_str, &entry, &test_mutex).await;
        }

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Page 1: limit=2, should return the two entries with the highest
        // (logged_at, alert_id) — that's Delta and Charlie (descending).
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?limit=2")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cursor = resp
            .headers()
            .get("x-next-cursor")
            .expect("should have cursor when more entries exist")
            .to_str()
            .unwrap()
            .to_string();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let p1: Vec<LogEntry> = body_str
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(p1.len(), 2);
        assert_eq!(p1[0].alertname, "Delta");
        assert_eq!(p1[1].alertname, "Charlie");

        // Page 2: use the cursor from page 1, should get Bravo and Alpha.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/logs?limit=2&before_cursor={}", cursor))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // No more pages — should NOT have X-Next-Cursor
        assert!(
            resp.headers().get("x-next-cursor").is_none(),
            "should not have cursor when no more entries"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let p2: Vec<LogEntry> = body_str
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(p2.len(), 2);
        assert_eq!(p2[0].alertname, "Bravo");
        assert_eq!(p2[1].alertname, "Alpha");

        // Verify no overlap: pages should cover all 4 entries with no duplicates
        let all_names: Vec<&str> = p1
            .iter()
            .chain(p2.iter())
            .map(|e| e.alertname.as_str())
            .collect();
        assert_eq!(all_names, vec!["Delta", "Charlie", "Bravo", "Alpha"]);

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_filters_by_verdict() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-filter-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("filter-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        // Write entries with different verdicts
        let mut benign = sample_structured_entry();
        benign.logged_at = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, 0).unwrap();
        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(&log_path_str, &benign, &test_mutex).await;

        let mut action_required = LogEntry::structured(
            Utc.with_ymd_and_hms(2025, 6, 15, 13, 0, 0).unwrap(),
            "Alert2:host:ts".into(),
            "Alert2".into(),
            "bitcoin-03".into(),
            String::new(),
            "action_required",
            Some("restart node".into()),
            "summary".into(),
            "cause".into(),
            "scope".into(),
            vec!["e1".into(), "e2".into()],
            sample_telemetry(),
        );
        action_required.logged_at = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, 1).unwrap();
        append_jsonl_log(&log_path_str, &action_required, &test_mutex).await;

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?verdict=action_required")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let lines: Vec<&str> = body_str.lines().filter(|l| !l.is_empty()).collect();

        // Pure JSONL: 1 entry (only action_required)
        assert_eq!(lines.len(), 1);
        let entry: LogEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry.verdict.as_deref(), Some("action_required"));

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_filters_by_alertname_and_host() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-alert-host-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("alert-host-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        let test_mutex = tokio::sync::Mutex::new(());

        // Write entries with different alertnames and hosts
        for (i, (alert, host)) in [
            ("BlockStale", "bitcoin-03"),
            ("INVQueue", "bitcoin-03"),
            ("BlockStale", "vps-dev-01"),
            ("INVQueue", "vps-dev-01"),
        ]
        .iter()
        .enumerate()
        {
            let mut entry = LogEntry::structured(
                Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
                format!("{}:{}:ts", alert, host),
                alert.to_string(),
                host.to_string(),
                String::new(),
                "benign",
                None,
                format!("Summary {} {}", alert, host),
                "cause".into(),
                "scope".into(),
                vec!["e1".into()],
                sample_telemetry(),
            );
            entry.logged_at = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, i as u32).unwrap();
            append_jsonl_log(&log_path_str, &entry, &test_mutex).await;
        }

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Filter by alertname only
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?alertname=BlockStale")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<LogEntry> = String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(entries.len(), 2, "should return 2 BlockStale entries");
        assert!(entries.iter().all(|e| e.alertname == "BlockStale"));

        // Filter by host only
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?host=vps-dev-01")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<LogEntry> = String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(entries.len(), 2, "should return 2 vps-dev-01 entries");
        assert!(entries.iter().all(|e| e.host == "vps-dev-01"));

        // Filter by both alertname and host
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?alertname=INVQueue&host=bitcoin-03")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries: Vec<LogEntry> = String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(entries.len(), 1, "should return 1 entry matching both");
        assert_eq!(entries[0].alertname, "INVQueue");
        assert_eq!(entries[0].host, "bitcoin-03");

        // Filter with no matches
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?alertname=NonExistent")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body_str.trim().is_empty(),
            "non-matching filter should return empty body"
        );

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_rejects_invalid_cursor() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-cursor-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("cursor-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();

        let entry = sample_structured_entry();
        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(&log_path_str, &entry, &test_mutex).await;

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Malformed cursor should return 400, not silently fall back to page 1
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?before_cursor=not-a-valid-cursor!!!")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "invalid cursor should return 400"
        );

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_returns_ndjson_content_type() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-ctype-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("ctype-test.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();

        let entry = sample_structured_entry();
        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(&log_path_str, &entry, &test_mutex).await;

        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str.clone()),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-ndjson; charset=utf-8"
        );

        // Cleanup
        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn routes_absent_when_no_log_file() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        use super::super::html::logs_page;

        // No log_file
        let state = Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        });

        let app = Router::new()
            .route("/logs", get(logs_page))
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // /logs returns 404 because log_file is None
        let req = Request::builder()
            .method("GET")
            .uri("/logs")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // /api/logs also returns 404
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Helper: create test entries with deterministic logged_at timestamps.
    /// Returns entries at 20:00:00, 20:00:01, 20:00:02, 20:00:03 on 2025-06-15.
    /// Uses the AppState's log_write_mutex so the lock is the same one the
    /// running server would use.
    async fn write_date_range_entries(state: &AppState) {
        let log_path_str = state.log_file.as_deref().unwrap();
        for i in 0u32..4 {
            let mut entry = LogEntry::structured(
                Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
                format!("Alert{}:host:ts", i),
                format!("Alert{}", i),
                if i < 2 {
                    "bitcoin-03".into()
                } else {
                    "vps-dev-01".into()
                },
                String::new(),
                "benign",
                None,
                format!("Summary {}", i),
                "cause".into(),
                "scope".into(),
                vec!["e1".into()],
                sample_telemetry(),
            );
            entry.logged_at = Utc.with_ymd_and_hms(2025, 6, 15, 20, 0, i).unwrap();
            append_jsonl_log(log_path_str, &entry, &state.log_write_mutex).await;
        }
    }

    fn make_test_state(log_path_str: String) -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: Some(log_path_str),
            claude_timeout: std::time::Duration::from_secs(600),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: tokio::sync::Semaphore::new(4),
            cooldown: std::time::Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(std::collections::HashMap::new()),
            viewer_auth_token: Some("token".into()),
            log_write_mutex: tokio::sync::Mutex::new(()),
        })
    }

    fn parse_ndjson_body(body_bytes: &[u8]) -> Vec<LogEntry> {
        let body_str = std::str::from_utf8(body_bytes).unwrap();
        body_str
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn api_logs_date_range_logged_after_only() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-after-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-after.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // logged_after=20:00:02 — should include entries at :02 and :03 (inclusive lower bound)
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-15T20:00:02Z")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        assert_eq!(entries.len(), 2);
        // Newest first
        assert_eq!(entries[0].alertname, "Alert3");
        assert_eq!(entries[1].alertname, "Alert2");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_logged_before_only() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-before-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-before.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // logged_before=20:00:02 — should include entries at :00 and :01 (exclusive upper bound)
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_before=2025-06-15T20:00:02Z")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].alertname, "Alert1");
        assert_eq!(entries[1].alertname, "Alert0");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_combined() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-combined-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-combined.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Half-open [20:00:01, 20:00:03) — should include entries at :01 and :02
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-15T20:00:01Z&logged_before=2025-06-15T20:00:03Z")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].alertname, "Alert2");
        assert_eq!(entries[1].alertname, "Alert1");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_boundary_semantics() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-boundary-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-boundary.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Exact boundary: logged_after == logged_at of entry at :01 (inclusive, should match)
        // and logged_before == logged_at of entry at :02 (exclusive, should NOT match)
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-15T20:00:01Z&logged_before=2025-06-15T20:00:02Z")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        // Only the entry at exactly :01 should be included
        assert_eq!(
            entries.len(),
            1,
            "half-open [01, 02) should include only :01"
        );
        assert_eq!(entries[0].alertname, "Alert1");

        // Zero-width interval [T, T) — should return empty 200, not 400
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-15T20:00:01Z&logged_before=2025-06-15T20:00:01Z")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        assert_eq!(entries.len(), 0, "zero-width [T, T) should return empty");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_rejects_malformed() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let dir =
            std::env::temp_dir().join(format!("peer-observer-test-dr-bad-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-bad.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();

        let entry = sample_structured_entry();
        let test_mutex = tokio::sync::Mutex::new(());
        append_jsonl_log(&log_path_str, &entry, &test_mutex).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(make_test_state(log_path_str));

        // Malformed logged_after
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=not-a-date")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Malformed logged_before
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_before=2025-13-99")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_with_pagination_and_filters() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-combo-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-combo.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        // Entries: Alert0/bitcoin-03@:00, Alert1/bitcoin-03@:01,
        //          Alert2/vps-dev-01@:02, Alert3/vps-dev-01@:03
        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // Date range [20:00:00, 20:00:03) + host=bitcoin-03 + limit=1 for pagination
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-15T20:00:00Z&logged_before=2025-06-15T20:00:03Z&host=bitcoin-03&limit=1")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cursor = resp
            .headers()
            .get("x-next-cursor")
            .expect("should have cursor")
            .to_str()
            .unwrap()
            .to_string();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let p1 = parse_ndjson_body(&body);
        assert_eq!(p1.len(), 1);
        assert_eq!(p1[0].alertname, "Alert1"); // newest bitcoin-03 in range

        // Page 2 with cursor
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/logs?logged_after=2025-06-15T20:00:00Z&logged_before=2025-06-15T20:00:03Z&host=bitcoin-03&limit=1&before_cursor={}", cursor))
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-next-cursor").is_none(),
            "no more pages"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let p2 = parse_ndjson_body(&body);
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].alertname, "Alert0");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    #[tokio::test]
    async fn api_logs_date_range_accepts_rfc3339_with_offset() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!(
            "peer-observer-test-dr-offset-{}",
            std::process::id()
        ));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let log_path = dir.join("dr-offset.jsonl");
        let log_path_str = log_path.to_str().unwrap().to_string();
        let _ = tokio::fs::remove_file(&log_path).await;

        // Entries at 20:00:00Z .. 20:00:03Z
        let state = make_test_state(log_path_str);
        write_date_range_entries(&state).await;

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // logged_after with +08:00 offset: 2025-06-16T04:00:01+08:00 == 2025-06-15T20:00:01Z
        // logged_before with +08:00 offset: 2025-06-16T04:00:03+08:00 == 2025-06-15T20:00:03Z
        // Half-open [20:00:01Z, 20:00:03Z) should return entries at :01 and :02
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs?logged_after=2025-06-16T04:00:01%2B08:00&logged_before=2025-06-16T04:00:03%2B08:00")
            .header("authorization", "Bearer token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let entries = parse_ndjson_body(&body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].alertname, "Alert2");
        assert_eq!(entries[1].alertname, "Alert1");

        let _ = tokio::fs::remove_file(&log_path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }
}
