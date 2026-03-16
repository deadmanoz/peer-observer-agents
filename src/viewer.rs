//! Annotation log viewer — JSONL log entries, `/api/logs` API, and `/logs` HTML page.
//!
//! Enabled only when both `ANNOTATION_AGENT_LOG_FILE` and
//! `ANNOTATION_AGENT_VIEWER_AUTH_TOKEN` are configured.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Html,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tracing::warn;

use crate::{AppState, ClaudeOutput};

// ── JSONL schema (v1) ───────────────────────────────────────────────

/// Schema version for forward compatibility.
const SCHEMA_VERSION: u8 = 1;

/// Distinguishes structured annotation entries from raw fallback entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryKind {
    Structured,
    RawFallback,
}

/// Telemetry from the Claude CLI invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Telemetry {
    pub(crate) num_turns: u64,
    pub(crate) duration_ms: u64,
    pub(crate) duration_api_ms: u64,
    pub(crate) cost_usd: f64,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) stop_reason: String,
    pub(crate) session_id: String,
}

impl From<&ClaudeOutput> for Telemetry {
    fn from(co: &ClaudeOutput) -> Self {
        Self {
            num_turns: co.num_turns,
            duration_ms: co.duration_ms,
            duration_api_ms: co.duration_api_ms,
            cost_usd: co.cost_usd,
            input_tokens: co.input_tokens,
            output_tokens: co.output_tokens,
            stop_reason: co.stop_reason.clone(),
            session_id: co.session_id.clone(),
        }
    }
}

/// A single JSONL log entry written after each successful annotation post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LogEntry {
    /// Schema version (always 1 for now).
    pub(crate) v: u8,
    /// Wall-clock time when this entry was appended to the log.
    /// Used for newest-first ordering and cursor pagination.
    pub(crate) logged_at: DateTime<Utc>,
    /// Alert start time from Alertmanager.
    pub(crate) alert_starts_at: DateTime<Utc>,
    /// Stable correlation ID (e.g., "AlertName:host:20250615T120000Z").
    pub(crate) alert_id: String,
    pub(crate) alertname: String,
    pub(crate) host: String,
    pub(crate) threadname: String,
    /// Whether this entry has structured annotation fields or raw fallback text.
    pub(crate) entry_kind: EntryKind,
    // Structured fields (present when entry_kind == Structured)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<Vec<String>>,
    // Raw fallback (present when entry_kind == RawFallback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw_text: Option<String>,
    pub(crate) telemetry: Telemetry,
}

impl LogEntry {
    /// Create a LogEntry for a structured annotation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn structured(
        alert_starts_at: DateTime<Utc>,
        alert_id: String,
        alertname: String,
        host: String,
        threadname: String,
        verdict: &str,
        action: Option<String>,
        summary: String,
        cause: String,
        scope: String,
        evidence: Vec<String>,
        telemetry: Telemetry,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION,
            logged_at: Utc::now(),
            alert_starts_at,
            alert_id,
            alertname,
            host,
            threadname,
            entry_kind: EntryKind::Structured,
            verdict: Some(verdict.to_string()),
            action,
            summary: Some(summary),
            cause: Some(cause),
            scope: Some(scope),
            evidence: Some(evidence),
            raw_text: None,
            telemetry,
        }
    }

    /// Create a LogEntry for a raw fallback (unparseable Claude output).
    pub(crate) fn raw_fallback(
        alert_starts_at: DateTime<Utc>,
        alert_id: String,
        alertname: String,
        host: String,
        threadname: String,
        raw_text: String,
        telemetry: Telemetry,
    ) -> Self {
        Self {
            v: SCHEMA_VERSION,
            logged_at: Utc::now(),
            alert_starts_at,
            alert_id,
            alertname,
            host,
            threadname,
            entry_kind: EntryKind::RawFallback,
            verdict: None,
            action: None,
            summary: None,
            cause: None,
            scope: None,
            evidence: None,
            raw_text: Some(raw_text),
            telemetry,
        }
    }
}

/// Append a JSONL log entry to the configured log file.
pub(crate) async fn append_jsonl_log(path: &str, entry: &LogEntry) {
    let mut line = match serde_json::to_string(entry) {
        Ok(json) => json,
        Err(e) => {
            warn!("failed to serialize log entry: {e}");
            return;
        }
    };
    line.push('\n');
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(mut f) => {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = f.write_all(line.as_bytes()).await {
                warn!(path, error = %e, "failed to write JSONL log entry");
            }
        }
        Err(e) => warn!(path, error = %e, "failed to open JSONL log file"),
    }
}

// ── Cursor pagination ───────────────────────────────────────────────

/// Opaque cursor encoding `(logged_at, alert_id)` as base64.
fn encode_cursor(logged_at: &DateTime<Utc>, alert_id: &str) -> String {
    let raw = format!("{}|{}", logged_at.to_rfc3339(), alert_id);
    base64_encode(&raw)
}

fn decode_cursor(cursor: &str) -> Option<(DateTime<Utc>, String)> {
    let raw = base64_decode(cursor)?;
    let (ts_str, alert_id) = raw.split_once('|')?;
    let ts = ts_str.parse::<DateTime<Utc>>().ok()?;
    Some((ts, alert_id.to_string()))
}

/// Simple base64 encoding without pulling in a crate.
/// Uses the standard alphabet (A-Z, a-z, 0-9, +, /) with = padding.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<String> {
    const DECODE: [u8; 128] = {
        let mut table = [255u8; 128];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[alphabet[i] as usize] = i as u8;
            i += 1;
        }
        table
    };
    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return Some(String::new());
    }
    let mut bytes = Vec::with_capacity(input.len() * 3 / 4);
    // Reject any non-base64 characters instead of silently dropping them.
    let mut chars = Vec::with_capacity(input.len());
    for b in input.bytes() {
        if b >= 128 || DECODE[b as usize] == 255 {
            return None; // invalid character
        }
        chars.push(DECODE[b as usize]);
    }
    for chunk in chars.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let b0 = (chunk[0] as u32) << 18
            | (chunk[1] as u32) << 12
            | if chunk.len() > 2 {
                (chunk[2] as u32) << 6
            } else {
                0
            }
            | if chunk.len() > 3 { chunk[3] as u32 } else { 0 };
        bytes.push((b0 >> 16) as u8);
        if chunk.len() > 2 {
            bytes.push((b0 >> 8) as u8);
        }
        if chunk.len() > 3 {
            bytes.push(b0 as u8);
        }
    }
    String::from_utf8(bytes).ok()
}

// ── Heap entry for bounded top-N collection ─────────────────────────

/// Wrapper around `LogEntry` that implements `Ord` by `(logged_at, alert_id)`
/// for use in a min-heap. The smallest entry (oldest by total order) sits at
/// the top so it can be evicted when the heap exceeds the collection bound.
struct HeapEntry {
    logged_at: DateTime<Utc>,
    alert_id: String,
    entry: LogEntry,
}

impl HeapEntry {
    fn from_log_entry(entry: LogEntry) -> Self {
        Self {
            logged_at: entry.logged_at,
            alert_id: entry.alert_id.clone(),
            entry,
        }
    }
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        (&self.logged_at, &self.alert_id) == (&other.logged_at, &other.alert_id)
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.logged_at, &self.alert_id).cmp(&(&other.logged_at, &other.alert_id))
    }
}

// ── API endpoint: GET /api/logs ─────────────────────────────────────

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
}

/// Validate the Bearer token from the Authorization header.
fn check_auth(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if token != expected {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
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
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    // Reject malformed cursors with 400 instead of silently falling back to page 1.
    let before = match &query.before_cursor {
        Some(cursor) => Some(decode_cursor(cursor).ok_or(StatusCode::BAD_REQUEST)?),
        None => None,
    };

    // Forward-scan the file, collecting all matching entries.
    let file = tokio::fs::File::open(path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StatusCode::NOT_FOUND
        } else {
            warn!(path, error = %e, "failed to open log file");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;
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
            Err(_) => continue, // skip malformed lines
        };

        // Apply before_cursor filter — uses the same (logged_at, alert_id)
        // total order as the heap key, so cursor semantics are consistent.
        if let Some((ref cursor_ts, ref cursor_id)) = before {
            if (entry.logged_at, &entry.alert_id) >= (*cursor_ts, cursor_id) {
                continue;
            }
        }

        // Apply server-side filters
        if let Some(ref v) = query.verdict {
            match &entry.verdict {
                Some(ev) if ev == v => {}
                _ => continue,
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
        [(
            axum::http::header::CONTENT_TYPE,
            "application/x-ndjson; charset=utf-8",
        )],
        body,
    )
        .into_response();

    if let Some(cursor) = next_cursor {
        resp.headers_mut()
            .insert("x-next-cursor", cursor.parse().unwrap());
    }

    Ok(resp)
}

// ── HTML page: GET /logs ────────────────────────────────────────────

/// `GET /logs` — serves the self-contained HTML log viewer.
pub(crate) async fn logs_page(
    State(state): State<Arc<AppState>>,
) -> Result<Html<&'static str>, StatusCode> {
    // Only serve if viewer is enabled (both log file and auth token configured)
    if state.viewer_auth_token.is_none() || state.log_file.is_none() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(Html(include_str!("viewer.html")))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_telemetry() -> Telemetry {
        Telemetry {
            num_turns: 12,
            duration_ms: 58000,
            duration_api_ms: 45000,
            cost_usd: 0.04,
            input_tokens: 18000,
            output_tokens: 2500,
            stop_reason: "end_turn".into(),
            session_id: "test-session".into(),
        }
    }

    fn sample_structured_entry() -> LogEntry {
        LogEntry::structured(
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            "PeerObserverBlockStale:bitcoin-03:20250615T120000Z".into(),
            "PeerObserverBlockStale".into(),
            "bitcoin-03".into(),
            String::new(),
            "benign",
            None,
            "No new block in 47 minutes, all hosts at same height.".into(),
            "Normal mining variance.".into(),
            "multi-host".into(),
            vec![
                "last_block: 47 min ago".into(),
                "all hosts synced at 890421".into(),
            ],
            sample_telemetry(),
        )
    }

    fn sample_raw_fallback_entry() -> LogEntry {
        LogEntry::raw_fallback(
            Utc.with_ymd_and_hms(2025, 6, 15, 13, 0, 0).unwrap(),
            "TestAlert:bitcoin-03:20250615T130000Z".into(),
            "TestAlert".into(),
            "bitcoin-03".into(),
            String::new(),
            "Claude output that failed to parse as structured JSON.".into(),
            sample_telemetry(),
        )
    }

    // ── Serialization round-trip ────────────────────────────────────

    #[test]
    fn structured_entry_roundtrip() {
        let entry = sample_structured_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.entry_kind, EntryKind::Structured);
        assert_eq!(parsed.verdict.as_deref(), Some("benign"));
        assert_eq!(parsed.alertname, "PeerObserverBlockStale");
        assert_eq!(parsed.host, "bitcoin-03");
        assert!(parsed.threadname.is_empty());
        assert!(parsed.raw_text.is_none());
        assert_eq!(parsed.evidence.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.telemetry.num_turns, 12);
        assert!((parsed.telemetry.cost_usd - 0.04).abs() < f64::EPSILON);
    }

    #[test]
    fn raw_fallback_entry_roundtrip() {
        let entry = sample_raw_fallback_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entry_kind, EntryKind::RawFallback);
        assert!(parsed.verdict.is_none());
        assert!(parsed.summary.is_none());
        assert!(parsed.evidence.is_none());
        assert_eq!(
            parsed.raw_text.as_deref(),
            Some("Claude output that failed to parse as structured JSON.")
        );
    }

    #[test]
    fn structured_entry_skips_none_fields() {
        let entry = sample_structured_entry();
        let json = serde_json::to_string(&entry).unwrap();
        // raw_text should not be in the JSON
        assert!(!json.contains("raw_text"));
        // action should not be in the JSON (it's None for benign)
        assert!(!json.contains("\"action\""));
    }

    #[test]
    fn raw_fallback_entry_skips_structured_fields() {
        let entry = sample_raw_fallback_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"verdict\""));
        assert!(!json.contains("\"summary\""));
        assert!(!json.contains("\"cause\""));
        assert!(!json.contains("\"scope\""));
        assert!(!json.contains("\"evidence\""));
    }

    #[test]
    fn entry_has_logged_at_and_alert_starts_at() {
        let entry = sample_structured_entry();
        // logged_at is set to Utc::now() in the constructor, alert_starts_at is from the alert
        assert_eq!(
            entry.alert_starts_at,
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap()
        );
        // logged_at should be recent (within the last second)
        let now = Utc::now();
        assert!(
            (now - entry.logged_at).num_seconds().abs() < 2,
            "logged_at should be close to now"
        );
    }

    // ── Cursor encoding/decoding ────────────────────────────────────

    #[test]
    fn cursor_roundtrip() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let alert_id = "PeerObserverBlockStale:bitcoin-03:20250615T120000Z";
        let encoded = encode_cursor(&ts, alert_id);
        let (decoded_ts, decoded_id) = decode_cursor(&encoded).unwrap();
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, alert_id);
    }

    #[test]
    fn cursor_decode_invalid() {
        assert!(decode_cursor("not-valid-base64!!!").is_none());
        assert!(decode_cursor("").is_none());
    }

    #[test]
    fn base64_rejects_trailing_garbage() {
        // A valid base64 string with trailing non-base64 chars must be rejected,
        // not silently decoded by dropping the garbage.
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let alert_id = "Test:host:ts";
        let valid = encode_cursor(&ts, alert_id);
        let tampered = format!("{}!!!", valid);
        assert!(
            decode_cursor(&tampered).is_none(),
            "cursor with trailing garbage should be rejected"
        );
    }

    #[test]
    fn base64_roundtrip() {
        let inputs = [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "hello world!",
            "2025-06-15T12:00:00+00:00|AlertName:host:ts",
        ];
        for input in inputs {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, input, "roundtrip failed for {input:?}");
        }
    }

    // ── Auth checking ───────────────────────────────────────────────

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

    // ── XSS safety ──────────────────────────────────────────────────

    #[test]
    fn raw_fallback_preserves_script_tags_literally() {
        let malicious = r#"<script>alert('xss')</script><img onerror="alert(1)" src=x>"#;
        let entry = LogEntry::raw_fallback(
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            "TestAlert:host:20250615T120000Z".into(),
            "TestAlert".into(),
            "host".into(),
            String::new(),
            malicious.to_string(),
            sample_telemetry(),
        );
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        // The raw_text field must round-trip the literal script tag string.
        // XSS safety: the viewer renders raw_text via textContent only (never innerHTML).
        // The JSON transport itself may or may not escape angle brackets — that's fine,
        // because the safety boundary is in the DOM rendering, not the wire format.
        assert_eq!(parsed.raw_text.as_deref(), Some(malicious));
    }

    // ── JSONL file reading (integration test with temp file) ────────

    #[tokio::test]
    async fn append_and_read_jsonl() {
        let dir = std::env::temp_dir().join(format!("peer-observer-test-{}", std::process::id()));
        let _ = tokio::fs::create_dir_all(&dir).await;
        let path = dir.join("test.jsonl");
        let path_str = path.to_str().unwrap();

        // Clean up any previous test file
        let _ = tokio::fs::remove_file(&path).await;

        let entry1 = sample_structured_entry();
        let entry2 = sample_raw_fallback_entry();

        append_jsonl_log(path_str, &entry1).await;
        append_jsonl_log(path_str, &entry2).await;

        // Read back and verify
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: LogEntry = serde_json::from_str(lines[0]).unwrap();
        let parsed2: LogEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed1.entry_kind, EntryKind::Structured);
        assert_eq!(parsed2.entry_kind, EntryKind::RawFallback);

        // Cleanup
        let _ = tokio::fs::remove_file(&path).await;
        let _ = tokio::fs::remove_dir(&dir).await;
    }

    // ── API handler (integration test with axum) ────────────────────

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
        append_jsonl_log(&log_path_str, &entry).await;

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
        });

        let app = Router::new()
            .route("/api/logs", get(api_logs))
            .with_state(state);

        // No auth header → 401
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong token → 401
        let req = Request::builder()
            .method("GET")
            .uri("/api/logs")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Valid token → 200
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
            append_jsonl_log(&log_path_str, &entry).await;
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
            append_jsonl_log(&log_path_str, &entry).await;
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
        append_jsonl_log(&log_path_str, &benign).await;

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
        append_jsonl_log(&log_path_str, &action_required).await;

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
        append_jsonl_log(&log_path_str, &entry).await;

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
        append_jsonl_log(&log_path_str, &entry).await;

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

    #[tokio::test]
    async fn routes_absent_when_no_log_file() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

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
}
