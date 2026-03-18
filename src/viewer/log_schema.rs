//! JSONL schema types for annotation log entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::ClaudeOutput;

/// Schema version for forward compatibility.
pub(crate) const SCHEMA_VERSION: u8 = 1;

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

/// Default value for `agent_version` when deserializing old entries that lack the field.
fn unknown_agent_version() -> String {
    "unknown".to_string()
}

/// A single JSONL log entry written after each successful annotation post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LogEntry {
    /// Schema version (always 1 for now).
    pub(crate) v: u8,
    /// Version of peer-observer-agents that produced this entry.
    #[serde(default = "unknown_agent_version")]
    pub(crate) agent_version: String,
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
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
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
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::TimeZone;

    pub(crate) fn sample_telemetry() -> Telemetry {
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

    pub(crate) fn sample_structured_entry() -> LogEntry {
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

    pub(crate) fn sample_raw_fallback_entry() -> LogEntry {
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

    #[test]
    fn structured_entry_roundtrip() {
        let entry = sample_structured_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.agent_version, env!("CARGO_PKG_VERSION"));
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
        assert_eq!(parsed.agent_version, env!("CARGO_PKG_VERSION"));
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
    fn legacy_entry_without_agent_version_defaults_to_unknown() {
        // Simulate a pre-version log entry (no agent_version field).
        let json = r#"{
            "v": 1,
            "logged_at": "2025-06-15T12:00:00Z",
            "alert_starts_at": "2025-06-15T12:00:00Z",
            "alert_id": "TestAlert:host:20250615T120000Z",
            "alertname": "TestAlert",
            "host": "bitcoin-03",
            "threadname": "",
            "entry_kind": "structured",
            "verdict": "benign",
            "summary": "All good.",
            "cause": "Normal.",
            "scope": "single-host",
            "evidence": ["e1"],
            "telemetry": {
                "num_turns": 5,
                "duration_ms": 10000,
                "duration_api_ms": 8000,
                "cost_usd": 0.02,
                "input_tokens": 5000,
                "output_tokens": 1000,
                "stop_reason": "end_turn",
                "session_id": "legacy-session"
            }
        }"#;
        let parsed: LogEntry = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.agent_version, "unknown");
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
}
