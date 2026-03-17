use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;

/// Parsed Claude CLI JSON output with telemetry fields.
#[derive(Debug)]
pub(crate) struct ClaudeOutput {
    pub(crate) result: String,
    pub(crate) is_error: bool,
    pub(crate) num_turns: u64,
    pub(crate) duration_ms: u64,
    pub(crate) duration_api_ms: u64,
    pub(crate) cost_usd: f64,
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) stop_reason: String,
    pub(crate) session_id: String,
}

// Alertmanager webhook payload types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AlertmanagerPayload {
    pub(crate) alerts: Vec<Alert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Alert {
    pub(crate) status: String,
    pub(crate) labels: HashMap<String, String>,
    pub(crate) annotations: Option<HashMap<String, String>>,
    pub(crate) starts_at: DateTime<Utc>,
    pub(crate) ends_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ── Alertmanager payload deserialization ────────────────────────────

    fn sample_webhook_json() -> &'static str {
        r#"{
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "PeerObserverInboundConnectionDrop", "host": "bitcoin-03", "severity": "warning", "category": "connections"},
                    "annotations": {"description": "Inbound connections dropped below lower band", "dashboard": "https://grafana.example.com/d/abc"},
                    "startsAt": "2025-06-15T12:00:00Z",
                    "endsAt": "0001-01-01T00:00:00Z"
                },
                {
                    "status": "resolved",
                    "labels": {"alertname": "PeerObserverBlockStale", "host": "bitcoin-04"},
                    "annotations": null,
                    "startsAt": "2025-06-15T11:00:00Z",
                    "endsAt": "2025-06-15T11:30:00Z"
                }
            ]
        }"#
    }

    #[test]
    fn deserialize_alertmanager_payload() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        assert_eq!(payload.alerts.len(), 2);
        assert_eq!(payload.alerts[0].status, "firing");
        assert_eq!(
            payload.alerts[0].labels.get("alertname").unwrap(),
            "PeerObserverInboundConnectionDrop"
        );
        assert_eq!(payload.alerts[1].status, "resolved");
    }

    #[test]
    fn deserialize_alert_with_null_annotations() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        assert!(payload.alerts[1].annotations.is_none());
    }

    #[test]
    fn deserialize_alert_timestamps() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        let firing = &payload.alerts[0];
        assert_eq!(
            firing.starts_at,
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap()
        );
        // Sentinel date for still-firing
        let ends = firing.ends_at.unwrap();
        assert!(ends.timestamp() < 0, "sentinel date should be pre-epoch");
    }

    #[test]
    fn deserialize_empty_alerts() {
        let json = r#"{"alerts": []}"#;
        let payload: AlertmanagerPayload = serde_json::from_str(json).unwrap();
        assert!(payload.alerts.is_empty());
    }

    #[test]
    fn deserialize_minimal_alert() {
        let json = r#"{
            "alerts": [{
                "status": "firing",
                "labels": {},
                "startsAt": "2025-01-01T00:00:00Z"
            }]
        }"#;
        let payload: AlertmanagerPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.alerts.len(), 1);
        assert!(payload.alerts[0].annotations.is_none());
        assert!(payload.alerts[0].ends_at.is_none());
    }
}
