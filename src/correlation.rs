use chrono::{DateTime, Utc};
use std::fmt;

use crate::annotation::Verdict;
use crate::prompt::strip_control_chars;
use crate::types::Alert;

/// Stable correlation ID for an alert, derived from (alertname, host, threadname, startsAt).
/// Logged through all processing stages so a single alert can be traced end-to-end.
#[derive(Debug, Clone)]
pub(crate) struct AlertId {
    pub(crate) alertname: String,
    pub(crate) host: String,
    pub(crate) threadname: String,
    pub(crate) started: DateTime<Utc>,
}

impl AlertId {
    pub(crate) fn from_alert(alert: &Alert) -> Self {
        Self {
            alertname: alert.labels.get("alertname").cloned().unwrap_or_default(),
            host: alert
                .labels
                .get("host")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            threadname: alert
                .labels
                .get("threadname")
                .map(|t| strip_control_chars(t))
                .unwrap_or_default(),
            started: alert.starts_at,
        }
    }
}

impl fmt::Display for AlertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // threadname is pre-sanitized in from_alert (control chars stripped).
        if self.threadname.is_empty() {
            write!(
                f,
                "{}:{}:{}",
                self.alertname,
                self.host,
                self.started.format("%Y%m%dT%H%M%SZ")
            )
        } else {
            write!(
                f,
                "{}:{}:{}:{}",
                self.alertname,
                self.host,
                self.threadname,
                self.started.format("%Y%m%dT%H%M%SZ")
            )
        }
    }
}

/// Build the stable tag set used for idempotency checks.
/// Verdict is NOT included — it may differ between retries (fallback vs structured).
/// Tag count is 3 for alerts without threadname, 4 for alerts with.
pub(crate) fn build_idempotency_tags(aid: &AlertId) -> Vec<String> {
    let mut tags = vec![
        "ai-annotation".to_string(),
        aid.alertname.clone(),
        aid.host.clone(),
    ];
    if !aid.threadname.is_empty() {
        tags.push(aid.threadname.clone());
    }
    tags
}

/// Build the full tag set posted to Grafana (idempotency tags + verdict).
pub(crate) fn build_annotation_tags(aid: &AlertId, verdict: Option<&Verdict>) -> Vec<String> {
    let mut tags = build_idempotency_tags(aid);
    if let Some(v) = verdict {
        tags.push(v.as_tag().to_string());
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::HashMap;

    // ── AlertId correlation ────────────────────────────────────────────

    #[test]
    fn alert_id_display_format() {
        let alert = Alert {
            status: "firing".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("alertname".into(), "TestAlert".into());
                m.insert("host".into(), "bitcoin-03".into());
                m
            },
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert_eq!(aid.to_string(), "TestAlert:bitcoin-03:20250615T120000Z");
    }

    #[test]
    fn alert_id_display_format_with_threadname() {
        let alert = Alert {
            status: "firing".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("alertname".into(), "PeerObserverThreadSaturation".into());
                m.insert("host".into(), "bitcoin-03".into());
                m.insert("threadname".into(), "b-msghand".into());
                m
            },
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert_eq!(
            aid.to_string(),
            "PeerObserverThreadSaturation:bitcoin-03:b-msghand:20250615T120000Z"
        );
    }

    #[test]
    fn alert_id_strips_control_chars_from_threadname_at_construction() {
        let alert = Alert {
            status: "firing".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("alertname".into(), "TestAlert".into());
                m.insert("host".into(), "bitcoin-03".into());
                m.insert("threadname".into(), "b-net\nINFO injected".into());
                m
            },
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        // Control chars stripped at construction
        assert_eq!(aid.threadname, "b-netINFO injected");
        assert!(!aid.to_string().contains('\n'));
    }

    #[test]
    fn alert_id_control_char_only_threadname_becomes_empty() {
        let alert = Alert {
            status: "firing".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("alertname".into(), "TestAlert".into());
                m.insert("host".into(), "bitcoin-03".into());
                m.insert("threadname".into(), "\n\t".into());
                m
            },
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert!(aid.threadname.is_empty());
        // Falls through to 3-segment format
        assert_eq!(aid.to_string(), "TestAlert:bitcoin-03:20250615T120000Z");
    }

    #[test]
    fn alert_id_missing_labels() {
        let alert = Alert {
            status: "firing".into(),
            labels: HashMap::new(),
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert_eq!(aid.to_string(), ":unknown:20250101T000000Z");
    }

    // ── Tag building (idempotency split) ──────────────────────────────

    fn test_aid() -> AlertId {
        AlertId {
            alertname: "TestAlert".into(),
            host: "bitcoin-03".into(),
            threadname: String::new(),
            started: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
        }
    }

    fn test_aid_with_threadname() -> AlertId {
        AlertId {
            alertname: "TestAlert".into(),
            host: "bitcoin-03".into(),
            threadname: "b-msghand".into(),
            started: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
        }
    }

    #[test]
    fn idempotency_tags_without_threadname_are_three_element() {
        let tags = build_idempotency_tags(&test_aid());
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], "ai-annotation");
        assert_eq!(tags[1], "TestAlert");
        assert_eq!(tags[2], "bitcoin-03");
    }

    #[test]
    fn idempotency_tags_with_threadname_are_four_element() {
        let tags = build_idempotency_tags(&test_aid_with_threadname());
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[0], "ai-annotation");
        assert_eq!(tags[1], "TestAlert");
        assert_eq!(tags[2], "bitcoin-03");
        assert_eq!(tags[3], "b-msghand");
    }

    #[test]
    fn annotation_tags_include_verdict() {
        let tags = build_annotation_tags(&test_aid(), Some(&Verdict::Benign));
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[3], "benign");

        let tags = build_annotation_tags(&test_aid(), Some(&Verdict::ActionRequired));
        assert_eq!(tags[3], "action_required");
    }

    #[test]
    fn annotation_tags_without_verdict_match_idempotency() {
        let key = build_idempotency_tags(&test_aid());
        let posted = build_annotation_tags(&test_aid(), None);
        assert_eq!(key, posted);
    }

    #[test]
    fn annotation_tags_superset_of_idempotency_tags() {
        let key = build_idempotency_tags(&test_aid());
        let posted = build_annotation_tags(&test_aid(), Some(&Verdict::Investigate));
        assert_eq!(&posted[..key.len()], &key[..]);
        assert_eq!(posted.len(), key.len() + 1);
    }

    #[test]
    fn annotation_tags_with_threadname_superset_of_idempotency_tags() {
        let key = build_idempotency_tags(&test_aid_with_threadname());
        let posted = build_annotation_tags(&test_aid_with_threadname(), Some(&Verdict::Benign));
        assert_eq!(&posted[..key.len()], &key[..]);
        assert_eq!(posted.len(), key.len() + 1);
    }
}
