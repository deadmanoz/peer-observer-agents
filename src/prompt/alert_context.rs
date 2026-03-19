use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::context::ContextSection;
use crate::sanitization::strip_control_chars;

/// All pre-fetched data sources collected before Claude investigation.
///
/// Using a struct avoids a growing positional param list as new data sources
/// are added.
#[derive(Default)]
pub struct PreFetchData {
    pub prior_context: String,
    pub sections: Vec<ContextSection>,
}

pub struct AlertContext {
    pub alertname: String,
    pub host: String,
    pub threadname: String,
    pub severity: String,
    pub category: String,
    pub started: DateTime<Utc>,
    pub description: String,
    pub dashboard: String,
    pub runbook: String,
    pub prior_context: String,
    /// Pre-fetched context sections (RPC, profiling, debug log, etc.).
    pub sections: Vec<ContextSection>,
}

impl AlertContext {
    /// Extract an `AlertContext` from an Alertmanager alert's labels and annotations.
    pub fn from_alert(
        labels: &HashMap<String, String>,
        annotations: &Option<HashMap<String, String>>,
        starts_at: DateTime<Utc>,
        prefetch: PreFetchData,
    ) -> Self {
        let get_ann = |key: &str, default: &str| -> String {
            annotations
                .as_ref()
                .and_then(|a| a.get(key))
                .cloned()
                .unwrap_or_else(|| default.to_string())
        };

        Self {
            alertname: labels.get("alertname").cloned().unwrap_or_default(),
            host: labels
                .get("host")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            threadname: labels
                .get("threadname")
                .map(|t| strip_control_chars(t))
                .unwrap_or_default(),
            severity: labels
                .get("severity")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            category: labels
                .get("category")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            started: starts_at,
            description: get_ann("description", "No description provided."),
            dashboard: get_ann("dashboard", ""),
            runbook: get_ann("runbook", ""),
            prior_context: prefetch.prior_context,
            sections: prefetch.sections,
        }
    }
}

#[cfg(test)]
impl AlertContext {
    /// Standard test context for prompt unit tests.
    pub(super) fn test_default() -> Self {
        Self {
            alertname: "TestAlert".into(),
            host: "host".into(),
            threadname: String::new(),
            severity: "warning".into(),
            category: "connections".into(),
            started: chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2025, 6, 15, 12, 0, 0)
                .unwrap(),
            description: "desc".into(),
            dashboard: String::new(),
            runbook: String::new(),
            prior_context: String::new(),
            sections: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> DateTime<Utc> {
        AlertContext::test_default().started
    }

    #[test]
    fn from_alert_extracts_labels() {
        let mut labels = HashMap::new();
        labels.insert("alertname".into(), "TestAlert".into());
        labels.insert("host".into(), "bitcoin-03".into());
        labels.insert("severity".into(), "critical".into());
        labels.insert("category".into(), "chain_health".into());

        let mut annotations = HashMap::new();
        annotations.insert("description".into(), "Block stale".into());
        annotations.insert("dashboard".into(), "https://grafana/d/x".into());

        let ctx = AlertContext::from_alert(
            &labels,
            &Some(annotations),
            test_time(),
            PreFetchData::default(),
        );
        assert_eq!(ctx.alertname, "TestAlert");
        assert_eq!(ctx.host, "bitcoin-03");
        assert_eq!(ctx.severity, "critical");
        assert_eq!(ctx.category, "chain_health");
        assert_eq!(ctx.description, "Block stale");
        assert_eq!(ctx.dashboard, "https://grafana/d/x");
        assert!(ctx.runbook.is_empty());
    }

    #[test]
    fn from_alert_defaults_missing_fields() {
        let labels = HashMap::new();
        let ctx = AlertContext::from_alert(&labels, &None, test_time(), PreFetchData::default());
        assert!(ctx.alertname.is_empty());
        assert_eq!(ctx.host, "unknown");
        assert_eq!(ctx.severity, "unknown");
        assert_eq!(ctx.category, "unknown");
        assert_eq!(ctx.description, "No description provided.");
    }

    #[test]
    fn from_alert_extracts_threadname() {
        let mut labels = HashMap::new();
        labels.insert("alertname".into(), "PeerObserverThreadSaturation".into());
        labels.insert("host".into(), "bitcoin-03".into());
        labels.insert("threadname".into(), "b-msghand".into());
        let ctx = AlertContext::from_alert(&labels, &None, test_time(), PreFetchData::default());
        assert_eq!(ctx.threadname, "b-msghand");
    }

    #[test]
    fn from_alert_defaults_threadname_to_empty() {
        let labels = HashMap::new();
        let ctx = AlertContext::from_alert(&labels, &None, test_time(), PreFetchData::default());
        assert!(ctx.threadname.is_empty());
    }
}
