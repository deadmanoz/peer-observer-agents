use chrono::{DateTime, Utc};

/// Body already sanitized by the upstream extractor. Prompt builder embeds verbatim.
pub(crate) struct SanitizedBody(String);

impl SanitizedBody {
    pub(crate) fn new(body: String) -> Self {
        Self(body)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Label sanitized for safe prompt embedding.
pub(crate) struct SanitizedLabel(String);

impl SanitizedLabel {
    pub(crate) fn new(raw: &str) -> Self {
        Self(crate::sanitization::sanitize_host_for_prompt(raw))
    }
}

impl std::fmt::Display for SanitizedLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Ordering key for deterministic section layout in the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ContextKind {
    Rpc,
    Profiling,
    DebugLog,
}

/// One section of pre-fetched context for the investigation prompt.
pub(crate) struct ContextSection {
    #[allow(dead_code)] // reserved for deterministic section ordering
    pub(crate) kind: ContextKind,
    pub(crate) heading: String,
    pub(crate) source_label: Option<SanitizedLabel>,
    pub(crate) intro: String,
    pub(crate) xml_tag: String,
    pub(crate) body: SanitizedBody,
    pub(crate) fetched_at: DateTime<Utc>,
}

#[cfg(test)]
impl ContextSection {
    pub(crate) fn test_rpc(body: &str) -> Self {
        Self {
            kind: ContextKind::Rpc,
            heading: "RPC Data".into(),
            source_label: Some(SanitizedLabel::new("host")),
            intro: "pre-fetched data".into(),
            xml_tag: "rpc-data".into(),
            body: SanitizedBody::new(body.into()),
            fetched_at: chrono::Utc::now(),
        }
    }

    pub(crate) fn test_profiling(body: &str) -> Self {
        Self {
            kind: ContextKind::Profiling,
            heading: "Profiling Data".into(),
            source_label: Some(SanitizedLabel::new("host")),
            intro: "CPU profile".into(),
            xml_tag: "profiling-data".into(),
            body: SanitizedBody::new(body.into()),
            fetched_at: chrono::Utc::now(),
        }
    }

    pub(crate) fn test_debug_log(body: &str) -> Self {
        Self {
            kind: ContextKind::DebugLog,
            heading: "Debug Log".into(),
            source_label: Some(SanitizedLabel::new("host")),
            intro: "debug log lines".into(),
            xml_tag: "debug-log-data".into(),
            body: SanitizedBody::new(body.into()),
            fetched_at: chrono::Utc::now(),
        }
    }
}
