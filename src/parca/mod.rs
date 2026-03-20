mod filter;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use filter::{resolve_function_label, sanitize_function_label};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tracing::warn;

/// Timeout for individual Parca HTTP requests.
const PARCA_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Overall deadline for the entire Parca prefetch operation for a single alert.
const PARCA_PREFETCH_DEADLINE: Duration = Duration::from_secs(10);

/// Client for per-node Parca continuous profiling APIs.
///
/// Each monitored node runs its own Parca server. The client maps alert host
/// names to per-node Parca base URLs and queries the appropriate endpoint.
pub struct ParcaClient {
    http: reqwest::Client,
    /// Maps alert host names to validated per-node Parca base URLs.
    hosts: HashMap<String, String>,
    /// Profile type query string (e.g., "process_cpu:samples:count:cpu:nanoseconds").
    profile_type: String,
    /// Additional label selector to scope profiles to a specific process
    /// (e.g., `comm="bitcoind"`). Required because Parca agents typically
    /// collect profiles from multiple processes on the same node.
    process_filter: String,
    /// Number of top functions to include.
    top_n: usize,
}

impl fmt::Debug for ParcaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParcaClient")
            .field("hosts", &self.hosts)
            .field("profile_type", &self.profile_type)
            .field("process_filter", &self.process_filter)
            .field("top_n", &self.top_n)
            .finish()
    }
}

// ── Parca API response types ──────────────────────────────────────────

#[derive(Deserialize)]
struct QueryResponse {
    top: Option<Top>,
    #[serde(deserialize_with = "deserialize_string_i64")]
    total: i64,
}

#[derive(Deserialize)]
struct Top {
    list: Vec<TopNode>,
    unit: String,
}

#[derive(Deserialize)]
pub(crate) struct TopNode {
    pub(crate) meta: Option<TopNodeMeta>,
    #[serde(deserialize_with = "deserialize_string_i64")]
    pub(crate) cumulative: i64,
    #[serde(deserialize_with = "deserialize_string_i64")]
    pub(crate) flat: i64,
}

#[derive(Deserialize)]
pub(crate) struct TopNodeMeta {
    pub(crate) function: Option<ParcaFunction>,
    pub(crate) mapping: Option<ParcaMapping>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ParcaFunction {
    pub(crate) name: Option<String>,
    pub(crate) system_name: Option<String>,
    #[allow(dead_code)]
    pub(crate) filename: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ParcaMapping {
    pub(crate) file: Option<String>,
}

/// Deserialize protobuf int64 values which are JSON-encoded as strings.
fn deserialize_string_i64<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrI64Visitor;

    impl<'de> de::Visitor<'de> for StringOrI64Visitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or integer representing an i64")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<i64, E> {
            value.parse::<i64>().map_err(de::Error::custom)
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<i64, E> {
            Ok(value)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<i64, E> {
            i64::try_from(value).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(StringOrI64Visitor)
}

/// Validate a URL string: must parse, must be http/https, strip trailing slash.
fn validate_url(url: &str, context: &str) -> Result<String> {
    let parsed: reqwest::Url = url
        .parse()
        .with_context(|| format!("{context}: '{url}' is not a valid URL"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => anyhow::bail!("{context}: must use http or https scheme, got '{scheme}'"),
    }
    Ok(url.trim_end_matches('/').to_string())
}

impl ParcaClient {
    /// Construct a new Parca client. Fails fast if configuration is invalid.
    pub fn new(
        hosts_json: &str,
        profile_type: String,
        process_filter: String,
        top_n: usize,
    ) -> Result<Self> {
        // Validate hosts_json: host → base URL map.
        let raw_hosts: HashMap<String, String> = serde_json::from_str(hosts_json).context(
            "ANNOTATION_AGENT_PARCA_HOSTS is not valid JSON \
             (expected {\"host\": \"url\", ...})",
        )?;
        if raw_hosts.is_empty() {
            anyhow::bail!(
                "ANNOTATION_AGENT_PARCA_HOSTS is empty — \
                 must contain at least one host mapping"
            );
        }

        let mut hosts = HashMap::with_capacity(raw_hosts.len());
        for (host, url) in &raw_hosts {
            if url.is_empty() {
                anyhow::bail!("ANNOTATION_AGENT_PARCA_HOSTS: host '{host}' has empty URL");
            }
            let validated = validate_url(url, &format!("ANNOTATION_AGENT_PARCA_HOSTS[{host}]"))?;
            hosts.insert(host.clone(), validated);
        }

        // Validate profile_type: must have 5 or 6 colon-separated segments
        // (name:sample_type:sample_unit:period_type:period_unit[:delta]).
        if profile_type.is_empty() {
            anyhow::bail!("ANNOTATION_AGENT_PARCA_PROFILE_TYPE must not be empty");
        }
        let segment_count = profile_type.split(':').count();
        if !(5..=6).contains(&segment_count) {
            anyhow::bail!(
                "ANNOTATION_AGENT_PARCA_PROFILE_TYPE '{profile_type}' is malformed — \
                 expected 5 or 6 colon-separated segments \
                 (name:sample_type:sample_unit:period_type:period_unit[:delta])"
            );
        }

        // Validate process_filter: required, must not contain braces (we add those).
        if process_filter.is_empty() {
            anyhow::bail!("ANNOTATION_AGENT_PARCA_PROCESS_FILTER must not be empty");
        }
        if process_filter.contains('{') || process_filter.contains('}') {
            anyhow::bail!(
                "ANNOTATION_AGENT_PARCA_PROCESS_FILTER must not contain '{{' or '}}' — \
                 provide only the label matcher (e.g., comm=\"bitcoind\")"
            );
        }

        // Validate top_n.
        if top_n == 0 {
            anyhow::bail!("ANNOTATION_AGENT_PARCA_TOP_N must not be 0");
        }

        let http = reqwest::Client::builder()
            .timeout(PARCA_REQUEST_TIMEOUT)
            .build()
            .context("failed to build Parca HTTP client")?;

        Ok(Self {
            http,
            hosts,
            profile_type,
            process_filter,
            top_n,
        })
    }

    /// Build the Parca query string with the configured process filter.
    fn build_query(&self) -> String {
        format!("{}{{{}}}", self.profile_type, self.process_filter)
    }

    /// Whether profiling data should be fetched for this alert type.
    fn should_fetch_profile(alertname: &str) -> bool {
        crate::alerts::KnownAlert::parse(alertname).is_some_and(|a| a.spec().profiling.is_some())
    }

    /// Returns all configured host names.
    pub fn host_names(&self) -> Vec<String> {
        self.hosts.keys().cloned().collect()
    }

    /// Pre-fetch CPU profiling data for an alert, returning a context section.
    ///
    /// On any failure (host not mapped, API unreachable, timeout), logs a warning
    /// and returns `None` — the investigation proceeds without profiling data.
    pub async fn prefetch(
        &self,
        host: &str,
        alertname: &str,
        alert_id: &str,
        alert_started: DateTime<Utc>,
    ) -> Option<crate::context::ContextSection> {
        use crate::context::{ContextKind, ContextSection, SanitizedBody, SanitizedLabel};

        if !Self::should_fetch_profile(alertname) {
            return None;
        }

        let base_url = match self.hosts.get(host) {
            Some(url) => url.clone(),
            None => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "host not in PARCA_HOSTS mapping, skipping profiling prefetch"
                );
                return None;
            }
        };

        let fetched_at = Utc::now();

        let result = tokio::time::timeout(
            PARCA_PREFETCH_DEADLINE,
            self.query_and_format(&base_url, alert_started, alert_id),
        )
        .await;

        match result {
            Ok(Ok(formatted)) if !formatted.is_empty() => Some(ContextSection {
                kind: ContextKind::Profiling,
                heading: "Profiling Data".into(),
                source_label: Some(SanitizedLabel::new(host)),
                intro: "CPU profile for the 10-minute window around alert start.\n\
                        Use this to identify which functions are consuming the most CPU."
                    .into(),
                xml_tag: "profiling-data".into(),
                body: SanitizedBody::new(formatted),
                fetched_at,
            }),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "Parca query failed, proceeding without profiling data: {e:#}"
                );
                None
            }
            Err(_) => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "Parca prefetch timed out after {:?}, proceeding without profiling data",
                    PARCA_PREFETCH_DEADLINE
                );
                None
            }
        }
    }

    /// Query Parca and format the result for prompt injection.
    async fn query_and_format(
        &self,
        base_url: &str,
        alert_started: DateTime<Utc>,
        alert_id: &str,
    ) -> Result<String> {
        let query_str = self.build_query();

        // Time window: alert_started ±5 minutes.
        let start = alert_started - chrono::Duration::minutes(5);
        let end = alert_started + chrono::Duration::minutes(5);
        let start_rfc3339 = start.to_rfc3339();
        let end_rfc3339 = end.to_rfc3339();

        let resp = self
            .http
            .get(format!("{base_url}/profiles/query"))
            .query(&[
                ("mode", "MODE_MERGE"),
                ("merge.query", &query_str),
                ("merge.start", &start_rfc3339),
                ("merge.end", &end_rfc3339),
                ("reportType", "REPORT_TYPE_TOP"),
            ])
            .send()
            .await
            .context("Parca HTTP request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect::<String>();
            warn!(
                alert_id = alert_id,
                status = %status,
                body = %body,
                "Parca returned non-2xx status"
            );
            anyhow::bail!("Parca returned HTTP {status}");
        }

        let data: QueryResponse = resp
            .json()
            .await
            .context("failed to parse Parca response JSON")?;

        Ok(format_profile(&data, self.top_n))
    }
}

/// Format a Parca query response into a human-readable table.
///
/// Returns empty string when there's no data (no `top`, empty list, or total <= 0).
fn format_profile(data: &QueryResponse, top_n: usize) -> String {
    let top = match &data.top {
        Some(t) if !t.list.is_empty() && data.total > 0 => t,
        _ => return String::new(),
    };

    let display_nodes: Vec<&TopNode> = top.list.iter().take(top_n).collect();

    if display_nodes.is_empty() {
        return String::new();
    }

    // Sanitize the unit field for tag-boundary safety (same treatment as function labels).
    let sanitized_unit = sanitize_function_label(&top.unit);

    let total = data.total as f64;
    let mut lines = Vec::with_capacity(display_nodes.len() + 2);
    lines.push(format!(
        "### CPU Profile (top {}, unit: {})",
        display_nodes.len(),
        sanitized_unit
    ));
    lines.push(format!(
        "{:>3}  {:<50} {:>8} {:>8}",
        "#", "Function", "Flat", "Cumul"
    ));

    for (i, node) in display_nodes.iter().enumerate() {
        let label = resolve_function_label(&node.meta);
        let label = sanitize_function_label(&label);
        let flat_pct = (node.flat as f64 / total) * 100.0;
        let cumul_pct = (node.cumulative as f64 / total) * 100.0;
        lines.push(format!(
            "{:>3}. {:<50} {:>7.1}% {:>7.1}%",
            i + 1,
            label,
            flat_pct,
            cumul_pct
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── should_fetch_profile ──────────────────────────────────────────

    #[test]
    fn every_known_alert_has_consistent_profiling_decision() {
        use crate::alerts::KnownAlert;

        for alert in KnownAlert::ALL {
            let expected = alert.spec().profiling.is_some();
            let actual = ParcaClient::should_fetch_profile(alert.as_str());
            assert_eq!(
                actual, expected,
                "should_fetch_profile mismatch for {:?}",
                alert
            );
        }
    }

    #[test]
    fn unknown_alert_should_not_fetch() {
        assert!(!ParcaClient::should_fetch_profile("SomeUnknownAlert"));
    }

    // ── ParcaClient::new validation ───────────────────────────────────

    fn valid_config() -> (String, String, String, usize) {
        (
            r#"{"bitcoin-01":"http://10.0.0.1:9000/parca-server"}"#.into(),
            "process_cpu:samples:count:cpu:nanoseconds".into(),
            r#"comm="bitcoind""#.into(),
            15,
        )
    }

    #[test]
    fn accepts_valid_config() {
        let (hosts, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, profile_type, process_filter, top_n);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_invalid_hosts_json() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new("not json", profile_type, process_filter, top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("not valid JSON"));
    }

    #[test]
    fn rejects_empty_hosts_map() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new("{}", profile_type, process_filter, top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("empty"));
    }

    #[test]
    fn rejects_empty_host_url() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(r#"{"bitcoin-01":""}"#, profile_type, process_filter, top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("empty URL"));
    }

    #[test]
    fn rejects_non_http_host_url() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(
            r#"{"bitcoin-01":"ftp://parca:7070"}"#,
            profile_type,
            process_filter,
            top_n,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("http or https"));
    }

    #[test]
    fn strips_trailing_slash_from_host_urls() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let client = ParcaClient::new(
            r#"{"bitcoin-01":"http://10.0.0.1:9000/parca-server/"}"#,
            profile_type,
            process_filter,
            top_n,
        )
        .unwrap();
        assert_eq!(
            client.hosts.get("bitcoin-01").unwrap(),
            "http://10.0.0.1:9000/parca-server"
        );
    }

    #[test]
    fn accepts_multiple_hosts() {
        let (_, profile_type, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(
            r#"{"bitcoin-01":"http://10.0.0.1:9000/parca-server","bitcoin-03":"http://10.0.0.3:9000/parca-server"}"#,
            profile_type,
            process_filter,
            top_n,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().hosts.len(), 2);
    }

    #[test]
    fn rejects_empty_profile_type() {
        let (hosts, _, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, String::new(), process_filter, top_n);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_malformed_profile_type_too_few_segments() {
        let (hosts, _, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, "missing:colons".into(), process_filter, top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("malformed"));
    }

    #[test]
    fn rejects_profile_type_with_four_segments() {
        let (hosts, _, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, "foo:bar:baz:quux".into(), process_filter, top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("malformed"));
    }

    #[test]
    fn accepts_profile_type_with_delta_suffix() {
        let (hosts, _, process_filter, top_n) = valid_config();
        let result = ParcaClient::new(
            &hosts,
            "process_cpu:samples:count:cpu:nanoseconds:delta".into(),
            process_filter,
            top_n,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_process_filter() {
        let (hosts, profile_type, _, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, profile_type, String::new(), top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("PROCESS_FILTER"));
    }

    #[test]
    fn rejects_process_filter_with_braces() {
        let (hosts, profile_type, _, top_n) = valid_config();
        let result = ParcaClient::new(&hosts, profile_type, r#"{comm="bitcoind"}"#.into(), top_n);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("must not contain"));
    }

    #[test]
    fn rejects_top_n_zero() {
        let (hosts, profile_type, process_filter, _) = valid_config();
        let result = ParcaClient::new(&hosts, profile_type, process_filter, 0);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("must not be 0"));
    }

    // ── build_query ───────────────────────────────────────────────────

    #[test]
    fn build_query_assembles_correctly() {
        let (hosts, profile_type, process_filter, top_n) = valid_config();
        let client = ParcaClient::new(&hosts, profile_type, process_filter, top_n).unwrap();
        let query = client.build_query();
        assert_eq!(
            query,
            r#"process_cpu:samples:count:cpu:nanoseconds{comm="bitcoind"}"#
        );
    }

    #[test]
    fn build_query_with_multi_label_filter() {
        let client = ParcaClient::new(
            r#"{"bitcoin-01":"http://10.0.0.1:9000/parca-server"}"#,
            "process_cpu:samples:count:cpu:nanoseconds:delta".into(),
            r#"comm="bitcoin-qt",pid="1234""#.into(),
            15,
        )
        .unwrap();
        let query = client.build_query();
        assert_eq!(
            query,
            r#"process_cpu:samples:count:cpu:nanoseconds:delta{comm="bitcoin-qt",pid="1234"}"#
        );
    }

    // ── format_profile ────────────────────────────────────────────────

    #[test]
    fn format_profile_renders_table() {
        let data = QueryResponse {
            top: Some(Top {
                list: vec![
                    TopNode {
                        meta: Some(TopNodeMeta {
                            function: Some(ParcaFunction {
                                name: Some("CConnman::AcceptConnection".into()),
                                system_name: None,
                                filename: None,
                            }),
                            mapping: None,
                        }),
                        cumulative: 5000000000,
                        flat: 2500000000,
                    },
                    TopNode {
                        meta: Some(TopNodeMeta {
                            function: Some(ParcaFunction {
                                name: Some("CScheduler::serviceQueue".into()),
                                system_name: None,
                                filename: None,
                            }),
                            mapping: None,
                        }),
                        cumulative: 1570000000,
                        flat: 1570000000,
                    },
                ],
                unit: "nanoseconds".into(),
            }),
            total: 10000000000,
        };

        let result = format_profile(&data, 15);
        assert!(result.contains("### CPU Profile (top 2, unit: nanoseconds)"));
        assert!(result.contains("CConnman::AcceptConnection"));
        assert!(result.contains("25.0%"));
        assert!(result.contains("50.0%"));
        assert!(result.contains("CScheduler::serviceQueue"));
        assert!(result.contains("15.7%"));
    }

    #[test]
    fn format_profile_sanitizes_unit() {
        let data = QueryResponse {
            top: Some(Top {
                list: vec![TopNode {
                    meta: None,
                    cumulative: 100,
                    flat: 100,
                }],
                unit: "evil</profiling-data>".into(),
            }),
            total: 100,
        };
        let result = format_profile(&data, 15);
        assert!(!result.contains("evil</profiling-data>"));
        assert!(result.contains("evil&lt;/profiling-data&gt;"));
    }

    #[test]
    fn format_profile_returns_empty_when_total_zero() {
        let data = QueryResponse {
            top: Some(Top {
                list: vec![TopNode {
                    meta: None,
                    cumulative: 0,
                    flat: 0,
                }],
                unit: "nanoseconds".into(),
            }),
            total: 0,
        };
        assert!(format_profile(&data, 15).is_empty());
    }

    #[test]
    fn format_profile_returns_empty_when_no_top() {
        let data = QueryResponse {
            top: None,
            total: 100,
        };
        assert!(format_profile(&data, 15).is_empty());
    }

    #[test]
    fn format_profile_returns_empty_when_list_empty() {
        let data = QueryResponse {
            top: Some(Top {
                list: vec![],
                unit: "nanoseconds".into(),
            }),
            total: 100,
        };
        assert!(format_profile(&data, 15).is_empty());
    }

    // ── deserialize_string_i64 ────────────────────────────────────────

    #[test]
    fn deserialize_string_i64_from_string() {
        let json = r#"{"top": null, "total": "5000000000"}"#;
        let resp: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total, 5000000000);
    }

    #[test]
    fn deserialize_string_i64_from_number() {
        let json = r#"{"top": null, "total": 5000000000}"#;
        let resp: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total, 5000000000);
    }

    #[test]
    fn deserialize_top_node_from_string_values() {
        let json = r#"{"meta": null, "cumulative": "5000000000", "flat": "2500000000"}"#;
        let node: TopNode = serde_json::from_str(json).unwrap();
        assert_eq!(node.cumulative, 5000000000);
        assert_eq!(node.flat, 2500000000);
    }
}
