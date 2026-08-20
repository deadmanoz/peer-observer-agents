//! Minimal Prometheus HTTP API client for the deterministic sweep.
//!
//! v1 never talked to Prometheus directly — it reached it only through the
//! Claude CLI's MCP tools, which meant every query cost a model call. The sweep
//! is explicitly zero-LLM, so it needs its own client.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// Timeout for a single Prometheus HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A labelled time series with its samples, ordered by timestamp.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Series {
    pub(crate) labels: BTreeMap<String, String>,
    /// `(unix_seconds, value)` pairs.
    pub(crate) samples: Vec<(f64, f64)>,
}

impl Series {
    /// Bare sample values, dropping timestamps.
    pub(crate) fn values(&self) -> Vec<f64> {
        self.samples.iter().map(|(_, v)| *v).collect()
    }

    /// Identify this series by a label, falling back to the metric name.
    pub(crate) fn label(&self, key: &str) -> String {
        self.labels
            .get(key)
            .or_else(|| self.labels.get("__name__"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Client for the Prometheus HTTP query API.
#[derive(Debug, Clone)]
pub(crate) struct PromClient {
    http: reqwest::Client,
    base_url: String,
}

// ── Wire types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    status: String,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct QueryData {
    result: Vec<RawSeries>,
}

#[derive(Deserialize)]
struct RawSeries {
    #[serde(default)]
    metric: BTreeMap<String, String>,
    /// Present for instant (vector) queries.
    #[serde(default)]
    value: Option<(f64, String)>,
    /// Present for range (matrix) queries.
    #[serde(default)]
    values: Option<Vec<(f64, String)>>,
}

impl RawSeries {
    fn into_series(self) -> Series {
        let mut samples: Vec<(f64, f64)> = Vec::new();
        if let Some((ts, raw)) = self.value {
            if let Ok(v) = raw.parse::<f64>() {
                samples.push((ts, v));
            }
        }
        if let Some(vs) = self.values {
            for (ts, raw) in vs {
                if let Ok(v) = raw.parse::<f64>() {
                    samples.push((ts, v));
                }
            }
        }
        samples.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        Series {
            labels: self.metric,
            samples,
        }
    }
}

impl PromClient {
    /// Build a client against a Prometheus base URL (e.g. `http://127.0.0.1:9090`).
    pub(crate) fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building Prometheus HTTP client")?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        })
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(params)
            .send()
            .await
            .with_context(|| format!("querying {url}"))?;
        let status = resp.status();
        let body = resp.text().await.context("reading Prometheus response")?;
        if !status.is_success() {
            bail!(
                "Prometheus returned HTTP {status}: {}",
                truncate(&body, 300)
            );
        }
        let env: ApiEnvelope<T> =
            serde_json::from_str(&body).with_context(|| format!("parsing {url} response"))?;
        if env.status != "success" {
            bail!(
                "Prometheus query failed: {}",
                env.error.unwrap_or_else(|| "unknown error".into())
            );
        }
        env.data.context("Prometheus response had no data field")
    }

    /// Range query over `[start, end]` at `step` resolution.
    ///
    /// `start`/`end` are unix seconds; `step` is a Prometheus duration such as
    /// `"5m"`.
    pub(crate) async fn query_range(
        &self,
        promql: &str,
        start: i64,
        end: i64,
        step: &str,
    ) -> Result<Vec<Series>> {
        let data: QueryData = self
            .get(
                "/api/v1/query_range",
                &[
                    ("query", promql),
                    ("start", &start.to_string()),
                    ("end", &end.to_string()),
                    ("step", step),
                ],
            )
            .await?;
        Ok(data
            .result
            .into_iter()
            .map(RawSeries::into_series)
            .collect())
    }
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
///
/// Byte-slicing would panic on a multi-byte boundary, and this runs on
/// Prometheus error bodies, which are exactly the untrusted input most likely to
/// contain non-ASCII.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_instant_vector() {
        let raw = r#"{"metric":{"__name__":"up","host":"a"},"value":[1755000000,"1"]}"#;
        let rs: RawSeries = serde_json::from_str(raw).expect("valid");
        let s = rs.into_series();
        assert_eq!(s.samples, vec![(1755000000.0, 1.0)]);
        assert_eq!(s.label("host"), "a");
    }

    #[test]
    fn parses_range_matrix_and_sorts() {
        let raw = r#"{"metric":{"host":"b"},"values":[[20,"2"],[10,"1"]]}"#;
        let rs: RawSeries = serde_json::from_str(raw).expect("valid");
        let s = rs.into_series();
        assert_eq!(s.samples, vec![(10.0, 1.0), (20.0, 2.0)]);
        assert_eq!(s.values(), vec![1.0, 2.0]);
    }

    #[test]
    fn skips_unparseable_sample_values() {
        // Prometheus emits "NaN" for staleness; it must not abort the series.
        let raw = r#"{"metric":{},"values":[[10,"1"],[20,"not-a-number"],[30,"3"]]}"#;
        let rs: RawSeries = serde_json::from_str(raw).expect("valid");
        let s = rs.into_series();
        assert_eq!(s.values(), vec![1.0, 3.0]);
    }

    #[test]
    fn label_falls_back_to_metric_name() {
        let raw = r#"{"metric":{"__name__":"m"},"value":[1,"1"]}"#;
        let s: RawSeries = serde_json::from_str(raw).expect("valid");
        assert_eq!(s.into_series().label("host"), "m");
    }

    #[test]
    fn truncate_is_boundary_safe() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
    }

    #[test]
    fn truncate_does_not_panic_on_multibyte_boundary() {
        // "é" is two bytes; cutting at byte 1 lands mid-character and a naive
        // &s[..max] would panic. Prometheus error bodies are exactly where
        // non-ASCII shows up.
        let s = "é".repeat(200);
        let out = truncate(&s, 301);
        assert!(out.ends_with('…'));
        assert!(out.len() <= 304);

        // Every prefix length must be handled, including 0.
        for max in 0..12 {
            let _ = truncate("aébcdé", max);
        }
    }
}
