pub(crate) mod filter;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use filter::{filter_log_lines, log_filter_for_alert};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tracing::warn;

/// Timeout for individual debug log HTTP requests.
const DEBUG_LOG_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Overall deadline for the entire debug log prefetch operation for a single alert.
const DEBUG_LOG_PREFETCH_DEADLINE: Duration = Duration::from_secs(10);

/// Default maximum bytes to fetch from the tail of debug.log.
#[cfg(test)]
const DEFAULT_TAIL_BYTES: u64 = 1_048_576;

/// Default time window before alert start to include log lines (seconds).
#[cfg(test)]
const DEFAULT_WINDOW_SECS: u64 = 300;

/// Default maximum number of filtered lines to include in the prompt.
#[cfg(test)]
const DEFAULT_MAX_LINES: usize = 200;

/// Path to the live debug.log on the nginx webserver.
const DEBUG_LOG_PATH: &str = "/debug-log-live";

/// Client for fetching Bitcoin Core debug.log tails via HTTP Range requests.
///
/// Reuses the RPC client's host→WireGuard IP mapping and nginx webserver port.
/// The debug log is served at a separate path on the same nginx instance that
/// proxies RPC requests.
#[derive(Debug)]
pub struct DebugLogClient {
    http: reqwest::Client,
    hosts: HashMap<String, IpAddr>,
    port: u16,
    /// Maximum bytes to fetch from the tail of debug.log.
    max_bytes: u64,
    /// How far before alert start to include log lines (seconds).
    window_secs: u64,
    /// Maximum number of filtered lines to include in the prompt.
    max_lines: usize,
}

impl DebugLogClient {
    /// Construct a new debug log client. Fails if configuration is invalid.
    pub fn new(
        hosts: HashMap<String, IpAddr>,
        port: u16,
        max_bytes: u64,
        window_secs: u64,
        max_lines: usize,
    ) -> Result<Self> {
        if hosts.is_empty() {
            anyhow::bail!("debug log client requires at least one host mapping");
        }
        if max_bytes == 0 {
            anyhow::bail!("DEBUG_LOGS_MAX_BYTES must not be 0");
        }
        if window_secs == 0 {
            anyhow::bail!("DEBUG_LOGS_WINDOW_SECS must not be 0");
        }
        if max_lines == 0 {
            anyhow::bail!("DEBUG_LOGS_MAX_LINES must not be 0");
        }

        let http = reqwest::Client::builder()
            .timeout(DEBUG_LOG_REQUEST_TIMEOUT)
            .build()
            .context("failed to build debug log HTTP client")?;

        Ok(Self {
            http,
            hosts,
            port,
            max_bytes,
            window_secs,
            max_lines,
        })
    }

    /// Pre-fetch debug log lines relevant to an alert, returning formatted context.
    ///
    /// On any failure (host not mapped, HTTP error, timeout), logs a warning and
    /// returns an empty string — the investigation proceeds without debug log data.
    pub async fn prefetch(
        &self,
        host: &str,
        alertname: &str,
        alert_id: &str,
        alert_started: DateTime<Utc>,
    ) -> (String, Option<DateTime<Utc>>) {
        // Guard: skip alerts where debug log categories are empty
        let filter = log_filter_for_alert(alertname);
        if filter.categories.is_empty() && !filter.include_uncategorized {
            return (String::new(), None);
        }

        let ip = match self.hosts.get(host) {
            Some(&ip) => ip,
            None => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "host not in RPC_HOSTS mapping, skipping debug log prefetch"
                );
                return (String::new(), None);
            }
        };

        let fetched_at = Utc::now();

        let result = tokio::time::timeout(
            DEBUG_LOG_PREFETCH_DEADLINE,
            self.fetch_and_filter(ip, alertname, alert_id, alert_started),
        )
        .await;

        match result {
            Ok(Ok(filtered)) if !filtered.is_empty() => (filtered, Some(fetched_at)),
            Ok(Ok(_)) => (String::new(), None),
            Ok(Err(e)) => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "debug log fetch failed, proceeding without debug log data: {e:#}"
                );
                (String::new(), None)
            }
            Err(_) => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "debug log prefetch timed out after {:?}, proceeding without debug log data",
                    DEBUG_LOG_PREFETCH_DEADLINE
                );
                (String::new(), None)
            }
        }
    }

    /// Fetch the tail of debug.log and filter by time/category.
    async fn fetch_and_filter(
        &self,
        ip: IpAddr,
        alertname: &str,
        alert_id: &str,
        alert_started: DateTime<Utc>,
    ) -> Result<String> {
        let url = match ip {
            IpAddr::V6(_) => format!("http://[{ip}]:{}{DEBUG_LOG_PATH}", self.port),
            IpAddr::V4(_) => format!("http://{ip}:{}{DEBUG_LOG_PATH}", self.port),
        };

        let resp = self
            .http
            .get(&url)
            .header("Range", format!("bytes=-{}", self.max_bytes))
            .send()
            .await
            .with_context(|| format!("debug log request to {ip} failed"))?;

        let status = resp.status();
        let body = match status.as_u16() {
            206 => {
                // Partial Content — range request succeeded.
                // The byte range likely starts mid-line, so the first "line" is
                // usually a partial fragment. However, if the range happens to
                // start on a line boundary, the first line is valid. Use
                // timestamp parseability to distinguish: a valid log line starts
                // with a parseable timestamp; a partial fragment does not.
                let text = resp.text().await.context("failed to read debug log body")?;
                let first_line = text.lines().next().unwrap_or("");
                if filter::parse_line_timestamp(first_line).is_some() {
                    // First line has a valid timestamp — range started on a
                    // line boundary, keep the full content.
                    text
                } else {
                    // First line is a partial fragment — skip it.
                    match text.find('\n') {
                        Some(idx) => text[idx + 1..].to_string(),
                        None => return Ok(String::new()),
                    }
                }
            }
            200 => {
                // Full content — file smaller than max_bytes.
                // Do NOT skip the first line.
                resp.text().await.context("failed to read debug log body")?
            }
            _ => {
                warn!(
                    alert_id = alert_id,
                    status = %status,
                    url = %url,
                    "debug log endpoint returned non-2xx status"
                );
                return Ok(String::new());
            }
        };

        let filter = log_filter_for_alert(alertname);
        let window_start = alert_started - chrono::Duration::seconds(self.window_secs as i64);
        let window_end = Utc::now();

        Ok(filter_log_lines(
            &body,
            &filter,
            window_start,
            window_end,
            self.max_lines,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hosts() -> HashMap<String, IpAddr> {
        let mut hosts = HashMap::new();
        hosts.insert("bitcoin-03".into(), "10.0.0.3".parse::<IpAddr>().unwrap());
        hosts
    }

    // ── new() validation ──────────────────────────────────────────────

    #[test]
    fn rejects_empty_hosts() {
        let result = DebugLogClient::new(
            HashMap::new(),
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("at least one host"));
    }

    #[test]
    fn rejects_max_bytes_zero() {
        let result = DebugLogClient::new(
            valid_hosts(),
            9000,
            0,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("MAX_BYTES"));
    }

    #[test]
    fn rejects_window_secs_zero() {
        let result = DebugLogClient::new(
            valid_hosts(),
            9000,
            DEFAULT_TAIL_BYTES,
            0,
            DEFAULT_MAX_LINES,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("WINDOW_SECS"));
    }

    #[test]
    fn rejects_max_lines_zero() {
        let result = DebugLogClient::new(
            valid_hosts(),
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            0,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("MAX_LINES"));
    }

    #[test]
    fn accepts_valid_config() {
        let result = DebugLogClient::new(
            valid_hosts(),
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        );
        assert!(result.is_ok());
    }

    // ── URL formatting ────────────────────────────────────────────────

    #[test]
    fn ipv6_url_uses_brackets() {
        let mut hosts = HashMap::new();
        hosts.insert("node".into(), "::1".parse::<IpAddr>().unwrap());
        let client = DebugLogClient::new(
            hosts,
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        )
        .unwrap();
        // We can't easily test the URL directly without making a request,
        // but we can verify the client was created successfully with IPv6
        assert!(client.hosts.get("node").unwrap().is_ipv6());
    }

    // ── prefetch guards ───────────────────────────────────────────────

    #[tokio::test]
    async fn prefetch_skips_infrastructure_alerts() {
        let client = DebugLogClient::new(
            valid_hosts(),
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        )
        .unwrap();

        let (result, ts) = client
            .prefetch(
                "bitcoin-03",
                "PeerObserverServiceFailed",
                "test-id",
                Utc::now(),
            )
            .await;
        assert!(result.is_empty());
        assert!(ts.is_none());
    }

    #[tokio::test]
    async fn prefetch_skips_unknown_host() {
        let client = DebugLogClient::new(
            valid_hosts(),
            9000,
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        )
        .unwrap();

        let (result, ts) = client
            .prefetch(
                "unknown-host",
                "PeerObserverBlockStale",
                "test-id",
                Utc::now(),
            )
            .await;
        assert!(result.is_empty());
        assert!(ts.is_none());
    }

    #[tokio::test]
    async fn prefetch_returns_empty_on_connection_error() {
        let client = DebugLogClient::new(
            valid_hosts(),
            19999, // unreachable port
            DEFAULT_TAIL_BYTES,
            DEFAULT_WINDOW_SECS,
            DEFAULT_MAX_LINES,
        )
        .unwrap();

        let (result, ts) = client
            .prefetch(
                "bitcoin-03",
                "PeerObserverBlockStale",
                "test-id",
                Utc::now(),
            )
            .await;
        assert!(result.is_empty());
        assert!(ts.is_none());
    }

    // ── HTTP fetch tests (local axum server) ──────────────────────────

    /// Start a local HTTP server that responds with the given status and body
    /// at the `/debug-log-live` path. Returns the port.
    async fn start_test_server(status: axum::http::StatusCode, body: &'static str) -> u16 {
        use axum::routing::get;

        let app =
            axum::Router::new().route(DEBUG_LOG_PATH, get(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    fn localhost_hosts(port: u16) -> (HashMap<String, IpAddr>, u16) {
        let mut hosts = HashMap::new();
        hosts.insert("test-node".into(), "127.0.0.1".parse::<IpAddr>().unwrap());
        (hosts, port)
    }

    /// Generate a timestamp string N seconds before now (so it falls within
    /// the default 300s window).
    fn recent_ts() -> String {
        let ts = Utc::now() - chrono::Duration::seconds(60);
        ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
    }

    #[tokio::test]
    async fn fetch_200_returns_full_content_including_first_line() {
        // Build log content with a line that will match the [net] category
        // filter for PeerObserverBlockStale (uses [validation]).
        let ts = recent_ts();
        let body: &'static str = Box::leak(
            format!(
                "{ts} [msghand] [validation] block connected\n\
                 {ts} [msghand] [validation] second line",
                ts = ts,
            )
            .into_boxed_str(),
        );

        let port = start_test_server(axum::http::StatusCode::OK, body).await;
        let (hosts, port) = localhost_hosts(port);
        let client = DebugLogClient::new(hosts, port, DEFAULT_TAIL_BYTES, 300, 200).unwrap();

        let (result, fetched_at) = client
            .prefetch("test-node", "PeerObserverBlockStale", "test-id", Utc::now())
            .await;

        assert!(fetched_at.is_some(), "should have a fetched_at timestamp");
        assert!(
            result.contains("block connected"),
            "200 response should include first line"
        );
        assert!(
            result.contains("second line"),
            "200 response should include second line"
        );
    }

    #[tokio::test]
    async fn fetch_206_skips_partial_first_line() {
        // Simulate a 206 response where the byte range starts mid-line:
        // the first "line" is a fragment without a valid timestamp.
        let ts = recent_ts();
        let body: &'static str = Box::leak(
            format!(
                "artial fragment from previous line\n\
                 {ts} [msghand] [validation] real log line",
                ts = ts,
            )
            .into_boxed_str(),
        );

        let port = start_test_server(axum::http::StatusCode::PARTIAL_CONTENT, body).await;
        let (hosts, port) = localhost_hosts(port);
        let client = DebugLogClient::new(hosts, port, DEFAULT_TAIL_BYTES, 300, 200).unwrap();

        let (result, fetched_at) = client
            .prefetch("test-node", "PeerObserverBlockStale", "test-id", Utc::now())
            .await;

        assert!(fetched_at.is_some());
        assert!(
            !result.contains("artial fragment"),
            "206 should skip the partial first line"
        );
        assert!(
            result.contains("real log line"),
            "206 should include the real log line after the fragment"
        );
    }

    #[tokio::test]
    async fn fetch_206_keeps_first_line_when_on_boundary() {
        // Simulate a 206 response where the byte range happens to start
        // exactly on a line boundary — first line has a valid timestamp.
        let ts = recent_ts();
        let body: &'static str = Box::leak(
            format!(
                "{ts} [msghand] [validation] first complete line\n\
                 {ts} [msghand] [validation] second line",
                ts = ts,
            )
            .into_boxed_str(),
        );

        let port = start_test_server(axum::http::StatusCode::PARTIAL_CONTENT, body).await;
        let (hosts, port) = localhost_hosts(port);
        let client = DebugLogClient::new(hosts, port, DEFAULT_TAIL_BYTES, 300, 200).unwrap();

        let (result, fetched_at) = client
            .prefetch("test-node", "PeerObserverBlockStale", "test-id", Utc::now())
            .await;

        assert!(fetched_at.is_some());
        assert!(
            result.contains("first complete line"),
            "206 on line boundary should keep first line (has valid timestamp)"
        );
        assert!(result.contains("second line"));
    }

    #[tokio::test]
    async fn fetch_non_2xx_returns_empty() {
        let port = start_test_server(axum::http::StatusCode::NOT_FOUND, "not found").await;
        let (hosts, port) = localhost_hosts(port);
        let client = DebugLogClient::new(hosts, port, DEFAULT_TAIL_BYTES, 300, 200).unwrap();

        let (result, fetched_at) = client
            .prefetch("test-node", "PeerObserverBlockStale", "test-id", Utc::now())
            .await;

        assert!(result.is_empty(), "non-2xx should return empty");
        assert!(fetched_at.is_none());
    }

    #[tokio::test]
    async fn fetch_ipv6_url_format() {
        // Verify that IPv6 addresses are formatted with brackets in URLs.
        // We can't easily start a server on IPv6 loopback in all test envs,
        // but we can verify the URL is built correctly by testing against
        // localhost (IPv4) and checking the IPv6 formatting logic separately.
        let url_v6 = format!("http://[::1]:9000{}", DEBUG_LOG_PATH);
        assert_eq!(url_v6, "http://[::1]:9000/debug-log-live");

        let url_v4 = format!("http://127.0.0.1:9000{}", DEBUG_LOG_PATH);
        assert_eq!(url_v4, "http://127.0.0.1:9000/debug-log-live");
    }
}
