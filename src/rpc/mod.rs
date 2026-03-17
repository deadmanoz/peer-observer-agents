use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tracing::warn;

mod filter;
use filter::filter_rpc_response;

// RpcClient is pub and accessible as crate::rpc::RpcClient

/// Timeout for individual RPC HTTP requests.
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Overall deadline for all concurrent RPC prefetch calls for a single alert.
const RPC_PREFETCH_DEADLINE: Duration = Duration::from_secs(10);

/// Bitcoin Core JSON-RPC request body.
#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'a str,
    params: Vec<Value>,
}

/// Bitcoin Core JSON-RPC response body.
#[derive(Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

/// Client for Bitcoin Core JSON-RPC over WireGuard.
pub struct RpcClient {
    http: reqwest::Client,
    /// Maps host names (from alert labels) to validated WireGuard IPs.
    hosts: HashMap<String, std::net::IpAddr>,
    port: u16,
    user: String,
    password: String,
}

impl fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcClient")
            .field("hosts", &self.hosts)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl RpcClient {
    /// Construct a new RPC client. Fails fast if configuration is invalid.
    pub fn new(hosts_json: &str, user: String, password: String, port: u16) -> Result<Self> {
        let raw_hosts: HashMap<String, String> = serde_json::from_str(hosts_json).context(
            "ANNOTATION_AGENT_RPC_HOSTS is not valid JSON (expected {\"host\": \"ip\", ...})",
        )?;

        if raw_hosts.is_empty() {
            anyhow::bail!(
                "ANNOTATION_AGENT_RPC_HOSTS is empty — must contain at least one host mapping"
            );
        }

        // Parse and validate all values as IP addresses at startup. This prevents
        // URL injection (e.g., "@attacker.com") and stores typed IpAddr values so
        // call() can format URLs without re-parsing.
        let mut hosts = HashMap::with_capacity(raw_hosts.len());
        for (host, ip_str) in &raw_hosts {
            let ip: std::net::IpAddr = ip_str.parse().with_context(|| {
                format!("ANNOTATION_AGENT_RPC_HOSTS: host '{host}' has invalid IP '{ip_str}'")
            })?;
            hosts.insert(host.clone(), ip);
        }

        let http = reqwest::Client::builder()
            .timeout(RPC_REQUEST_TIMEOUT)
            .build()
            .context("failed to build RPC HTTP client")?;

        Ok(Self {
            http,
            hosts,
            port,
            user,
            password,
        })
    }

    /// Call a single RPC method on the given host. Returns the `result` field.
    async fn call(&self, ip: std::net::IpAddr, method: &str) -> Result<Value> {
        let url = match ip {
            std::net::IpAddr::V6(_) => format!("http://[{ip}]:{}/", self.port),
            std::net::IpAddr::V4(_) => format!("http://{ip}:{}/", self.port),
        };
        let body = JsonRpcRequest {
            jsonrpc: "1.0",
            id: "agent",
            method,
            params: vec![],
        };

        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("RPC request to {ip} for {method} failed"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            // Bitcoin Core returns HTTP 500 for RPC-level errors with the actual
            // error message in the JSON body. Try to extract it for debuggability.
            let error_body = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<JsonRpcResponse>(&error_body)
                .ok()
                .and_then(|r| r.error)
                .map(|e| format!(": {e}"))
                .unwrap_or_default();
            anyhow::bail!("RPC {method} on {ip} returned HTTP {status}{detail}");
        }

        let rpc_resp: JsonRpcResponse = resp
            .json()
            .await
            .with_context(|| format!("failed to parse RPC response for {method}"))?;

        if let Some(err) = rpc_resp.error {
            anyhow::bail!("RPC {method} error: {err}");
        }

        rpc_resp
            .result
            .with_context(|| format!("RPC {method} returned null result"))
    }

    /// Pre-fetch all relevant RPC data for an alert, returning formatted context.
    ///
    /// Calls are fanned out concurrently with an overall deadline. On any failure
    /// (host not mapped, RPC unreachable, timeout), logs a warning and returns
    /// an empty string — the investigation proceeds with Prometheus only.
    pub async fn prefetch(
        &self,
        host: &str,
        alertname: &str,
        alert_id: &str,
    ) -> (String, Option<chrono::DateTime<chrono::Utc>>) {
        let host_ip = match self.hosts.get(host) {
            Some(&ip) => ip,
            None => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "host not in RPC_HOSTS mapping, skipping RPC prefetch"
                );
                return (String::new(), None);
            }
        };

        let methods = rpc_methods_for_alert(alertname);
        if methods.is_empty() {
            return (String::new(), None);
        }

        // Record timestamp before fetching so the prompt header reflects when
        // data was requested, not when the last RPC call finished.
        let fetched_at = chrono::Utc::now();

        // Fan out all RPC calls concurrently under a single deadline.
        let result = tokio::time::timeout(
            RPC_PREFETCH_DEADLINE,
            self.fetch_all(host_ip, alertname, methods, alert_id),
        )
        .await;

        match result {
            Ok(sections) if !sections.is_empty() => (sections, Some(fetched_at)),
            Ok(_) => (String::new(), None),
            Err(_) => {
                warn!(
                    alert_id = alert_id,
                    host = host,
                    "RPC prefetch timed out after {:?}, proceeding without RPC data",
                    RPC_PREFETCH_DEADLINE
                );
                (String::new(), None)
            }
        }
    }

    /// Fetch all methods concurrently and format the results.
    async fn fetch_all(
        &self,
        host_ip: std::net::IpAddr,
        alertname: &str,
        methods: Vec<&str>,
        alert_id: &str,
    ) -> String {
        // Fan out all RPC calls concurrently.
        let futs: Vec<_> = methods
            .iter()
            .map(|method| {
                let method = method.to_string();
                async move {
                    let result = self.call(host_ip, &method).await;
                    (method, result)
                }
            })
            .collect();

        let results = futures_util::future::join_all(futs).await;

        let mut sections = Vec::new();
        for (method, result) in results {
            match result {
                Ok(data) => {
                    let filtered = filter_rpc_response(alertname, &method, &data);
                    sections.push(format!("### {method}\n{filtered}"));
                }
                Err(e) => {
                    warn!(
                        alert_id = alert_id,
                        method = %method,
                        "RPC call failed, skipping: {e}"
                    );
                }
            }
        }

        if sections.is_empty() {
            String::new()
        } else {
            sections.join("\n\n")
        }
    }
}

/// Returns the RPC methods to prefetch for a given alert name.
/// Infrastructure/meta alerts return an empty list (no Bitcoin Core RPC needed).
fn rpc_methods_for_alert(alertname: &str) -> Vec<&'static str> {
    match alertname {
        // P2P message alerts — need peer details
        "PeerObserverAddressMessageSpike" | "PeerObserverMisbehaviorSpike" => {
            vec!["getpeerinfo"]
        }

        // Connection alerts — need peers + network state
        "PeerObserverInboundConnectionDrop"
        | "PeerObserverOutboundConnectionDrop"
        | "PeerObserverTotalPeersDrop" => {
            vec!["getpeerinfo", "getnetworkinfo"]
        }

        // Network inactive — only need network state
        "PeerObserverNetworkInactive" => vec!["getnetworkinfo"],

        // Queue depth alerts — need peer details
        "PeerObserverINVQueueDepthAnomaly" | "PeerObserverINVQueueDepthExtreme" => {
            vec!["getpeerinfo"]
        }

        // Chain health alerts — need blockchain state
        "PeerObserverBlockStale"
        | "PeerObserverBlockStaleCritical"
        | "PeerObserverNodeInIBD"
        | "PeerObserverHeaderBlockGap" => {
            vec!["getblockchaininfo"]
        }

        // Restart — need uptime + blockchain state
        "PeerObserverBitcoinCoreRestart" => vec!["getblockchaininfo", "uptime"],

        // Mempool alerts — need mempool state
        "PeerObserverMempoolFull" | "PeerObserverMempoolEmpty" => vec!["getmempoolinfo"],

        // CPU/thread alerts — need blockchain state for IBD correlation
        "PeerObserverHighCPU" | "PeerObserverThreadSaturation" => vec!["getblockchaininfo"],

        // Infrastructure/meta alerts — no Bitcoin Core RPC needed
        "PeerObserverServiceFailed"
        | "PeerObserverMetricsToolDown"
        | "PeerObserverDiskSpaceLow"
        | "PeerObserverHighMemory"
        | "PeerObserverAnomalyDetectionDown" => vec![],

        // Unknown alerts — no prefetch
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── rpc_methods_for_alert ─────────────────────────────────────────

    #[test]
    fn addr_spike_needs_getpeerinfo() {
        let methods = rpc_methods_for_alert("PeerObserverAddressMessageSpike");
        assert_eq!(methods, vec!["getpeerinfo"]);
    }

    #[test]
    fn misbehavior_spike_needs_getpeerinfo() {
        let methods = rpc_methods_for_alert("PeerObserverMisbehaviorSpike");
        assert_eq!(methods, vec!["getpeerinfo"]);
    }

    #[test]
    fn connection_drops_need_peerinfo_and_netinfo() {
        for alert in &[
            "PeerObserverInboundConnectionDrop",
            "PeerObserverOutboundConnectionDrop",
            "PeerObserverTotalPeersDrop",
        ] {
            let methods = rpc_methods_for_alert(alert);
            assert_eq!(
                methods,
                vec!["getpeerinfo", "getnetworkinfo"],
                "for {alert}"
            );
        }
    }

    #[test]
    fn network_inactive_needs_netinfo() {
        let methods = rpc_methods_for_alert("PeerObserverNetworkInactive");
        assert_eq!(methods, vec!["getnetworkinfo"]);
    }

    #[test]
    fn inv_queue_alerts_need_peerinfo() {
        for alert in &[
            "PeerObserverINVQueueDepthAnomaly",
            "PeerObserverINVQueueDepthExtreme",
        ] {
            let methods = rpc_methods_for_alert(alert);
            assert_eq!(methods, vec!["getpeerinfo"], "for {alert}");
        }
    }

    #[test]
    fn chain_health_alerts_need_blockchaininfo() {
        for alert in &[
            "PeerObserverBlockStale",
            "PeerObserverBlockStaleCritical",
            "PeerObserverNodeInIBD",
            "PeerObserverHeaderBlockGap",
        ] {
            let methods = rpc_methods_for_alert(alert);
            assert_eq!(methods, vec!["getblockchaininfo"], "for {alert}");
        }
    }

    #[test]
    fn restart_needs_blockchaininfo_and_uptime() {
        let methods = rpc_methods_for_alert("PeerObserverBitcoinCoreRestart");
        assert_eq!(methods, vec!["getblockchaininfo", "uptime"]);
    }

    #[test]
    fn mempool_alerts_need_mempoolinfo() {
        for alert in &["PeerObserverMempoolFull", "PeerObserverMempoolEmpty"] {
            let methods = rpc_methods_for_alert(alert);
            assert_eq!(methods, vec!["getmempoolinfo"], "for {alert}");
        }
    }

    #[test]
    fn cpu_thread_alerts_need_blockchaininfo() {
        for alert in &["PeerObserverHighCPU", "PeerObserverThreadSaturation"] {
            let methods = rpc_methods_for_alert(alert);
            assert_eq!(methods, vec!["getblockchaininfo"], "for {alert}");
        }
    }

    #[test]
    fn infrastructure_alerts_need_no_rpc() {
        for alert in &[
            "PeerObserverServiceFailed",
            "PeerObserverMetricsToolDown",
            "PeerObserverDiskSpaceLow",
            "PeerObserverHighMemory",
            "PeerObserverAnomalyDetectionDown",
        ] {
            let methods = rpc_methods_for_alert(alert);
            assert!(methods.is_empty(), "{alert} should need no RPC");
        }
    }

    #[test]
    fn unknown_alert_needs_no_rpc() {
        assert!(rpc_methods_for_alert("SomeNewUnknownAlert").is_empty());
    }

    // ── RpcClient::new validation ─────────────────────────────────────

    #[test]
    fn rpc_client_rejects_invalid_json() {
        let result = RpcClient::new("not json", "user".into(), "pass".into(), 9000);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("not valid JSON"),);
    }

    #[test]
    fn rpc_client_rejects_empty_hosts() {
        let result = RpcClient::new("{}", "user".into(), "pass".into(), 9000);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("empty"),);
    }

    #[test]
    fn rpc_client_rejects_empty_ip() {
        let result = RpcClient::new(r#"{"bitcoin-03": ""}"#, "user".into(), "pass".into(), 9000);
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("invalid IP"),);
    }

    #[test]
    fn rpc_client_rejects_url_injection() {
        let result = RpcClient::new(
            r#"{"node": "@attacker.com"}"#,
            "user".into(),
            "pass".into(),
            9000,
        );
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("invalid IP"),);
    }

    #[test]
    fn rpc_client_accepts_valid_config() {
        let result = RpcClient::new(
            r#"{"bitcoin-03": "10.0.0.3", "vps-dev-01": "10.0.0.4"}"#,
            "user".into(),
            "pass".into(),
            9000,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rpc_client_rejects_wrong_json_type() {
        // Valid JSON but not a string→string map
        let result = RpcClient::new(r#"["not", "a", "map"]"#, "user".into(), "pass".into(), 9000);
        assert!(result.is_err());
    }
}
