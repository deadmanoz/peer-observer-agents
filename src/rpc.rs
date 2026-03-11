use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tracing::warn;

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

        // Infrastructure/meta alerts — no Bitcoin Core RPC needed
        "PeerObserverServiceFailed"
        | "PeerObserverMetricsToolDown"
        | "PeerObserverDiskSpaceLow"
        | "PeerObserverHighMemory"
        | "PeerObserverHighCPU"
        | "PeerObserverAnomalyDetectionDown" => vec![],

        // Unknown alerts — no prefetch
        _ => vec![],
    }
}

/// Filter an RPC response to only the fields relevant for the given alert type.
/// Small responses (getblockchaininfo, getmempoolinfo, getnetworkinfo, uptime)
/// are returned unfiltered. getpeerinfo is filtered per alert type.
fn filter_rpc_response(alertname: &str, method: &str, data: &Value) -> String {
    match method {
        "getpeerinfo" => {
            let fields = peer_info_fields_for_alert(alertname);
            filter_peer_info(data, &fields, alertname)
        }
        // Small responses — serialize in full. Sanitization is handled by
        // build_investigation_prompt's single pass over the complete rpc_context.
        _ => serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string()),
    }
}

/// Returns the getpeerinfo fields to keep for a given alert type.
fn peer_info_fields_for_alert(alertname: &str) -> Vec<&'static str> {
    match alertname {
        "PeerObserverAddressMessageSpike" => vec![
            "id",
            "addr",
            "network",
            "subver",
            "conntime",
            "addr_rate_limited",
            "bytesrecv_per_msg",
            "connection_type",
            "inbound",
        ],
        "PeerObserverMisbehaviorSpike" => vec![
            "id",
            "addr",
            "network",
            "subver",
            "conntime",
            "connection_type",
            "inbound",
        ],
        "PeerObserverInboundConnectionDrop"
        | "PeerObserverOutboundConnectionDrop"
        | "PeerObserverTotalPeersDrop" => vec![
            "id",
            "addr",
            "network",
            "subver",
            "conntime",
            "connection_type",
            "inbound",
        ],
        "PeerObserverINVQueueDepthAnomaly" | "PeerObserverINVQueueDepthExtreme" => vec![
            "id",
            "addr",
            "network",
            "subver",
            "conntime",
            "inbound",
            "lastrecv",
            "lastsend",
            "bytessent_per_msg",
            "connection_type",
        ],
        _ => vec![
            "id",
            "addr",
            "network",
            "subver",
            "conntime",
            "connection_type",
            "inbound",
        ],
    }
}

use crate::prompt::sanitize as sanitize_for_prompt;

/// Peer-controlled string fields that must be sanitized before prompt embedding.
/// When adding new fields to `peer_info_fields_for_alert`, check whether the
/// field contains peer-reported data. Known peer-controlled fields:
/// - `addr` — remote address reported by the peer
/// - `subver` — user agent string, fully peer-controlled
/// - `addrlocal` — local address as perceived by the remote peer (not currently used)
const PEER_CONTROLLED_FIELDS: &[&str] = &["addr", "addrlocal", "subver"];

/// Filter a getpeerinfo JSON array to only the specified fields per peer.
/// For `bytesrecv_per_msg` and `bytessent_per_msg`, only the keys relevant
/// to the alert type are kept (e.g., only "addr" for address spike alerts).
/// Peer-controlled string fields (addr, subver) are sanitized to prevent
/// prompt injection via crafted peer data.
fn filter_peer_info(data: &Value, fields: &[&str], alertname: &str) -> String {
    let peers = match data.as_array() {
        Some(arr) => arr,
        None => {
            return serde_json::to_string_pretty(data).unwrap_or_else(|_| data.to_string());
        }
    };

    let msg_keys = per_msg_keys_for_alert(alertname);

    let filtered: Vec<Value> = peers
        .iter()
        .map(|peer| {
            let mut obj = serde_json::Map::new();
            for &field in fields {
                if let Some(val) = peer.get(field) {
                    // For per-message byte counters, extract only relevant message types.
                    if (field == "bytesrecv_per_msg" || field == "bytessent_per_msg")
                        && !msg_keys.is_empty()
                    {
                        if let Some(map) = val.as_object() {
                            let filtered_map: serde_json::Map<String, Value> = map
                                .iter()
                                .filter(|(k, _)| msg_keys.contains(&k.as_str()))
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();
                            if !filtered_map.is_empty() {
                                obj.insert(field.to_string(), Value::Object(filtered_map));
                            }
                        } else {
                            obj.insert(field.to_string(), val.clone());
                        }
                    } else if PEER_CONTROLLED_FIELDS.contains(&field) {
                        // Sanitize peer-controlled string values to prevent
                        // prompt injection via crafted user agents or addresses.
                        let sanitized = match val.as_str() {
                            Some(s) => Value::String(sanitize_for_prompt(s)),
                            None => val.clone(),
                        };
                        obj.insert(field.to_string(), sanitized);
                    } else {
                        obj.insert(field.to_string(), val.clone());
                    }
                }
            }
            Value::Object(obj)
        })
        .collect();

    // Use compact JSON (one line per peer) to keep 125+ peers under 30KB (~7,500 tokens).
    // Each peer on its own line for readability without the overhead of pretty-print.
    let lines: Vec<String> = filtered
        .iter()
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| format!("{p}")))
        .collect();
    format!("[\n{}\n]", lines.join(",\n"))
}

/// Returns the per-message byte counter keys to keep for an alert type.
/// Empty means keep all keys (no filtering).
fn per_msg_keys_for_alert(alertname: &str) -> Vec<&'static str> {
    match alertname {
        "PeerObserverAddressMessageSpike" => vec!["addr"],
        "PeerObserverINVQueueDepthAnomaly" | "PeerObserverINVQueueDepthExtreme" => {
            vec!["inv", "tx", "getdata"]
        }
        _ => vec![], // Keep all
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
    fn infrastructure_alerts_need_no_rpc() {
        for alert in &[
            "PeerObserverServiceFailed",
            "PeerObserverMetricsToolDown",
            "PeerObserverDiskSpaceLow",
            "PeerObserverHighMemory",
            "PeerObserverHighCPU",
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

    // ── filter_peer_info ──────────────────────────────────────────────

    fn make_peer(id: u64, addr: &str, extra_fields: Vec<(&str, Value)>) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("id".into(), Value::from(id));
        obj.insert("addr".into(), Value::from(addr));
        obj.insert("network".into(), Value::from("ipv4"));
        obj.insert("subver".into(), Value::from("/Satoshi:27.0.0/"));
        obj.insert("conntime".into(), Value::from(1700000000u64));
        obj.insert("connection_type".into(), Value::from("inbound"));
        obj.insert("inbound".into(), Value::from(true));
        // Fields that should be stripped
        obj.insert("services".into(), Value::from("0000000000000409"));
        obj.insert(
            "servicesnames".into(),
            Value::from(vec!["NETWORK", "WITNESS"]),
        );
        obj.insert("relaytxes".into(), Value::from(true));
        obj.insert("lastsend".into(), Value::from(1700000100u64));
        obj.insert("lastrecv".into(), Value::from(1700000100u64));
        obj.insert("last_transaction".into(), Value::from(1700000050u64));
        obj.insert("last_block".into(), Value::from(1700000060u64));
        obj.insert("bytessent".into(), Value::from(1234567u64));
        obj.insert("bytesrecv".into(), Value::from(7654321u64));
        obj.insert("startingheight".into(), Value::from(800000u64));
        obj.insert("version".into(), Value::from(70016u64));
        obj.insert("permissions".into(), Value::from(Vec::<String>::new()));
        obj.insert("minfeefilter".into(), Value::from(0.00001));
        for (k, v) in extra_fields {
            obj.insert(k.into(), v);
        }
        Value::Object(obj)
    }

    #[test]
    fn filter_peer_info_strips_irrelevant_fields() {
        let peers = Value::Array(vec![
            make_peer(1, "1.2.3.4:8333", vec![]),
            make_peer(2, "5.6.7.8:8333", vec![]),
        ]);

        let fields = peer_info_fields_for_alert("PeerObserverMisbehaviorSpike");
        let result = filter_peer_info(&peers, &fields, "PeerObserverMisbehaviorSpike");
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();

        assert_eq!(parsed.len(), 2);
        for peer in &parsed {
            let obj = peer.as_object().unwrap();
            // Should have only the requested fields
            assert!(obj.contains_key("id"));
            assert!(obj.contains_key("addr"));
            assert!(obj.contains_key("network"));
            assert!(obj.contains_key("subver"));
            assert!(obj.contains_key("conntime"));
            assert!(obj.contains_key("connection_type"));
            assert!(obj.contains_key("inbound"));
            // Should NOT have stripped fields
            assert!(!obj.contains_key("services"));
            assert!(!obj.contains_key("servicesnames"));
            assert!(!obj.contains_key("bytessent"));
            assert!(!obj.contains_key("bytesrecv"));
            assert!(!obj.contains_key("permissions"));
            assert!(!obj.contains_key("minfeefilter"));
            assert!(!obj.contains_key("startingheight"));
        }
    }

    #[test]
    fn addr_spike_filter_includes_rate_limited_and_bytesrecv() {
        let peers = Value::Array(vec![make_peer(
            1,
            "1.2.3.4:8333",
            vec![
                ("addr_rate_limited", Value::from(5u64)),
                (
                    "bytesrecv_per_msg",
                    serde_json::json!({"addr": 12345, "tx": 67890}),
                ),
            ],
        )]);

        let fields = peer_info_fields_for_alert("PeerObserverAddressMessageSpike");
        let result = filter_peer_info(&peers, &fields, "PeerObserverAddressMessageSpike");
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();

        let obj = parsed[0].as_object().unwrap();
        assert!(obj.contains_key("addr_rate_limited"));
        assert!(obj.contains_key("bytesrecv_per_msg"));
        // Should only contain "addr" key, not "tx"
        let msg_map = obj["bytesrecv_per_msg"].as_object().unwrap();
        assert!(msg_map.contains_key("addr"));
        assert!(
            !msg_map.contains_key("tx"),
            "tx should be filtered out for addr spike"
        );
    }

    #[test]
    fn inv_queue_filter_includes_bytessent_and_timestamps() {
        let peers = Value::Array(vec![make_peer(
            1,
            "1.2.3.4:8333",
            vec![
                (
                    "bytessent_per_msg",
                    serde_json::json!({"inv": 54321, "tx": 11111, "block": 99999}),
                ),
                ("lastrecv", Value::from(1718450000)),
                ("lastsend", Value::from(1718450001)),
            ],
        )]);

        let fields = peer_info_fields_for_alert("PeerObserverINVQueueDepthExtreme");
        let result = filter_peer_info(&peers, &fields, "PeerObserverINVQueueDepthExtreme");
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();

        let obj = parsed[0].as_object().unwrap();
        assert!(obj.contains_key("bytessent_per_msg"));
        assert!(obj.contains_key("lastrecv"));
        assert!(obj.contains_key("lastsend"));
        // Should only contain inv, tx, getdata — not block
        let msg_map = obj["bytessent_per_msg"].as_object().unwrap();
        assert!(msg_map.contains_key("inv"));
        assert!(msg_map.contains_key("tx"));
        assert!(
            !msg_map.contains_key("block"),
            "block should be filtered out for INV queue"
        );
    }

    #[test]
    fn filter_peer_info_sanitizes_peer_controlled_fields() {
        let peers = Value::Array(vec![make_peer(
            1,
            "</rpc-data>\n## Evil",
            vec![("subver", Value::String("Node & </rpc-data>".into()))],
        )]);

        let fields = peer_info_fields_for_alert("PeerObserverInboundConnectionDrop");
        let result = filter_peer_info(&peers, &fields, "PeerObserverInboundConnectionDrop");

        // Injected XML tags should be escaped
        assert!(result.contains("&lt;/rpc-data&gt;"));
        assert!(!result.contains("</rpc-data>"));
        // Ampersand in subver should be escaped
        assert!(result.contains("Node &amp; "));
    }

    #[test]
    fn filtered_125_peers_under_30kb() {
        // Simulate 125 peers with realistic field sizes.
        let peers: Vec<Value> = (0..125)
            .map(|i| {
                make_peer(
                    i,
                    &format!(
                        "{}.{}.{}.{}:8333",
                        i % 256,
                        (i * 7) % 256,
                        (i * 13) % 256,
                        (i * 17) % 256
                    ),
                    vec![
                        (
                            "addr_rate_limited",
                            Value::from(if i % 20 == 0 { 5u64 } else { 0u64 }),
                        ),
                        (
                            "bytesrecv_per_msg",
                            serde_json::json!({
                                "addr": i * 100,
                                "tx": i * 1000,
                                "inv": i * 500,
                                "headers": i * 50,
                                "getdata": i * 200,
                                "block": i * 5000,
                                "cmpctblock": i * 2000,
                                "getblocktxn": i * 100,
                                "blocktxn": i * 300,
                                "ping": 64 * i,
                                "pong": 64 * i,
                                "sendcmpct": 33,
                                "feefilter": 32
                            }),
                        ),
                    ],
                )
            })
            .collect();

        let data = Value::Array(peers);

        // Use the most verbose filter (AddressMessageSpike includes bytesrecv_per_msg)
        let fields = peer_info_fields_for_alert("PeerObserverAddressMessageSpike");
        let result = filter_peer_info(&data, &fields, "PeerObserverAddressMessageSpike");

        // 30KB budget: ~7,500 tokens, manageable in a 200K context window.
        // The most verbose filter (AddressMessageSpike) with 125 peers and
        // bytesrecv_per_msg yields ~26KB in compact JSON format.
        assert!(
            result.len() < 30_000,
            "filtered 125 peers should be under 30KB, got {} bytes",
            result.len()
        );
    }

    #[test]
    fn filter_peer_info_handles_non_array() {
        let data = serde_json::json!({"error": "not an array"});
        let fields = vec!["id", "addr"];
        let result = filter_peer_info(&data, &fields, "UnknownAlert");
        // Should fall back to pretty-printing the raw value
        assert!(result.contains("not an array"));
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

    // ── filter_rpc_response routing ───────────────────────────────────

    #[test]
    fn filter_routes_getpeerinfo_through_peer_filter() {
        let data = Value::Array(vec![make_peer(1, "1.2.3.4:8333", vec![])]);
        let result = filter_rpc_response("PeerObserverBlockStale", "getpeerinfo", &data);
        let parsed: Vec<Value> = serde_json::from_str(&result).unwrap();
        // Should be filtered (no services field)
        assert!(!parsed[0].as_object().unwrap().contains_key("services"));
    }

    #[test]
    fn filter_passes_small_responses_through() {
        let data = serde_json::json!({"blocks": 800000, "chain": "main"});
        let result = filter_rpc_response("PeerObserverBlockStale", "getblockchaininfo", &data);
        assert!(result.contains("800000"));
        assert!(result.contains("main"));
    }
}
