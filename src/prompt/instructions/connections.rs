use std::borrow::Cow;

pub(super) fn inbound_drop() -> Cow<'static, str> {
    r#"1. Query `peerobserver_anomaly:level{anomaly_name="inbound_connections"}` and compare against `peerobserver_anomaly:lower_band` to confirm the drop magnitude.
2. Check the RPC Data section above for per-peer details — examine connection ages, network types (IPv4/IPv6/Tor/I2P/CJDNS), and connection direction to see which peers remain and which likely disconnected.
3. Check the Debug Log section above for disconnect reasons — look for `socket closed`, `broken pipe`, `timeout`, or other connection lifecycle events that explain why peers dropped.
4. Check if outbound connections are also affected (correlated drop = local issue, inbound-only = external). The RPC Data getnetworkinfo section shows current connection counts.
5. Compare the same metric across other hosts to determine if this is node-specific or network-wide.
6. Look for recent restart indicators (uptime metrics) — the alert excludes a restart window but timing may be borderline.
7. Conclude: identify whether the cause is a local network issue, a DNS seed problem, a peer-observer restart, or an external event."#.into()
}

pub(super) fn outbound_drop() -> Cow<'static, str> {
    r#"1. Query `peerobserver_anomaly:level{anomaly_name="outbound_connections"}` and compare against `peerobserver_anomaly:lower_band` to confirm the drop.
2. Check the RPC Data section above — count remaining outbound peers (normal is 8 full-relay + 2 block-only). The getnetworkinfo section shows aggregate connection counts.
3. Check the Debug Log section above for disconnect reasons — look for `socket closed`, `broken pipe`, `timeout`, or connection failure messages that explain why outbound peers dropped.
4. Investigate DNS seed reachability — outbound drops usually indicate DNS or network connectivity issues.
5. Check if inbound connections are also affected (both dropping = local network issue).
6. Compare across other hosts to determine scope.
7. Conclude: identify whether this is a DNS resolution failure, local network outage, or Bitcoin network event."#.into()
}

pub(super) fn total_peers_drop() -> Cow<'static, str> {
    r#"1. Query `peerobserver_rpc_peer_info_num_peers` to confirm the current peer count (normal is 10 outbound: 8 full-relay + 2 block-only).
2. Check the RPC Data section above — the getpeerinfo data shows all current peers with connection ages, types, and direction. The getnetworkinfo section shows aggregate inbound/outbound counts.
3. Check the Debug Log section above for disconnect reasons — look for `socket closed`, `broken pipe`, `timeout`, or mass disconnect events that explain the peer count drop.
4. Check if Bitcoin Core recently restarted (`peerobserver_rpc_uptime`) — a restart causes a temporary peer count drop.
5. Look at connection age distribution in the RPC data — are all peers young (suggesting recent restart) or did established peers disconnect?
6. Compare across other hosts to determine if this is node-specific.
7. Conclude: with fewer than 8 peers the node is at risk of eclipse attacks and has reduced network visibility."#.into()
}

pub(super) fn network_inactive() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — P2P networking is completely disabled on the node.
2. Check the RPC Data section above — the getnetworkinfo `networkactive` field directly confirms whether networking is disabled.
3. Check if peer count is also dropping to zero, confirming the network is truly inactive.
4. Check if Bitcoin Core recently restarted — this should not persist after restart.
5. Check if other hosts are also affected (unlikely unless coordinated).
6. Conclude: this requires immediate operator action to re-enable networking via `bitcoin-cli setnetworkactive true`. Determine if this was intentional maintenance or accidental."#.into()
}
