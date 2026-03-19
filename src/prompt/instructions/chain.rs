use std::borrow::Cow;

pub(super) fn block_stale() -> Cow<'static, str> {
    r#"1. Query `peerobserver_validation_block_connected_latest_height` to confirm the current block height and when the last block was connected.
2. Check the RPC Data section above — `getblockchaininfo` provides the current `blocks` height, `headers` height, `initialblockdownload` status, and `verificationprogress` directly from the node.
3. Check the Debug Log section above for block validation timing (`[bench]` lines) and compact block reconstruction details — these show whether blocks are being received but validation is slow.
4. Compare the RPC `blocks` vs `headers` — if headers are ahead of blocks, the node is still validating. If both are equal and match other hosts, this is a slow block interval.
5. Check if other hosts are also stale — if all nodes are at the same height, this is likely a slow block interval rather than a node issue.
6. If only this host is stale, check peer count and network connectivity — the node may be partitioned.
7. Conclude: differentiate between a naturally slow block interval (no action needed) and a node that has fallen behind or been partitioned (action needed).
8. SANITY CHECK: The alert start time tells you how long the stale condition has persisted. Cross-reference any duration claims against this. Convert all Prometheus timestamps to UTC before calculating durations."#.into()
}

pub(super) fn block_stale_critical() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — no new block connected in 2 hours. This is almost certainly a real problem.
2. Check the RPC Data section above — `getblockchaininfo` provides the current `blocks` height, `headers` height, and `initialblockdownload` status directly from the node. If this data is missing, bitcoind may be unresponsive.
3. Check the Debug Log section above for block validation timing and errors — look for `[bench]` lines showing slow validation, `[validation]` errors, or compact block reconstruction failures.
4. Compare the RPC block height against other hosts via Prometheus — if others are ahead, this node is partitioned or stalled.
5. Check peer count and network status — can the node reach peers at all?
6. Check systemd service status via `node_systemd_unit_state` for bitcoind.
7. Conclude: a 2-hour gap almost certainly indicates the node is partitioned, bitcoind has crashed, or disk I/O is completely stalled. Immediate operator action is required."#.into()
}

pub(super) fn restart() -> Cow<'static, str> {
    r#"1. This is an INFO alert — Bitcoin Core has restarted. Check the RPC Data section above — the `uptime` value (in seconds) confirms exactly when the restart occurred.
2. Check the Debug Log section above for the startup sequence — look for initialization messages, bind/listen results, and initial peer connections that show the restart progressing normally.
3. Check `getblockchaininfo` from the RPC data — verify `initialblockdownload` is false and `blocks` matches `headers` (no sync gap after restart).
4. Look for correlated alerts — restarts often trigger PeerObserverInboundConnectionDrop and PeerObserverOutboundConnectionDrop temporarily.
5. If RPC data shows `initialblockdownload: true`, the node is re-syncing — this is unexpected unless the datadir was corrupted.
6. Verify the node is reconnecting to peers via Prometheus peer count metrics and the block height is advancing.
7. Conclude: determine if this was a planned restart (no action) or unexpected crash (investigate further). Note any correlated alerts that should be expected during the reconnection window."#.into()
}

pub(super) fn node_in_ibd() -> Cow<'static, str> {
    r#"1. Check the RPC Data section above — `getblockchaininfo` confirms `initialblockdownload` status, current `blocks` vs `headers` gap, and `verificationprogress` directly from the node.
2. Use the RPC `verificationprogress` to assess how far along the sync is (1.0 = fully synced).
3. Use the RPC `blocks` vs `headers` gap to estimate how many blocks remain to validate.
4. Check if Bitcoin Core recently restarted (`peerobserver_rpc_uptime`) — IBD after restart with a fresh datadir is expected.
5. Check disk I/O and CPU usage — IBD is resource-intensive and may be slow on constrained hardware.
6. Conclude: determine if this is an expected initial sync (just monitor progress) or an unexpected regression into IBD (investigate datadir corruption). A running node entering IBD is very unusual."#.into()
}

pub(super) fn header_block_gap() -> Cow<'static, str> {
    r#"1. Check the RPC Data section above — `getblockchaininfo` provides the exact `blocks` and `headers` values, letting you calculate the gap size directly.
2. Compare the RPC gap against the Prometheus trend — query `peerobserver_rpc_blockchaininfo_headers` and `peerobserver_rpc_blockchaininfo_blocks` to see if the gap is growing, stable, or shrinking.
3. Check disk I/O metrics — a header-block gap usually indicates the node can't validate blocks fast enough, often due to slow disk.
4. Check CPU usage — heavy block validation can bottleneck on CPU.
5. Check if the node recently restarted — a temporary gap after restart is normal during catchup.
6. Conclude: a persistent gap >10 blocks indicates a performance problem (usually disk I/O). The node is receiving headers but can't keep up with validation. Recommend investigating storage performance."#.into()
}
