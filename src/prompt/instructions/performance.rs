use std::borrow::Cow;

use super::InstructionContext;

pub(super) fn inv_queue_anomaly() -> Cow<'static, str> {
    r#"1. Query `peerobserver_anomaly:level{anomaly_name="invtosend_mean"}` and the upper band to confirm the anomaly.
2. Also check `peerobserver_anomaly:level{anomaly_name="invtosend_max"}` to see if individual peers have extreme queue depths.
3. Check the RPC Data section above for per-peer details — cross-reference peers with deep queues against their `addr`, `subver`, `conntime`, and `network` from the RPC data.
4. For peers with deep queues, check `lastrecv` and `lastsend` timestamps from the RPC data — a large gap between lastrecv and now indicates a stalled peer.
5. Check mempool transaction volume — a sudden mempool surge will naturally increase INV queue depths across all peers.
6. Conclude: determine if this is caused by stalled peers or a legitimate transaction volume spike. Document the peer IP(s) with deep queues and their drain behavior for the observation record. Reference: https://b10c.me/observations/15-inv-to-send-queue/"#.into()
}

pub(super) fn inv_queue_extreme() -> Cow<'static, str> {
    r#"1. This is a CRITICAL alert — at least one peer has an INV queue exceeding 50,000 entries.
2. Immediately identify which peer(s) have extreme queue depths by querying per-peer INV queue metrics (`peerobserver_rpc_peer_info_invtosend_max`).
3. Cross-reference with the RPC Data section above — match the peer ID to get the full peer details including `addr`, `subver`, `conntime`, and `network`.
4. Check `lastrecv` and `lastsend` timestamps from the RPC data — a stalled peer stops draining its INV queue and will show stale activity timestamps.
5. Compare across hosts — is the same peer causing problems on multiple nodes?
6. Conclude: this almost always indicates a stalled or extremely slow peer. Document the peer IP, its user agent, queue depth, and last activity timestamps for the observation record. Reference: https://b10c.me/observations/15-inv-to-send-queue/"#.into()
}

pub(super) fn high_cpu(ctx: &InstructionContext) -> Cow<'static, str> {
    format!(
        r#"1. Query `1 - avg(rate(node_cpu_seconds_total{{mode="idle",host="{pq_host}"}}[5m]))` to confirm CPU usage exceeds 90%. Note: the raw idle metric measures idle time, so a low idle rate (near 0) confirms high CPU usage.
2. Check per-process CPU usage via process exporter to identify which process is consuming the most CPU.
2b. If a "Profiling Data" section is present above, examine the top CPU functions.
    This shows which functions consumed the most CPU during the alert window.
    Correlate the hot functions with the thread metrics — e.g., if b-scriptch threads are saturated
    and the top functions are script verification, that confirms block validation load.
3. Check per-thread CPU saturation: query `sum by(threadname) (rate(namedprocess_namegroup_thread_cpu_seconds_total{{host="{pq_host}",threadname=~"b-msghand|b-net|b-addcon|b-opencon|b-scheduler|b-scriptch.*|bitcoind"}}[5m]))`. The `sum by(threadname)` collapses user+system CPU per thread. A value near 1.0 means that thread is using 100% of one CPU core. Thread roles: b-msghand (message processing — most common bottleneck during mass-broadcast), b-net (network I/O), b-addcon/b-opencon (connection management), b-scheduler (task scheduling), b-scriptch.N (script verification — CPU-intensive during block validation and catchup), bitcoind (main thread).
4. Check the Debug Log section above for correlated events — look for block validation (`[bench]`), message floods (`[net]`), or other activity that coincides with the CPU spike.
5. Check if the node is in IBD — reference the pre-fetched `getblockchaininfo` RPC data (look for `initialblockdownload` field). High CPU during IBD is completely normal and expected.
6. Check if there's a header-block gap — the node may be catching up on validation.
7. Common causes: Bitcoin Core IBD (expected), heavy block validation after a long stale period, single-thread saturation during mass-broadcast events, or a runaway process.
8. Conclude: determine if the high CPU is expected (IBD, catchup, known mass-broadcast) or unexpected (runaway process, bug). Only unexpected sustained high CPU requires action."#,
        pq_host = ctx.pq_host,
    ).into()
}

pub(super) fn thread_saturation(ctx: &InstructionContext) -> Cow<'static, str> {
    format!(
        r#"1. Confirm saturation with PromQL: query `sum by(host, threadname) (rate(namedprocess_namegroup_thread_cpu_seconds_total{{host="{pq_host}",threadname="{pq_threadname}"}}[5m]))` — the `sum by` collapses user+system CPU. A value near 1.0 confirms 100% of one CPU core.
1b. If a "Profiling Data" section is present above, check which functions dominate CPU time.
    Correlate with the saturated thread name — e.g., b-msghand saturation with ProcessMessage()
    at the top confirms message-handling load, while b-scriptch saturation with VerifyScript()
    confirms block validation.
2. Check IBD status via pre-fetched `getblockchaininfo` RPC data (look for the `initialblockdownload` field). Thread saturation during IBD is expected — all threads work harder during initial sync.
3. Thread role context: b-msghand (message processing — the most common bottleneck; saturates during mass-broadcast events like large inv floods), b-net (network I/O — saturates under high peer count or bandwidth), b-addcon/b-opencon (connection management), b-scheduler (task scheduling), b-scriptch.N (script verification — CPU-intensive during block validation and catchup), bitcoind (main thread — typically low CPU outside startup).
4. Check the Debug Log section above for correlated events — look for block validation (`[bench]`), message floods (`[net]`), or other activity that coincides with the thread saturation.
5. Check for correlated events: query message rates (`peerobserver_p2p_message_count`), block events (`peerobserver_validation_block_connected_latest_height`), and connection changes to identify what triggered the saturation.
6. Cross-host comparison: query the same thread's CPU rate on other hosts to distinguish node-specific issues from network-wide events (e.g., mass-broadcast affects all nodes).
7. Conclude: IBD or mass-broadcast thread saturation is expected and benign. Sustained saturation outside these contexts (especially b-msghand without correlated message spikes) needs investigation — it may indicate a stuck peer, consensus bug, or pathological message pattern."#,
        pq_host = ctx.pq_host,
        pq_threadname = ctx.pq_threadname,
    ).into()
}

pub(super) fn thread_saturation_no_threadname() -> Cow<'static, str> {
    "The alert was fired without a `threadname` label. \
     Investigation cannot proceed without it — the threadname \
     is required to query per-thread CPU metrics. \
     Check the Alertmanager rule configuration."
        .into()
}
