use std::borrow::Cow;

pub(super) fn full() -> Cow<'static, str> {
    r#"1. Check the RPC Data section above — `getmempoolinfo` provides the exact mempool `size` (tx count), `bytes`, `usage` (memory), `maxmempool`, and `mempoolminfee` directly from the node.
2. Check the Debug Log section above for mempool rejection reasons — look for `[mempoolrej]` lines showing rejected transactions with fee data and rejection codes.
3. Calculate the fill percentage from the RPC data: `usage / maxmempool * 100`. Check `mempoolminfee` — this is the minimum feerate for new transactions to be accepted.
4. Query Prometheus for the trend — is mempool usage spiking suddenly or growing gradually?
5. Compare across hosts — if all nodes have full mempools, this is a network-wide fee event.
6. Check if this correlates with any unusual P2P message patterns (transaction flooding).
7. Conclude: a full mempool is usually caused by high on-chain demand (fee market event) and is not actionable unless caused by spam. Note the current min feerate from the RPC data for context."#.into()
}

pub(super) fn empty() -> Cow<'static, str> {
    r#"1. Check the RPC Data section above — `getmempoolinfo` provides the exact mempool `size` (tx count) directly from the node to confirm it is truly empty.
2. Check the Debug Log section above for mempool-related events — look for `[mempool]` and `[mempoolrej]` lines that may explain why the mempool is empty (e.g., all transactions being rejected).
3. An empty mempool for 5+ minutes is very abnormal — the Bitcoin network constantly generates transactions.
4. Check peer count — if the node has no peers, it can't receive transactions.
5. Check if the node is in IBD — nodes in IBD don't accept mempool transactions.
6. Compare across hosts — if other nodes have normal mempools, this node is likely disconnected or misconfigured.
7. Conclude: an empty mempool almost always indicates the node is not receiving transactions, either due to network isolation, IBD, or a configuration issue like `-blocksonly` mode."#.into()
}
