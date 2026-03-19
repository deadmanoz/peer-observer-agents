use std::borrow::Cow;

pub(super) fn misbehavior_spike() -> Cow<'static, str> {
    r#"1. Query `peerobserver_anomaly:level{anomaly_name="misbehavior_rate"}` and compare against `peerobserver_anomaly:upper_band` to confirm the spike.
2. Check the RPC Data section above for per-peer details — review each peer's `addr`, `subver`, `conntime`, `network`, and `connection_type` to identify peers with elevated misbehavior scores.
3. Check the Debug Log section above for misbehavior details — look for `Misbehaving: peer N ...` lines that identify the specific protocol violation and the peer involved.
4. Cross-reference the Prometheus misbehavior metrics with the RPC peer list to narrow down which peer(s) are generating the misbehavior score by IP.
5. For the peer(s) with elevated misbehavior, check their connection age and user agent — short-lived connections with unusual user agents are more notable.
6. Compare across hosts — are other nodes seeing misbehavior from the same IP(s)?
7. Conclude: determine if this is a protocol attack, a buggy node implementation, or an eclipse attempt. Document the peer IP(s), their user agents, and the specific misbehavior type for the observation record."#.into()
}
