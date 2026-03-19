use std::borrow::Cow;

pub(super) fn addr_spike() -> Cow<'static, str> {
    r#"1. Query `peerobserver_anomaly:level{anomaly_name="addr_message_rate"}` and compare against `peerobserver_anomaly:upper_band` to confirm spike magnitude.
2. Check the RPC Data section above for per-peer details — look for peers with a non-zero `addr_rate_limited` count and high `bytesrecv_per_msg.addr` values to identify which peer(s) are the primary addr sources by IP.
3. For the top sender(s), check their connection age, network type, and user agent from the RPC data.
4. Determine the pattern: is it a single peer with high volume, or multiple peers sending bursts simultaneously?
5. Check if other hosts see the same spike from the same source IP(s) via Prometheus.
6. Conclude: identify whether this is addr spam/reconnaissance, a legitimate addr relay surge (e.g., after a network event), or a buggy peer implementation. Document the source peer IP(s), their addr byte volumes, and user agents for the observation record."#.into()
}
