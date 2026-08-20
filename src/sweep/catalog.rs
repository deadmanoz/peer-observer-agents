//! The metric catalog the sweep walks.
//!
//! Curated rather than exhaustive. The fleet exports 217 `peerobserver_*`
//! metrics; sweeping all of them would bury real signal under derivative
//! restatements of the same thing (a histogram's `_sum`, `_count` and `_bucket`
//! are one signal, not three).
//!
//! Weighting is deliberately skewed toward network-level / P2P signals over
//! node-software health, per the user's scope decision. Every entry carries the
//! detection playbook or standing health question it serves, so a digest line
//! can explain *why* an operator should care without a model in the loop.

/// Which detectors to run for a given metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detector {
    /// Compare the recent window against this series' own recent history.
    Residual,
    /// Compare each host against its peers at the same instant.
    PeerGroup,
    /// Compare two adjacent windows for a level shift.
    ChangePoint,
}

/// One swept signal.
#[derive(Debug, Clone)]
pub(crate) struct MetricSpec {
    /// Short display name used in the digest.
    pub(crate) name: &'static str,
    /// PromQL producing one series per host.
    pub(crate) query: &'static str,
    /// Relative importance, multiplied into the interestingness score.
    /// Network-level/P2P signals sit at 1.0+; node-health signals below.
    pub(crate) weight: f64,
    /// Why this matters, cited to the plan's playbook or standing question.
    pub(crate) rationale: &'static str,
    /// Detectors to apply.
    pub(crate) detectors: &'static [Detector],
    /// Minimum absolute change, in the metric's own units, before a deviation is
    /// worth reporting.
    ///
    /// Statistical significance is not the same as operational significance. A
    /// host announcing 0.0034 addresses/sec against peers at exactly 0.0 is a
    /// large *robust* deviation and a meaningless *absolute* one, but it clears
    /// the z threshold purely because the peer baseline is zero — the first live
    /// digest surfaced several of these and they were pure noise. This is the
    /// effect-size floor that suppresses them, and it has to be per-metric
    /// because these signals share no units: connection counts, per-second
    /// rates, and nanosecond durations cannot answer to one global constant.
    pub(crate) min_absolute: f64,
}

const ALL: &[Detector] = &[
    Detector::Residual,
    Detector::PeerGroup,
    Detector::ChangePoint,
];
const RESID_PEER: &[Detector] = &[Detector::Residual, Detector::PeerGroup];
const PEER_CHANGE: &[Detector] = &[Detector::PeerGroup, Detector::ChangePoint];

/// The default catalog.
///
/// Rates are computed over 10m windows: long enough to survive the 10s RPC and
/// event cadence without aliasing, short enough that a burst is still visible.
pub(crate) fn default_catalog() -> Vec<MetricSpec> {
    vec![
        // ── Spy / surveillance infrastructure (playbook 1) ────────────
        MetricSpec {
            name: "linkinglion_inbound",
            query: "peerobserver_conn_inbound_list_linkinglion",
            weight: 1.6,
            rationale: "Known spy-cluster inbound presence (playbook 1: spy-client fingerprinting)",
            detectors: RESID_PEER,
            min_absolute: 1.0, // one connection
        },
        MetricSpec {
            name: "private_tx_broadcast",
            query: "peerobserver_conn_private_transaction_broadcast",
            weight: 1.5,
            rationale: "Private broadcast monitoring — the knowledge base's flagged first new-analysis win",
            detectors: RESID_PEER,
            min_absolute: 1.0, // one broadcast
        },
        // ── Addr-layer attacks (playbook 9, standing question 2) ──────
        MetricSpec {
            name: "addr_rate",
            query: "sum by (host) (rate(peerobserver_p2p_addr_addresses_count[10m]))",
            weight: 1.4,
            rationale: "Addr-relay spam / addrman poisoning (playbook 9; v1's dominant alert family)",
            detectors: ALL,
            min_absolute: 0.5, // addresses/sec
        },
        MetricSpec {
            name: "addrv2_rate",
            query: "sum by (host) (rate(peerobserver_p2p_addrv2_addresses_count[10m]))",
            weight: 1.4,
            rationale: "Addrv2 relay volume — same attack surface as addr (playbook 9)",
            detectors: ALL,
            min_absolute: 0.5, // addresses/sec
        },
        // The histogram carries `timestamp_offset={future,past}` and
        // `direction={inbound,outbound}` labels, and its top bucket is +Inf, so a
        // mean offset is not a usable statistic — extreme entries drag it to
        // implausible values (an early version of this catalog reported a ~4-year
        // "average" skew). Count the inbound future-dated entries instead: that
        // is the actual addrman-poisoning signature, and a rate is robust to the
        // unbounded tail. Outbound is excluded — those are our own announcements.
        MetricSpec {
            name: "addr_future_timestamps",
            query: "sum by (host) (rate(peerobserver_p2p_addr_timestamp_offset_seconds_count{timestamp_offset=\"future\",direction=\"inbound\"}[10m]))",
            weight: 1.5,
            rationale: "Inbound addr entries dated in the future — the documented addrman-poisoning signature",
            detectors: ALL,
            min_absolute: 0.5, // entries/sec
        },
        MetricSpec {
            name: "self_announcements",
            query: "sum by (host) (rate(peerobserver_p2p_address_selfannouncements[10m]))",
            weight: 1.2,
            rationale: "Self-announcement rate — addr spam campaign indicator",
            detectors: RESID_PEER,
            min_absolute: 0.05, // announcements/sec
        },
        MetricSpec {
            name: "subnet_announcements",
            query: "sum by (host) (rate(peerobserver_p2p_address_subnetannouncements[10m]))",
            weight: 1.3,
            rationale: "Subnet-concentrated announcements — /16 concentration signature of addr poisoning",
            detectors: RESID_PEER,
            min_absolute: 0.05, // announcements/sec
        },
        // ── Connection churn / eviction (playbook 2, question 8) ──────
        MetricSpec {
            name: "inbound_conns",
            query: "peerobserver_conn_inbound_current",
            weight: 1.2,
            rationale: "Inbound connection level — flood/eclipse indicator (playbook 2, question 8)",
            detectors: ALL,
            min_absolute: 5.0, // connections
        },
        MetricSpec {
            name: "outbound_conns",
            query: "peerobserver_conn_outbound_current",
            weight: 1.3,
            rationale: "Outbound connection level — partition/eclipse indicator (question 8)",
            detectors: ALL,
            min_absolute: 2.0, // connections
        },
        MetricSpec {
            name: "evicted_inbound",
            query: "sum by (host) (rate(peerobserver_conn_evicted_inbound[10m]))",
            weight: 1.3,
            rationale: "Eviction churn — inbound flood signature (playbook 2, cheapest high-signal check)",
            detectors: ALL,
            min_absolute: 0.1, // evictions/sec
        },
        MetricSpec {
            name: "misbehaving",
            query: "sum by (host) (rate(peerobserver_conn_misbehaving[10m]))",
            weight: 1.2,
            rationale: "Misbehaviour rate — protocol violations / costumed clients (playbook 11)",
            detectors: RESID_PEER,
            min_absolute: 0.05, // events/sec
        },
        // ── Relay pressure / DoS (playbook 3, question 9) ─────────────
        MetricSpec {
            name: "invtosend_max",
            query: "peerobserver_rpc_peer_info_invtosend_max",
            weight: 1.4,
            rationale: "inv-to-send queue depth — the one documented network-wide DoS (playbook 3, question 9)",
            detectors: ALL,
            min_absolute: 100.0, // queued invs
        },
        MetricSpec {
            name: "outbound_large_invs",
            query: "sum by (host) (rate(peerobserver_p2p_invs_outbound_large[10m]))",
            weight: 1.2,
            rationale: "Oversized outbound INV batches — relay-queue bloat precursor (playbook 3)",
            detectors: RESID_PEER,
            min_absolute: 0.05, // messages/sec
        },
        MetricSpec {
            name: "ping_duration",
            query: "peerobserver_p2pextractor_ping_duration_nanoseconds",
            weight: 1.1,
            rationale: "Protocol ping RTT — node processing backlog (exported by v1, never consumed)",
            detectors: RESID_PEER,
            min_absolute: 20000000.0, // 20ms in nanoseconds
        },
        // ── Block / consensus layer (playbooks 4, 6, 10; question 1) ──
        MetricSpec {
            name: "block_connect_time",
            query: "peerobserver_validation_block_connected_latest_connection_time",
            weight: 1.3,
            rationale: "Block validation time — propagation degradation (playbook 10, question 1)",
            detectors: PEER_CHANGE,
            min_absolute: 100000.0, // 100ms in microseconds
        },
        MetricSpec {
            name: "compact_block_extra_txs",
            query: "sum by (host) (rate(peerobserver_log_compact_block_reconstruction_txs_extra_pool[10m]))",
            weight: 1.2,
            rationale: "Compact-block reconstruction quality — mempool divergence proxy (question 5)",
            detectors: RESID_PEER,
            min_absolute: 0.5, // txs/sec
        },
        // ── Mempool / policy (questions 5, 6, 7) ──────────────────────
        MetricSpec {
            name: "mempool_rejected",
            query: "sum by (host) (rate(peerobserver_mempool_rejected[10m]))",
            weight: 1.2,
            rationale: "Mempool rejections — policy divergence across our Core/Knots/Libre fleet (question 5)",
            detectors: ALL,
            min_absolute: 1.0, // rejections/sec
        },
        MetricSpec {
            name: "mempool_replaced",
            query: "sum by (host) (rate(peerobserver_mempool_replaced[10m]))",
            weight: 1.1,
            rationale: "Replacement rate — replacement-cycling patterns (question 7)",
            detectors: RESID_PEER,
            min_absolute: 0.5, // replacements/sec
        },
        MetricSpec {
            name: "mempool_added",
            query: "sum by (host) (rate(peerobserver_mempool_added[10m]))",
            weight: 1.0,
            rationale: "Mempool intake — fee-pressure regime context (question 6)",
            detectors: PEER_CHANGE,
            min_absolute: 1.0, // txs/sec
        },
        // ── Node health (deliberately lower weight) ───────────────────
        MetricSpec {
            name: "log_events",
            query: "sum by (host) (rate(peerobserver_log_events[10m]))",
            weight: 0.7,
            rationale: "debug.log event rate — instrumentation liveness, not a network signal",
            detectors: &[Detector::PeerGroup],
            min_absolute: 1.0, // events/sec
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_non_empty_and_well_formed() {
        let c = default_catalog();
        assert!(c.len() >= 15, "catalog too small: {}", c.len());
        for m in &c {
            assert!(!m.name.is_empty());
            assert!(!m.query.is_empty());
            assert!(!m.rationale.is_empty(), "{} lacks rationale", m.name);
            assert!(m.weight > 0.0, "{} has non-positive weight", m.name);
            assert!(!m.detectors.is_empty(), "{} has no detectors", m.name);
        }
    }

    #[test]
    fn metric_names_are_unique() {
        let c = default_catalog();
        let mut names: Vec<&str> = c.iter().map(|m| m.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate metric names in catalog");
    }

    #[test]
    fn network_signals_outweigh_node_health() {
        // The user's scope decision: network-level/P2P over node-software health.
        // Encode it as a test so a later edit cannot silently invert the priority.
        let c = default_catalog();
        let health: Vec<&MetricSpec> = c.iter().filter(|m| m.name == "log_events").collect();
        let network: Vec<&MetricSpec> = c
            .iter()
            .filter(|m| ["addr_rate", "linkinglion_inbound", "invtosend_max"].contains(&m.name))
            .collect();
        assert!(!health.is_empty() && !network.is_empty());
        let max_health = health.iter().map(|m| m.weight).fold(0.0_f64, f64::max);
        let min_network = network.iter().map(|m| m.weight).fold(f64::MAX, f64::min);
        assert!(
            min_network > max_health,
            "node-health weight {max_health} >= network weight {min_network}"
        );
    }
}
