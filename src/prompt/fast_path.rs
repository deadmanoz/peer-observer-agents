/// Whether a fast-path self-resolution check compares against the upper or lower band.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum BandDirection {
    /// Alert resolves when level drops BELOW the upper band (spike alerts).
    Upper,
    /// Alert resolves when level recovers ABOVE the lower band (drop alerts).
    Lower,
}

/// Specification for a fast-path self-resolution check on anomaly-band alerts.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct FastPathSpec {
    pub(super) anomaly_name: &'static str,
    pub(super) band: BandDirection,
}

/// Return a fast-path spec for alerts that use anomaly-band detection,
/// or `None` for alerts where a simple level-vs-band check is not meaningful
/// (fixed thresholds, critical operator-action alerts, non-anomaly alerts).
pub(super) fn fast_path_spec(alertname: &str) -> Option<FastPathSpec> {
    match alertname {
        "PeerObserverInboundConnectionDrop" => Some(FastPathSpec {
            anomaly_name: "inbound_connections",
            band: BandDirection::Lower,
        }),
        "PeerObserverOutboundConnectionDrop" => Some(FastPathSpec {
            anomaly_name: "outbound_connections",
            band: BandDirection::Lower,
        }),
        "PeerObserverAddressMessageSpike" => Some(FastPathSpec {
            anomaly_name: "addr_message_rate",
            band: BandDirection::Upper,
        }),
        "PeerObserverMisbehaviorSpike" => Some(FastPathSpec {
            anomaly_name: "misbehavior_rate",
            band: BandDirection::Upper,
        }),
        "PeerObserverINVQueueDepthAnomaly" => Some(FastPathSpec {
            anomaly_name: "invtosend_mean",
            band: BandDirection::Upper,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_spec_included_alerts() {
        let cases: &[(&str, &str, BandDirection)] = &[
            (
                "PeerObserverInboundConnectionDrop",
                "inbound_connections",
                BandDirection::Lower,
            ),
            (
                "PeerObserverOutboundConnectionDrop",
                "outbound_connections",
                BandDirection::Lower,
            ),
            (
                "PeerObserverAddressMessageSpike",
                "addr_message_rate",
                BandDirection::Upper,
            ),
            (
                "PeerObserverMisbehaviorSpike",
                "misbehavior_rate",
                BandDirection::Upper,
            ),
            (
                "PeerObserverINVQueueDepthAnomaly",
                "invtosend_mean",
                BandDirection::Upper,
            ),
        ];

        for (name, expected_anomaly, expected_band) in cases {
            let spec = fast_path_spec(name);
            assert!(
                spec.is_some(),
                "fast_path_spec should return Some for {name}"
            );
            let spec = spec.unwrap();
            assert_eq!(
                spec.anomaly_name, *expected_anomaly,
                "wrong anomaly_name for {name}"
            );
            assert_eq!(spec.band, *expected_band, "wrong band direction for {name}");
        }
    }

    #[test]
    fn fast_path_spec_excluded_alerts() {
        let excluded = [
            "PeerObserverTotalPeersDrop",
            "PeerObserverNetworkInactive",
            "PeerObserverINVQueueDepthExtreme",
            "PeerObserverBlockStale",
            "PeerObserverBlockStaleCritical",
            "PeerObserverBitcoinCoreRestart",
            "PeerObserverThreadSaturation",
            "PeerObserverServiceFailed",
            "PeerObserverMetricsToolDown",
            "PeerObserverAnomalyDetectionDown",
            "SomeUnknownAlert",
        ];

        for name in &excluded {
            assert!(
                fast_path_spec(name).is_none(),
                "fast_path_spec should return None for {name}"
            );
        }
    }
}
