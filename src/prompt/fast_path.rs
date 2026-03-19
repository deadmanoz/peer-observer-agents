pub(super) use crate::alerts::{BandDirection, FastPathSpec};

/// Return a fast-path spec for alerts that use anomaly-band detection,
/// or `None` for alerts where a simple level-vs-band check is not meaningful
/// (fixed thresholds, critical operator-action alerts, non-anomaly alerts).
pub(super) fn fast_path_spec(alertname: &str) -> Option<FastPathSpec> {
    crate::alerts::KnownAlert::parse(alertname).and_then(|a| a.spec().fast_path)
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
        use crate::alerts::KnownAlert;
        let excluded: Vec<_> = KnownAlert::ALL
            .iter()
            .filter(|a| a.spec().fast_path.is_none())
            .collect();
        assert!(!excluded.is_empty());
        for alert in &excluded {
            assert!(
                fast_path_spec(alert.as_str()).is_none(),
                "fast_path_spec should return None for {:?}",
                alert
            );
        }
        // Unknown alerts also excluded
        assert!(fast_path_spec("SomeUnknownAlert").is_none());
    }
}
