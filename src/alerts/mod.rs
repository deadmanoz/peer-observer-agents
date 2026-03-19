mod spec;

pub(crate) use spec::{BandDirection, FastPathSpec};

/// Declarative macro that generates a `KnownAlert` enum with:
/// - `as_str()` → Alertmanager string name
/// - `parse(s)` → `Option<KnownAlert>` from string
/// - `kind()` → `AlertKind` classification
/// - `ALL` → constant slice of all variants
macro_rules! define_alerts {
    (
        $(
            $variant:ident => $name:literal, kind: $kind:ident,
        )*
    ) => {
        /// Known alert types in the peer-observer monitoring system.
        ///
        /// Each variant corresponds to an Alertmanager alert name. Adding a new
        /// variant requires a `spec()` arm in `spec.rs` and an instruction
        /// dispatcher arm in `prompt/instructions/mod.rs` — both enforced by
        /// exhaustive matches with no wildcard.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub(crate) enum KnownAlert {
            $( $variant, )*
        }

        impl KnownAlert {
            /// All known alert variants, for use in catalog-driven tests.
            #[allow(dead_code)]
            pub(crate) const ALL: &'static [KnownAlert] = &[
                $( KnownAlert::$variant, )*
            ];

            /// The Alertmanager string name for this alert.
            #[allow(dead_code)]
            pub(crate) fn as_str(&self) -> &'static str {
                match self {
                    $( KnownAlert::$variant => $name, )*
                }
            }

            /// Parse an Alertmanager alert name into a `KnownAlert`, or `None`
            /// for unknown alerts.
            pub(crate) fn parse(s: &str) -> Option<KnownAlert> {
                match s {
                    $( $name => Some(KnownAlert::$variant), )*
                    _ => None,
                }
            }

            /// The broad category of this alert.
            #[allow(dead_code)]
            pub(crate) fn kind(&self) -> AlertKind {
                match self {
                    $( KnownAlert::$variant => AlertKind::$kind, )*
                }
            }
        }
    };
}

/// Broad classification of alerts for grouping and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Used in tests and upcoming Phase 3 instruction split.
pub(crate) enum AlertKind {
    Connection,
    P2pMessage,
    Security,
    Performance,
    ChainHealth,
    Mempool,
    Infrastructure,
    Meta,
}

define_alerts! {
    InboundConnectionDrop    => "PeerObserverInboundConnectionDrop",    kind: Connection,
    OutboundConnectionDrop   => "PeerObserverOutboundConnectionDrop",   kind: Connection,
    TotalPeersDrop           => "PeerObserverTotalPeersDrop",           kind: Connection,
    NetworkInactive          => "PeerObserverNetworkInactive",          kind: Connection,
    AddressMessageSpike      => "PeerObserverAddressMessageSpike",      kind: P2pMessage,
    MisbehaviorSpike         => "PeerObserverMisbehaviorSpike",         kind: Security,
    INVQueueDepthAnomaly     => "PeerObserverINVQueueDepthAnomaly",     kind: Performance,
    INVQueueDepthExtreme     => "PeerObserverINVQueueDepthExtreme",     kind: Performance,
    HighCPU                  => "PeerObserverHighCPU",                  kind: Performance,
    ThreadSaturation         => "PeerObserverThreadSaturation",         kind: Performance,
    BlockStale               => "PeerObserverBlockStale",               kind: ChainHealth,
    BlockStaleCritical       => "PeerObserverBlockStaleCritical",       kind: ChainHealth,
    BitcoinCoreRestart       => "PeerObserverBitcoinCoreRestart",       kind: ChainHealth,
    NodeInIBD                => "PeerObserverNodeInIBD",                kind: ChainHealth,
    HeaderBlockGap           => "PeerObserverHeaderBlockGap",           kind: ChainHealth,
    MempoolFull              => "PeerObserverMempoolFull",              kind: Mempool,
    MempoolEmpty             => "PeerObserverMempoolEmpty",             kind: Mempool,
    ServiceFailed            => "PeerObserverServiceFailed",            kind: Infrastructure,
    MetricsToolDown          => "PeerObserverMetricsToolDown",          kind: Infrastructure,
    DiskSpaceLow             => "PeerObserverDiskSpaceLow",             kind: Infrastructure,
    HighMemory               => "PeerObserverHighMemory",               kind: Infrastructure,
    AnomalyDetectionDown     => "PeerObserverAnomalyDetectionDown",     kind: Meta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_round_trip_through_parse() {
        for alert in KnownAlert::ALL {
            let s = alert.as_str();
            let parsed = KnownAlert::parse(s);
            assert_eq!(parsed, Some(*alert), "{s} should round-trip through parse");
        }
    }

    #[test]
    fn parse_returns_none_for_unknown() {
        assert_eq!(KnownAlert::parse("SomeUnknownAlert"), None);
        assert_eq!(KnownAlert::parse(""), None);
    }

    #[test]
    fn all_variants_have_a_kind() {
        for alert in KnownAlert::ALL {
            // Just verify it doesn't panic — kind() is exhaustive by construction.
            let _ = alert.kind();
        }
    }

    #[test]
    fn kind_grouping_is_correct() {
        assert_eq!(
            KnownAlert::InboundConnectionDrop.kind(),
            AlertKind::Connection
        );
        assert_eq!(
            KnownAlert::AddressMessageSpike.kind(),
            AlertKind::P2pMessage
        );
        assert_eq!(KnownAlert::MisbehaviorSpike.kind(), AlertKind::Security);
        assert_eq!(KnownAlert::HighCPU.kind(), AlertKind::Performance);
        assert_eq!(KnownAlert::BlockStale.kind(), AlertKind::ChainHealth);
        assert_eq!(KnownAlert::MempoolFull.kind(), AlertKind::Mempool);
        assert_eq!(KnownAlert::ServiceFailed.kind(), AlertKind::Infrastructure);
        assert_eq!(KnownAlert::AnomalyDetectionDown.kind(), AlertKind::Meta);
    }
}
