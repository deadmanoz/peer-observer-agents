use super::KnownAlert;

/// Whether a fast-path self-resolution check compares against the upper or lower band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BandDirection {
    /// Alert resolves when level drops BELOW the upper band (spike alerts).
    Upper,
    /// Alert resolves when level recovers ABOVE the lower band (drop alerts).
    Lower,
}

/// Specification for a fast-path self-resolution check on anomaly-band alerts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FastPathSpec {
    pub(crate) anomaly_name: &'static str,
    pub(crate) band: BandDirection,
}

/// RPC methods and field filters for a given alert type.
pub(crate) struct RpcSpec {
    /// RPC methods to prefetch (empty = no RPC needed).
    pub(crate) methods: &'static [&'static str],
    /// getpeerinfo fields to keep when filtering.
    pub(crate) peer_info_fields: &'static [&'static str],
    /// Per-message byte counter keys (empty = keep all).
    pub(crate) per_msg_keys: &'static [&'static str],
}

/// Debug log categories and inclusion flags for a given alert type.
pub(crate) struct DebugLogSpec {
    pub(crate) categories: &'static [&'static str],
    pub(crate) include_uncategorized: bool,
}

/// Profiling spec — presence signals "fetch profile."
pub(crate) struct ProfilingSpec;

/// Complete data-fetching specification for a known alert.
pub(crate) struct AlertSpec {
    pub(crate) rpc: RpcSpec,
    pub(crate) debug_logs: DebugLogSpec,
    pub(crate) profiling: Option<ProfilingSpec>,
    pub(crate) fast_path: Option<FastPathSpec>,
}

impl KnownAlert {
    /// Returns the data-fetching specification for this alert.
    ///
    /// Exhaustive match with no wildcard — adding a new `KnownAlert` variant
    /// without a spec arm is a compile error.
    pub(crate) fn spec(&self) -> AlertSpec {
        match self {
            // ── Connection alerts ────────────────────────────────────────
            KnownAlert::InboundConnectionDrop => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo", "getnetworkinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "connection_type",
                        "inbound",
                    ],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: Some(FastPathSpec {
                    anomaly_name: "inbound_connections",
                    band: BandDirection::Lower,
                }),
            },

            KnownAlert::OutboundConnectionDrop => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo", "getnetworkinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "connection_type",
                        "inbound",
                    ],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: Some(FastPathSpec {
                    anomaly_name: "outbound_connections",
                    band: BandDirection::Lower,
                }),
            },

            KnownAlert::TotalPeersDrop => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo", "getnetworkinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "connection_type",
                        "inbound",
                    ],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::NetworkInactive => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getnetworkinfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            // ── P2P message alerts ──────────────────────────────────────
            KnownAlert::AddressMessageSpike => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "addr_rate_limited",
                        "bytesrecv_per_msg",
                        "connection_type",
                        "inbound",
                    ],
                    per_msg_keys: &["addr"],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: Some(FastPathSpec {
                    anomaly_name: "addr_message_rate",
                    band: BandDirection::Upper,
                }),
            },

            // ── Security alerts ─────────────────────────────────────────
            KnownAlert::MisbehaviorSpike => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "connection_type",
                        "inbound",
                    ],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: Some(FastPathSpec {
                    anomaly_name: "misbehavior_rate",
                    band: BandDirection::Upper,
                }),
            },

            // ── Performance / queue alerts ───────────────────────────────
            KnownAlert::INVQueueDepthAnomaly => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "inbound",
                        "lastrecv",
                        "lastsend",
                        "bytessent_per_msg",
                        "connection_type",
                    ],
                    per_msg_keys: &["inv", "tx", "getdata"],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: Some(FastPathSpec {
                    anomaly_name: "invtosend_mean",
                    band: BandDirection::Upper,
                }),
            },

            KnownAlert::INVQueueDepthExtreme => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getpeerinfo"],
                    peer_info_fields: &[
                        "id",
                        "addr",
                        "network",
                        "subver",
                        "conntime",
                        "inbound",
                        "lastrecv",
                        "lastsend",
                        "bytessent_per_msg",
                        "connection_type",
                    ],
                    per_msg_keys: &["inv", "tx", "getdata"],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::HighCPU => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench", "net"],
                    include_uncategorized: false,
                },
                profiling: Some(ProfilingSpec),
                fast_path: None,
            },

            KnownAlert::ThreadSaturation => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench", "net"],
                    include_uncategorized: false,
                },
                profiling: Some(ProfilingSpec),
                fast_path: None,
            },

            // ── Chain health alerts ─────────────────────────────────────
            KnownAlert::BlockStale => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench", "cmpctblock"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::BlockStaleCritical => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench", "cmpctblock"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::BitcoinCoreRestart => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo", "uptime"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["net", "validation"],
                    include_uncategorized: true,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::NodeInIBD => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::HeaderBlockGap => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getblockchaininfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["validation", "bench", "cmpctblock"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            // ── Mempool alerts ──────────────────────────────────────────
            KnownAlert::MempoolFull => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getmempoolinfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["mempool", "mempoolrej"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::MempoolEmpty => AlertSpec {
                rpc: RpcSpec {
                    methods: &["getmempoolinfo"],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &["mempool", "mempoolrej"],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            // ── Infrastructure alerts ───────────────────────────────────
            KnownAlert::ServiceFailed => AlertSpec {
                rpc: RpcSpec {
                    methods: &[],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &[],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::MetricsToolDown => AlertSpec {
                rpc: RpcSpec {
                    methods: &[],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &[],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::DiskSpaceLow => AlertSpec {
                rpc: RpcSpec {
                    methods: &[],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &[],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            KnownAlert::HighMemory => AlertSpec {
                rpc: RpcSpec {
                    methods: &[],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &[],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },

            // ── Meta alerts ─────────────────────────────────────────────
            KnownAlert::AnomalyDetectionDown => AlertSpec {
                rpc: RpcSpec {
                    methods: &[],
                    peer_info_fields: &[],
                    per_msg_keys: &[],
                },
                debug_logs: DebugLogSpec {
                    categories: &[],
                    include_uncategorized: false,
                },
                profiling: None,
                fast_path: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_returns_a_spec() {
        for alert in KnownAlert::ALL {
            // Guaranteed by exhaustive match, but test it explicitly.
            let _ = alert.spec();
        }
    }

    // ── Fast-path correctness (explicit expected values) ────────────

    #[test]
    fn fast_path_included_alerts_have_correct_specs() {
        let cases: &[(KnownAlert, &str, BandDirection)] = &[
            (
                KnownAlert::InboundConnectionDrop,
                "inbound_connections",
                BandDirection::Lower,
            ),
            (
                KnownAlert::OutboundConnectionDrop,
                "outbound_connections",
                BandDirection::Lower,
            ),
            (
                KnownAlert::AddressMessageSpike,
                "addr_message_rate",
                BandDirection::Upper,
            ),
            (
                KnownAlert::MisbehaviorSpike,
                "misbehavior_rate",
                BandDirection::Upper,
            ),
            (
                KnownAlert::INVQueueDepthAnomaly,
                "invtosend_mean",
                BandDirection::Upper,
            ),
        ];

        for (alert, expected_anomaly, expected_band) in cases {
            let spec = alert.spec();
            let fp = spec
                .fast_path
                .as_ref()
                .unwrap_or_else(|| panic!("{:?} should have a fast_path spec", alert));
            assert_eq!(fp.anomaly_name, *expected_anomaly, "for {:?}", alert);
            assert_eq!(fp.band, *expected_band, "for {:?}", alert);
        }
    }

    #[test]
    fn fast_path_excluded_alerts_derived_from_catalog() {
        let excluded: Vec<_> = KnownAlert::ALL
            .iter()
            .filter(|a| a.spec().fast_path.is_none())
            .collect();
        assert!(excluded.len() > 10, "most alerts should not have fast-path");
        for alert in &excluded {
            assert!(alert.spec().fast_path.is_none());
        }
    }

    // ── RPC spec correctness ────────────────────────────────────────

    #[test]
    fn connection_drops_need_peerinfo_and_netinfo() {
        for alert in &[
            KnownAlert::InboundConnectionDrop,
            KnownAlert::OutboundConnectionDrop,
            KnownAlert::TotalPeersDrop,
        ] {
            let spec = alert.spec();
            assert_eq!(
                spec.rpc.methods,
                &["getpeerinfo", "getnetworkinfo"],
                "for {:?}",
                alert
            );
        }
    }

    #[test]
    fn addr_spike_rpc_spec_has_addr_rate_limited_and_bytesrecv() {
        let spec = KnownAlert::AddressMessageSpike.spec();
        assert!(spec.rpc.peer_info_fields.contains(&"addr_rate_limited"));
        assert!(spec.rpc.peer_info_fields.contains(&"bytesrecv_per_msg"));
        assert_eq!(spec.rpc.per_msg_keys, &["addr"]);
    }

    #[test]
    fn inv_queue_rpc_spec_has_timestamps_and_bytessent() {
        for alert in &[
            KnownAlert::INVQueueDepthAnomaly,
            KnownAlert::INVQueueDepthExtreme,
        ] {
            let spec = alert.spec();
            assert!(spec.rpc.peer_info_fields.contains(&"lastrecv"));
            assert!(spec.rpc.peer_info_fields.contains(&"lastsend"));
            assert!(spec.rpc.peer_info_fields.contains(&"bytessent_per_msg"));
            assert_eq!(spec.rpc.per_msg_keys, &["inv", "tx", "getdata"]);
        }
    }

    #[test]
    fn infrastructure_alerts_have_empty_rpc() {
        let infra: Vec<_> = KnownAlert::ALL
            .iter()
            .filter(|a| a.kind() == crate::alerts::AlertKind::Infrastructure)
            .collect();
        assert!(!infra.is_empty());
        for alert in infra {
            assert!(alert.spec().rpc.methods.is_empty(), "for {:?}", alert);
        }
    }

    // ── Profiling spec correctness ──────────────────────────────────

    #[test]
    fn only_cpu_thread_alerts_have_profiling() {
        let with_profiling: Vec<_> = KnownAlert::ALL
            .iter()
            .filter(|a| a.spec().profiling.is_some())
            .collect();
        assert_eq!(with_profiling.len(), 2);
        assert!(with_profiling.contains(&&KnownAlert::HighCPU));
        assert!(with_profiling.contains(&&KnownAlert::ThreadSaturation));
    }

    // ── Debug log spec correctness ──────────────────────────────────

    #[test]
    fn restart_alert_includes_uncategorized() {
        let spec = KnownAlert::BitcoinCoreRestart.spec();
        assert!(spec.debug_logs.include_uncategorized);
    }

    #[test]
    fn no_other_alert_includes_uncategorized() {
        let others: Vec<_> = KnownAlert::ALL
            .iter()
            .filter(|a| **a != KnownAlert::BitcoinCoreRestart)
            .filter(|a| a.spec().debug_logs.include_uncategorized)
            .collect();
        assert!(
            others.is_empty(),
            "only BitcoinCoreRestart should include_uncategorized, but found: {:?}",
            others
        );
    }

    #[test]
    fn infrastructure_meta_alerts_have_empty_debug_logs() {
        for alert in KnownAlert::ALL {
            let kind = alert.kind();
            if kind == crate::alerts::AlertKind::Infrastructure
                || kind == crate::alerts::AlertKind::Meta
            {
                let spec = alert.spec();
                assert!(
                    spec.debug_logs.categories.is_empty(),
                    "{:?} should have empty debug log categories",
                    alert
                );
            }
        }
    }
}
