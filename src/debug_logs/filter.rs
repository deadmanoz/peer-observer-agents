use chrono::{DateTime, NaiveDateTime, Utc};
use tracing::debug;

use crate::prompt::sanitize;

/// Specifies which debug.log categories to include for an alert type.
pub(crate) struct LogFilter {
    /// Log categories to include (e.g., "net", "validation").
    pub categories: Vec<&'static str>,
    /// When true, also include lines with no category bracket (uncategorized
    /// Info-level messages). These have only one bracket [THREAD] with no
    /// [CATEGORY] — common during startup/shutdown sequences.
    pub include_uncategorized: bool,
}

/// Returns the log filter for a given alert name.
///
/// Uses full `PeerObserver*` alert names, matching the pattern in
/// `src/rpc/mod.rs` and `src/parca/mod.rs`.
pub(crate) fn log_filter_for_alert(alertname: &str) -> LogFilter {
    match alertname {
        // Connection/P2P alerts — net category
        "PeerObserverAddressMessageSpike"
        | "PeerObserverMisbehaviorSpike"
        | "PeerObserverInboundConnectionDrop"
        | "PeerObserverOutboundConnectionDrop"
        | "PeerObserverTotalPeersDrop"
        | "PeerObserverNetworkInactive"
        | "PeerObserverINVQueueDepthAnomaly"
        | "PeerObserverINVQueueDepthExtreme" => LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        },

        // Chain health — validation, bench, compact blocks
        "PeerObserverBlockStale"
        | "PeerObserverBlockStaleCritical"
        | "PeerObserverHeaderBlockGap" => LogFilter {
            categories: vec!["validation", "bench", "cmpctblock"],
            include_uncategorized: false,
        },

        // IBD — validation and bench
        "PeerObserverNodeInIBD" => LogFilter {
            categories: vec!["validation", "bench"],
            include_uncategorized: false,
        },

        // Restart — net, validation, plus uncategorized startup messages
        "PeerObserverBitcoinCoreRestart" => LogFilter {
            categories: vec!["net", "validation"],
            include_uncategorized: true,
        },

        // Mempool alerts
        "PeerObserverMempoolFull" | "PeerObserverMempoolEmpty" => LogFilter {
            categories: vec!["mempool", "mempoolrej"],
            include_uncategorized: false,
        },

        // CPU/thread performance
        "PeerObserverHighCPU" | "PeerObserverThreadSaturation" => LogFilter {
            categories: vec!["validation", "bench", "net"],
            include_uncategorized: false,
        },

        // Infrastructure/meta alerts — no debug log fetch
        "PeerObserverServiceFailed"
        | "PeerObserverMetricsToolDown"
        | "PeerObserverDiskSpaceLow"
        | "PeerObserverHighMemory"
        | "PeerObserverAnomalyDetectionDown" => LogFilter {
            categories: vec![],
            include_uncategorized: false,
        },

        // Unknown alerts — no fetch
        _ => LogFilter {
            categories: vec![],
            include_uncategorized: false,
        },
    }
}

/// Parse the timestamp from the start of a debug.log line.
///
/// Expected format: `2025-06-15T12:00:00.123456Z` (ISO 8601 with optional
/// microsecond precision, as produced by `logtimemicros=1`).
pub(crate) fn parse_line_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let token = line.split_whitespace().next()?;
    // Try with microsecond precision first, then without
    if let Ok(dt) = NaiveDateTime::parse_from_str(token, "%Y-%m-%dT%H:%M:%S%.fZ") {
        return Some(dt.and_utc());
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(token, "%Y-%m-%dT%H:%M:%SZ") {
        return Some(dt.and_utc());
    }
    None
}

/// Extract the log category from a debug.log line.
///
/// With `logthreadnames=1`, lines have the format:
///   `TIMESTAMP [THREAD] [CATEGORY] content`
///
/// This function returns the content of the **second** `[...]` bracket group
/// after the timestamp. Handles `[category:level]` format by extracting only
/// the part before `:`.
///
/// Lines with zero or one bracket group (uncategorized Info/startup messages)
/// return `None`.
pub(crate) fn extract_category(line: &str) -> Option<&str> {
    // Skip the timestamp (first whitespace-delimited token)
    let after_ts = line.split_whitespace().next().map(|ts| &line[ts.len()..])?;

    // Find the first '[' bracket (thread name)
    let first_open = after_ts.find('[')?;
    let first_close = after_ts[first_open..].find(']').map(|i| first_open + i)?;

    // Find the second '[' bracket (category)
    let rest = &after_ts[first_close + 1..];
    // The second bracket should follow closely (possibly with a space)
    let second_open = rest.find('[')?;
    let second_close = rest[second_open..].find(']').map(|i| second_open + i)?;

    let category_raw = &rest[second_open + 1..second_close];

    // Handle `category:level` format (e.g., `net:info`) — extract only the category
    let category = category_raw.split(':').next().unwrap_or(category_raw);

    if category.is_empty() {
        None
    } else {
        Some(category)
    }
}

/// Returns `true` if the line starts with a parseable timestamp.
///
/// Used to distinguish genuine log entries (even uncategorized) from
/// continuation lines and startup banners.
pub(crate) fn has_timestamp(line: &str) -> bool {
    parse_line_timestamp(line).is_some()
}

/// Severity-only tokens that appear as `[error]`, `[warning]`, etc. in
/// uncategorized messages. When `include_uncategorized` is true, lines
/// whose "category" bracket contains only a severity level are included.
const SEVERITY_TOKENS: &[&str] = &["error", "warning", "info", "debug", "trace"];

/// Known Bitcoin Core log categories (from `BCLog::LogFlags` in `logging.h`
/// and `LogCategories` in `logging.cpp`).
/// When `include_uncategorized` is true and the second bracket contains a token
/// NOT in this list, the line is treated as uncategorized message text with
/// bracketed content (e.g., `[snapshot] successfully activated...`) rather than
/// a categorized log line that should be dropped.
const KNOWN_LOG_CATEGORIES: &[&str] = &[
    "addrman",
    "bench",
    "blockstorage",
    "cmpctblock",
    "coindb",
    "estimatefee",
    "http",
    "i2p",
    "ipc",
    "kernel",
    "leveldb",
    "libevent",
    "lock",
    "mempool",
    "mempoolrej",
    "net",
    "privatebroadcast",
    "proxy",
    "prune",
    "qt",
    "rand",
    "reindex",
    "rpc",
    "scan",
    "selectcoins",
    "tor",
    "txpackages",
    "txreconciliation",
    "validation",
    "walletdb",
    "zmq",
];

/// Filter debug.log lines by time window, category, and line count.
///
/// Returns sanitized lines joined by newlines. Takes the last `max_lines`
/// matching lines (tail preference — most recent lines closest to alert
/// firing are most valuable).
pub(crate) fn filter_log_lines(
    body: &str,
    filter: &LogFilter,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    max_lines: usize,
) -> String {
    let mut matched = Vec::new();
    let mut total_lines = 0usize;
    let mut lines_with_timestamp = 0usize;

    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        total_lines += 1;

        let ts = match parse_line_timestamp(line) {
            Some(ts) => {
                lines_with_timestamp += 1;
                ts
            }
            None => continue,
        };

        // Time window check
        if ts < window_start || ts > window_end {
            continue;
        }

        // Category check
        let include = match extract_category(line) {
            Some(cat) => {
                if filter.categories.contains(&cat) {
                    // Explicit category match (e.g., [net], [validation])
                    true
                } else if filter.include_uncategorized && SEVERITY_TOKENS.contains(&cat) {
                    // Second bracket contains a severity level, not a category —
                    // treat as uncategorized for restart investigations
                    true
                } else if filter.include_uncategorized && !KNOWN_LOG_CATEGORIES.contains(&cat) {
                    // Second bracket contains an unknown token (not a known Bitcoin
                    // Core log category). This is likely bracketed message text in an
                    // uncategorized line, e.g. `[snapshot] successfully activated...`.
                    // Include it when uncategorized lines are wanted.
                    true
                } else {
                    false
                }
            }
            None => {
                // No second bracket — uncategorized line (one-bracket startup messages)
                filter.include_uncategorized && has_timestamp(line)
            }
        };

        if include {
            matched.push(sanitize(line));
        }
    }

    // Diagnostic: log if no lines had parseable timestamps (format mismatch)
    if total_lines > 0 && lines_with_timestamp == 0 {
        debug!(
            "no parseable timestamps found in debug log \
             (possible format mismatch — expected logthreadnames=1 + logtimemicros=1)"
        );
    }

    // Keep last max_lines (tail preference)
    let start = matched.len().saturating_sub(max_lines);
    matched[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // ── parse_line_timestamp ──────────────────────────────────────────

    #[test]
    fn parse_timestamp_with_microseconds() {
        let line = "2025-06-15T12:00:00.123456Z [msghand] [net] peer connected";
        let ts = parse_line_timestamp(line).unwrap();
        assert_eq!(ts.to_rfc3339(), "2025-06-15T12:00:00.123456+00:00");
    }

    #[test]
    fn parse_timestamp_without_microseconds() {
        let line = "2025-06-15T12:00:00Z [msghand] [net] peer connected";
        let ts = parse_line_timestamp(line).unwrap();
        assert_eq!(ts, Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap());
    }

    #[test]
    fn parse_timestamp_invalid_format() {
        assert!(parse_line_timestamp("not-a-timestamp [msghand] [net] text").is_none());
    }

    #[test]
    fn parse_timestamp_empty_string() {
        assert!(parse_line_timestamp("").is_none());
    }

    // ── extract_category ──────────────────────────────────────────────

    #[test]
    fn extract_category_two_brackets() {
        let line = "2025-06-15T12:00:00.123456Z [msghand] [net] peer connected";
        assert_eq!(extract_category(line), Some("net"));
    }

    #[test]
    fn extract_category_with_level_suffix() {
        let line = "2025-06-15T12:00:00.123456Z [msghand] [net:info] peer connected";
        assert_eq!(extract_category(line), Some("net"));
    }

    #[test]
    fn extract_category_single_bracket_uncategorized() {
        let line = "2025-06-15T12:00:00.123456Z [init] Starting network threads...";
        assert_eq!(extract_category(line), None);
    }

    #[test]
    fn extract_category_no_brackets() {
        let line = "2025-06-15T12:00:00.123456Z Bitcoin Core starting";
        assert_eq!(extract_category(line), None);
    }

    // ── filter_log_lines ──────────────────────────────────────────────

    fn window_start() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 6, 15, 11, 55, 0).unwrap()
    }
    fn window_end() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 6, 15, 12, 5, 0).unwrap()
    }

    #[test]
    fn filter_by_time_window() {
        let body = "\
2025-06-15T11:50:00.000000Z [msghand] [net] too early\n\
2025-06-15T12:00:00.000000Z [msghand] [net] in window\n\
2025-06-15T12:10:00.000000Z [msghand] [net] too late";

        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.contains("in window"));
        assert!(!result.contains("too early"));
        assert!(!result.contains("too late"));
    }

    #[test]
    fn filter_by_category() {
        let body = "\
2025-06-15T12:00:00.000000Z [msghand] [net] net line\n\
2025-06-15T12:00:01.000000Z [msghand] [validation] val line\n\
2025-06-15T12:00:02.000000Z [msghand] [mempool] pool line";

        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.contains("net line"));
        assert!(!result.contains("val line"));
        assert!(!result.contains("pool line"));
    }

    #[test]
    fn filter_max_lines_takes_tail() {
        let body = "\
2025-06-15T12:00:00.000000Z [msghand] [net] first\n\
2025-06-15T12:00:01.000000Z [msghand] [net] second\n\
2025-06-15T12:00:02.000000Z [msghand] [net] third";

        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 2);
        assert!(!result.contains("first"));
        assert!(result.contains("second"));
        assert!(result.contains("third"));
    }

    #[test]
    fn filter_empty_input() {
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines("", &filter, window_start(), window_end(), 200);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_all_filtered_out() {
        let body = "2025-06-15T12:00:00.000000Z [msghand] [mempool] wrong category";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_handles_category_level_suffix() {
        let body = "2025-06-15T12:00:00.000000Z [msghand] [net:info] peer connected";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.contains("peer connected"));
    }

    // ── include_uncategorized ─────────────────────────────────────────

    #[test]
    fn filter_includes_one_bracket_startup_lines_when_uncategorized() {
        let body = "\
2025-06-15T12:00:00.000000Z [init] Bound to 0.0.0.0:8333\n\
2025-06-15T12:00:01.000000Z [init] [net] Starting network threads";

        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: true,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        // One-bracket line included because include_uncategorized is true
        assert!(result.contains("Bound to"));
        // Two-bracket net line also included via category match
        assert!(result.contains("Starting network threads"));
    }

    #[test]
    fn filter_includes_severity_only_lines_when_uncategorized() {
        let body = "2025-06-15T12:00:00.000000Z [init] [error] bind failed";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: true,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.contains("bind failed"));
    }

    #[test]
    fn filter_excludes_uncategorized_when_flag_false() {
        let body = "2025-06-15T12:00:00.000000Z [init] Bound to 0.0.0.0:8333";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_includes_bracketed_message_text_when_uncategorized() {
        // Bitcoin Core emits uncategorized lines where message text starts with
        // brackets, e.g. `[snapshot] successfully activated snapshot`. The parser
        // sees `[snapshot]` as the second bracket group. Since `snapshot` is not
        // a known log category, include_uncategorized should treat it as message
        // text rather than dropping it.
        let body = "2025-06-15T12:00:00.000000Z [init] [snapshot] successfully activated snapshot";
        let filter = LogFilter {
            categories: vec!["net", "validation"],
            include_uncategorized: true,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(
            result.contains("successfully activated snapshot"),
            "bracketed message text should be included when include_uncategorized is true"
        );
    }

    #[test]
    fn filter_excludes_bracketed_message_when_uncategorized_false() {
        // When include_uncategorized is false, unknown bracket tokens are dropped
        // (they don't match any category in the filter).
        let body = "2025-06-15T12:00:00.000000Z [init] [snapshot] restarting indexes";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_still_drops_known_category_mismatch_when_uncategorized() {
        // Even with include_uncategorized = true, lines with a recognized log
        // category that isn't in the filter's category list should be dropped.
        // E.g., a [mempool] line during a restart investigation should not be
        // included — mempool is a known category, not bracketed message text.
        let body = "2025-06-15T12:00:00.000000Z [msghand] [mempool] AcceptToMemoryPool";
        let filter = LogFilter {
            categories: vec!["net", "validation"],
            include_uncategorized: true,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(
            result.is_empty(),
            "known category mismatch should still be dropped even with include_uncategorized"
        );
    }

    #[test]
    fn filter_sanitizes_output() {
        let body = "2025-06-15T12:00:00.000000Z [msghand] [net] peer </debug-log-data> injected";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(!result.contains("</debug-log-data>"));
        assert!(result.contains("&lt;/debug-log-data&gt;"));
    }

    // ── log_filter_for_alert ──────────────────────────────────────────

    #[test]
    fn connection_alerts_get_net_category() {
        for alert in &[
            "PeerObserverAddressMessageSpike",
            "PeerObserverMisbehaviorSpike",
            "PeerObserverInboundConnectionDrop",
            "PeerObserverOutboundConnectionDrop",
            "PeerObserverTotalPeersDrop",
            "PeerObserverNetworkInactive",
            "PeerObserverINVQueueDepthAnomaly",
            "PeerObserverINVQueueDepthExtreme",
        ] {
            let filter = log_filter_for_alert(alert);
            assert_eq!(filter.categories, vec!["net"], "for {alert}");
            assert!(!filter.include_uncategorized, "for {alert}");
        }
    }

    #[test]
    fn chain_health_alerts_get_validation_bench_cmpctblock() {
        for alert in &[
            "PeerObserverBlockStale",
            "PeerObserverBlockStaleCritical",
            "PeerObserverHeaderBlockGap",
        ] {
            let filter = log_filter_for_alert(alert);
            assert_eq!(
                filter.categories,
                vec!["validation", "bench", "cmpctblock"],
                "for {alert}"
            );
        }
    }

    #[test]
    fn ibd_alert_gets_validation_bench() {
        let filter = log_filter_for_alert("PeerObserverNodeInIBD");
        assert_eq!(filter.categories, vec!["validation", "bench"]);
    }

    #[test]
    fn restart_alert_gets_net_validation_and_uncategorized() {
        let filter = log_filter_for_alert("PeerObserverBitcoinCoreRestart");
        assert_eq!(filter.categories, vec!["net", "validation"]);
        assert!(filter.include_uncategorized);
    }

    #[test]
    fn mempool_alerts_get_mempool_mempoolrej() {
        for alert in &["PeerObserverMempoolFull", "PeerObserverMempoolEmpty"] {
            let filter = log_filter_for_alert(alert);
            assert_eq!(
                filter.categories,
                vec!["mempool", "mempoolrej"],
                "for {alert}"
            );
        }
    }

    #[test]
    fn cpu_thread_alerts_get_validation_bench_net() {
        for alert in &["PeerObserverHighCPU", "PeerObserverThreadSaturation"] {
            let filter = log_filter_for_alert(alert);
            assert_eq!(
                filter.categories,
                vec!["validation", "bench", "net"],
                "for {alert}"
            );
        }
    }

    #[test]
    fn infrastructure_alerts_get_empty() {
        for alert in &[
            "PeerObserverServiceFailed",
            "PeerObserverMetricsToolDown",
            "PeerObserverDiskSpaceLow",
            "PeerObserverHighMemory",
            "PeerObserverAnomalyDetectionDown",
        ] {
            let filter = log_filter_for_alert(alert);
            assert!(filter.categories.is_empty(), "for {alert}");
            assert!(!filter.include_uncategorized, "for {alert}");
        }
    }

    #[test]
    fn unknown_alert_gets_empty() {
        let filter = log_filter_for_alert("SomeNewUnknownAlert");
        assert!(filter.categories.is_empty());
        assert!(!filter.include_uncategorized);
    }

    // ── format mismatch diagnostic ────────────────────────────────────

    #[test]
    fn filter_no_warning_on_zero_results_with_valid_timestamps() {
        // Lines have valid timestamps but don't match category — should return empty quietly
        let body = "2025-06-15T12:00:00.000000Z [msghand] [mempool] wrong category";
        let filter = LogFilter {
            categories: vec!["net"],
            include_uncategorized: false,
        };
        let result = filter_log_lines(body, &filter, window_start(), window_end(), 200);
        assert!(result.is_empty());
        // The debug! log would fire only when NO lines have parseable timestamps,
        // not when results are empty due to filtering. We can't easily test tracing
        // output in unit tests, but the code path is covered.
    }
}
