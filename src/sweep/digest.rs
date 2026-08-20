//! Rendering a sweep into the daily ranked digest.
//!
//! Two outputs: Markdown for a human at the Phase 0 gate, and JSON as the
//! machine-readable contract the later triage tier consumes. The JSON shape is
//! the thing to keep stable; the Markdown is a view over it.

use super::{group_by_subject, SweepReport};
use std::fmt::Write as _;

/// Render the digest as Markdown.
pub(crate) fn to_markdown(report: &SweepReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Interestingness digest — {}",
        report.generated_at.format("%Y-%m-%d %H:%M UTC")
    );
    let _ = writeln!(
        out,
        "\nWindow: {} → {} · {} metrics swept · {} series examined · {} findings",
        report.window_start.format("%Y-%m-%d %H:%M"),
        report.window_end.format("%Y-%m-%d %H:%M"),
        report.metrics_swept,
        report.series_examined,
        report.findings.len()
    );

    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "\n**No findings above threshold.** This is a valid and expected outcome — \
             the sweep is designed to stay silent when nothing is interesting."
        );
    } else {
        let _ = writeln!(out, "\n## Ranked findings\n");
        let _ = writeln!(
            out,
            "| # | score | metric | subject | observed | baseline | kind |"
        );
        let _ = writeln!(
            out,
            "|---|-------|--------|---------|----------|----------|------|"
        );
        for (i, f) in report.findings.iter().enumerate() {
            let _ = writeln!(
                out,
                "| {} | {:.1} | `{}` | {} | {:.4} | {:.4} | {} |",
                i + 1,
                f.score,
                f.metric,
                f.subject,
                f.observed,
                f.baseline,
                match f.kind {
                    super::FindingKind::ResidualSpike => "residual",
                    super::FindingKind::PeerGroupOutlier => "peer-group",
                    super::FindingKind::ChangePoint => "change-point",
                }
            );
        }

        let _ = writeln!(out, "\n## Why these matter\n");
        // One rationale per metric, not per finding — repeating the same
        // sentence for every host is noise.
        let mut seen: Vec<&str> = Vec::new();
        for f in &report.findings {
            if !seen.contains(&f.metric.as_str()) {
                seen.push(&f.metric);
                let _ = writeln!(out, "- **{}** — {}", f.metric, f.rationale);
            }
        }

        let grouped = group_by_subject(&report.findings);
        if grouped.len() > 1 {
            let _ = writeln!(out, "\n## By subject\n");
            for (subject, fs) in &grouped {
                let _ = writeln!(
                    out,
                    "- **{}** — {} finding(s): {}",
                    subject,
                    fs.len(),
                    fs.iter()
                        .map(|f| f.metric.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    if !report.empty_metrics.is_empty() {
        let _ = writeln!(
            out,
            "\n## Metrics returning no data ({})\n",
            report.empty_metrics.len()
        );
        let _ = writeln!(
            out,
            "Absence of data is itself a signal — it may mean the instrumentation \
             is missing rather than the condition being absent.\n"
        );
        for m in &report.empty_metrics {
            let _ = writeln!(out, "- `{m}`");
        }
    }

    if !report.failed_metrics.is_empty() {
        let _ = writeln!(
            out,
            "\n## Metrics whose queries failed ({})\n",
            report.failed_metrics.len()
        );
        let _ = writeln!(
            out,
            "These metrics were not swept at all — treat this digest as partial \
             and check Prometheus health before trusting a quiet result.\n"
        );
        for m in &report.failed_metrics {
            let _ = writeln!(out, "- `{m}`");
        }
    }

    out
}

/// Render the digest as pretty JSON.
pub(crate) fn to_json(report: &SweepReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sweep::{Finding, FindingKind};
    use chrono::Utc;

    fn report_with(findings: Vec<Finding>, empty: Vec<String>) -> SweepReport {
        let now = Utc::now();
        SweepReport {
            generated_at: now,
            window_start: now - chrono::Duration::hours(24),
            window_end: now,
            metrics_swept: 20,
            series_examined: 80,
            findings,
            empty_metrics: empty,
            failed_metrics: vec![],
        }
    }

    fn finding(metric: &str, subject: &str, score: f64) -> Finding {
        Finding {
            kind: FindingKind::PeerGroupOutlier,
            metric: metric.to_string(),
            subject: subject.to_string(),
            score,
            z: 4.0,
            observed: 10.0,
            baseline: 1.0,
            rationale: "because it matters",
            summary: "summary".to_string(),
        }
    }

    #[test]
    fn empty_digest_states_silence_is_valid() {
        let md = to_markdown(&report_with(vec![], vec![]));
        assert!(md.contains("No findings above threshold"));
        // "no action warranted" must read as a success, per the plan's
        // positivity-bias guard.
        assert!(md.contains("valid and expected"));
    }

    #[test]
    fn failed_queries_render_as_partial_sweep_warning() {
        let mut report = report_with(vec![], vec![]);
        report.failed_metrics = vec!["p2p_ping_rtt".to_string()];
        let md = to_markdown(&report);
        assert!(md.contains("Metrics whose queries failed (1)"));
        assert!(md.contains("treat this digest as partial"));
        assert!(md.contains("`p2p_ping_rtt`"));
    }

    #[test]
    fn digest_lists_findings_in_given_order() {
        let md = to_markdown(&report_with(
            vec![
                finding("addr_rate", "host-a", 9.0),
                finding("evicted", "host-b", 4.0),
            ],
            vec![],
        ));
        let first = md.find("addr_rate").expect("present");
        let second = md.find("evicted").expect("present");
        assert!(first < second, "digest reordered findings");
    }

    #[test]
    fn rationale_is_not_repeated_per_host() {
        let md = to_markdown(&report_with(
            vec![
                finding("addr_rate", "host-a", 9.0),
                finding("addr_rate", "host-b", 8.0),
                finding("addr_rate", "host-c", 7.0),
            ],
            vec![],
        ));
        assert_eq!(
            md.matches("because it matters").count(),
            1,
            "rationale repeated once per finding instead of once per metric"
        );
    }

    #[test]
    fn empty_metrics_are_surfaced_as_signal() {
        let md = to_markdown(&report_with(vec![], vec!["ghost_metric".into()]));
        assert!(md.contains("ghost_metric"));
        assert!(md.contains("Absence of data is itself a signal"));
    }

    #[test]
    fn json_round_trips() {
        let r = report_with(vec![finding("m", "h", 1.0)], vec![]);
        let j = to_json(&r).expect("serializes");
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["findings"][0]["metric"], "m");
        assert_eq!(v["findings"][0]["kind"], "peer_group_outlier");
    }
}
