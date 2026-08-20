//! Deterministic interestingness sweep — the zero-LLM tier.
//!
//! Walks a curated metric catalog, applies robust detectors, and emits a ranked
//! digest. No model is involved at any point: this is the "workflows before
//! agents" layer the plan puts in front of everything else, and the thing that
//! turns a firehose into a short list a human (or later, a triage model) can
//! actually read.

pub(crate) mod catalog;
pub(crate) mod digest;
pub(crate) mod prometheus;
pub(crate) mod stats;

use anyhow::{Context, Result};
use catalog::{Detector, MetricSpec};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use prometheus::{PromClient, Series};
use serde::Serialize;
use std::collections::BTreeMap;
use tracing::{debug, warn};

/// Which detector produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FindingKind {
    /// A series departed from its own recent history.
    ResidualSpike,
    /// A host departed from its peers at the same instant.
    PeerGroupOutlier,
    /// A series stepped to a new level between two adjacent windows.
    ChangePoint,
}

impl FindingKind {
    fn label(self) -> &'static str {
        match self {
            Self::ResidualSpike => "residual",
            Self::PeerGroupOutlier => "peer-group",
            Self::ChangePoint => "change-point",
        }
    }

    /// Confidence multiplier folded into the interestingness score.
    ///
    /// Peer-group outliers rank highest: with a deliberately heterogeneous fleet
    /// (Core / Knots / Libre) a cross-sectional disagreement is the signal the
    /// plan calls out as impossible for single-node operators to see. Residual
    /// spikes rank lowest because a single series departing from its own history
    /// is exactly what v1's alert layer already over-reported.
    fn weight(self) -> f64 {
        match self {
            Self::PeerGroupOutlier => 1.2,
            Self::ChangePoint => 1.0,
            Self::ResidualSpike => 0.8,
        }
    }
}

/// A single ranked observation.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Finding {
    pub(crate) kind: FindingKind,
    pub(crate) metric: String,
    /// Host or series identity the finding is about.
    pub(crate) subject: String,
    /// Composite interestingness score; higher ranks earlier.
    pub(crate) score: f64,
    /// Robust deviation in scale units.
    pub(crate) z: f64,
    pub(crate) observed: f64,
    pub(crate) baseline: f64,
    pub(crate) rationale: &'static str,
    /// Human-readable one-liner.
    pub(crate) summary: String,
}

/// Sweep tuning.
#[derive(Debug, Clone)]
pub(crate) struct SweepConfig {
    pub(crate) prometheus_url: String,
    /// How far back the baseline window reaches.
    pub(crate) lookback: ChronoDuration,
    /// Trailing window treated as "now" for change-point comparison.
    pub(crate) recent: ChronoDuration,
    /// Range-query resolution.
    pub(crate) step: String,
    /// Minimum samples before a detector will speak.
    pub(crate) min_samples: usize,
    /// |z| below this is not a finding.
    pub(crate) z_threshold: f64,
    /// Digest length.
    pub(crate) top_n: usize,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            prometheus_url: "http://127.0.0.1:9090".to_string(),
            lookback: ChronoDuration::hours(24),
            recent: ChronoDuration::hours(1),
            step: "5m".to_string(),
            min_samples: 6,
            z_threshold: 3.5,
            top_n: 25,
        }
    }
}

impl SweepConfig {
    /// Build from `ANNOTATION_AGENT_SWEEP_*` environment variables, falling back
    /// to defaults. Matches the repo's existing env-var configuration style.
    pub(crate) fn from_env() -> Result<Self> {
        let d = Self::default();
        Ok(Self {
            prometheus_url: std::env::var("ANNOTATION_AGENT_SWEEP_PROMETHEUS_URL")
                .unwrap_or(d.prometheus_url),
            lookback: ChronoDuration::hours(env_i64("ANNOTATION_AGENT_SWEEP_LOOKBACK_HOURS", 24)?),
            recent: ChronoDuration::minutes(env_i64("ANNOTATION_AGENT_SWEEP_RECENT_MINUTES", 60)?),
            step: std::env::var("ANNOTATION_AGENT_SWEEP_STEP").unwrap_or(d.step),
            min_samples: env_i64("ANNOTATION_AGENT_SWEEP_MIN_SAMPLES", 6)?.max(2) as usize,
            z_threshold: std::env::var("ANNOTATION_AGENT_SWEEP_Z_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.z_threshold),
            top_n: env_i64("ANNOTATION_AGENT_SWEEP_TOP_N", 25)?.max(1) as usize,
        })
    }
}

fn env_i64(key: &str, default: i64) -> Result<i64> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<i64>()
            .with_context(|| format!("{key} must be an integer, got {v:?}")),
        Err(_) => Ok(default),
    }
}

/// A completed sweep.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SweepReport {
    pub(crate) generated_at: DateTime<Utc>,
    pub(crate) window_start: DateTime<Utc>,
    pub(crate) window_end: DateTime<Utc>,
    pub(crate) metrics_swept: usize,
    pub(crate) series_examined: usize,
    pub(crate) findings: Vec<Finding>,
    /// Metrics that returned no data — an instrumentation signal in itself.
    pub(crate) empty_metrics: Vec<String>,
    /// Metrics whose Prometheus queries failed — the sweep is partial and a
    /// quiet digest must not be read as a quiet network.
    pub(crate) failed_metrics: Vec<String>,
}

/// Run the sweep against Prometheus.
pub(crate) async fn run(config: &SweepConfig) -> Result<SweepReport> {
    let client = PromClient::new(&config.prometheus_url)?;
    let specs = catalog::default_catalog();
    run_with(&client, config, &specs).await
}

pub(crate) async fn run_with(
    client: &PromClient,
    config: &SweepConfig,
    specs: &[MetricSpec],
) -> Result<SweepReport> {
    let end = Utc::now();
    let start = end - config.lookback;

    let mut fetched = Vec::with_capacity(specs.len());
    for spec in specs {
        let outcome = client
            .query_range(spec.query, start.timestamp(), end.timestamp(), &config.step)
            .await;
        if let Err(e) = &outcome {
            // A broken query must not abort the sweep; record and continue.
            warn!(metric = spec.name, error = %e, "sweep query failed");
        }
        fetched.push(outcome);
    }

    build_report(config, specs, fetched, start, end)
}

/// Assemble the report from fetched series, one outcome per spec.
///
/// Separated from the network fetch so the detector wiring, the
/// baseline/recent split, and the all-queries-failed guarantee can be
/// exercised with fixture data.
pub(crate) fn build_report(
    config: &SweepConfig,
    specs: &[MetricSpec],
    fetched: Vec<Result<Vec<Series>>>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<SweepReport> {
    let mut findings = Vec::new();
    let mut empty_metrics = Vec::new();
    let mut failed_metrics = Vec::new();
    let mut series_examined = 0usize;

    for (spec, outcome) in specs.iter().zip(fetched) {
        let series = match outcome {
            Ok(s) => s,
            Err(_) => {
                failed_metrics.push(spec.name.to_string());
                continue;
            }
        };
        if series.is_empty() {
            empty_metrics.push(spec.name.to_string());
            continue;
        }
        series_examined += series.len();
        debug!(metric = spec.name, series = series.len(), "swept");

        let recent_samples = recent_sample_count(config);

        // Per-series detectors.
        for s in &series {
            let host = s.label("host");
            let values = s.values();
            if values.len() < config.min_samples {
                continue;
            }
            let split = values.len().saturating_sub(recent_samples);
            let (baseline, recent) = values.split_at(split.max(1).min(values.len()));

            if spec.detectors.contains(&Detector::Residual) {
                // Smooth over a short tail rather than scoring the single latest
                // sample. On spiky per-observation gauges one transient (a slow
                // Tor peer's ping RTT) otherwise reads as an excursion. The tail
                // is deliberately short — this detector's job is "a brief
                // excursion happened recently", which stays distinct from the
                // change-point detector's "the level shifted and stayed there".
                if let Some(observed) = smoothed_tail(&values, RESIDUAL_TAIL_SAMPLES) {
                    if let Some(z) = stats::robust_z(observed, baseline, config.min_samples) {
                        let base = stats::median(baseline).unwrap_or(0.0);
                        if z.abs() >= config.z_threshold
                            && clears_effect_floor(spec, observed, base)
                        {
                            findings.push(make_finding(
                                FindingKind::ResidualSpike,
                                spec,
                                &host,
                                z,
                                observed,
                                base,
                            ));
                        }
                    }
                }
            }

            if spec.detectors.contains(&Detector::ChangePoint) && !recent.is_empty() {
                if let Some(shift) = stats::window_shift(baseline, recent, config.min_samples) {
                    if shift.z.abs() >= config.z_threshold
                        && clears_effect_floor(spec, shift.after, shift.before)
                    {
                        findings.push(make_finding(
                            FindingKind::ChangePoint,
                            spec,
                            &host,
                            shift.z,
                            shift.after,
                            shift.before,
                        ));
                    }
                }
            }
        }

        // Cross-sectional detector: compare hosts over the recent window.
        //
        // Deliberately the median of each host's recent window rather than its
        // single latest sample. Several swept metrics are spiky per-observation
        // gauges (`ping_duration` reports the last ping RTT, which legitimately
        // hits seconds for a slow Tor peer). Comparing single samples made one
        // transient spike look like a 1000x cross-sectional outlier; a windowed
        // median only fires when a host is *persistently* unlike its peers,
        // which is what "grey failure" actually means.
        if spec.detectors.contains(&Detector::PeerGroup) {
            let peers: Vec<(String, f64)> = series
                .iter()
                .filter_map(|s| {
                    let values = s.values();
                    let tail = values.len().saturating_sub(recent_samples);
                    stats::median(&values[tail..]).map(|v| (s.label("host"), v))
                })
                .collect();
            let peer_median = stats::median(&peers.iter().map(|(_, v)| *v).collect::<Vec<_>>());
            for dev in stats::peer_group_outliers(&peers) {
                let pm = peer_median.unwrap_or(0.0);
                if dev.z.abs() >= config.z_threshold && clears_effect_floor(spec, dev.value, pm) {
                    findings.push(make_finding(
                        FindingKind::PeerGroupOutlier,
                        spec,
                        &dev.label,
                        dev.z,
                        dev.value,
                        peer_median.unwrap_or(0.0),
                    ));
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings.truncate(config.top_n);

    // Every query failing means Prometheus itself is unreachable or broken;
    // exiting non-zero keeps an outage from rendering as a quiet network.
    if failed_metrics.len() == specs.len() {
        anyhow::bail!(
            "all {} sweep queries failed; is Prometheus reachable at {}?",
            specs.len(),
            config.prometheus_url
        );
    }

    Ok(SweepReport {
        generated_at: end,
        window_start: start,
        window_end: end,
        metrics_swept: specs.len(),
        series_examined,
        findings,
        empty_metrics,
        failed_metrics,
    })
}

/// Trailing samples the residual detector smooths over before scoring.
///
/// Three at the default 5m step is 15 minutes: enough to reject a single-sample
/// transient, short enough that a genuine brief excursion still registers.
const RESIDUAL_TAIL_SAMPLES: usize = 3;

/// Median of the last `n` samples, or `None` if there are none.
fn smoothed_tail(values: &[f64], n: usize) -> Option<f64> {
    let start = values.len().saturating_sub(n.max(1));
    stats::median(&values[start..])
}

/// How many trailing samples constitute the "recent" window.
fn recent_sample_count(config: &SweepConfig) -> usize {
    let step_secs = parse_step_seconds(&config.step).unwrap_or(300);
    let recent_secs = config.recent.num_seconds().max(0) as u64;
    ((recent_secs / step_secs.max(1)) as usize).max(1)
}

/// Parse a Prometheus-style duration such as `5m`, `30s`, `1h` into seconds.
fn parse_step_seconds(step: &str) -> Option<u64> {
    let step = step.trim();
    let (num, unit) = step.split_at(step.find(|c: char| c.is_alphabetic())?);
    let n: u64 = num.parse().ok()?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    Some(n * mult)
}

/// Does this deviation clear the metric's operational effect-size floor?
///
/// Statistical and operational significance are different questions. This
/// answers the second one, and it is checked *after* the z threshold so that a
/// finding must be both robustly anomalous and materially large.
fn clears_effect_floor(spec: &MetricSpec, observed: f64, baseline: f64) -> bool {
    (observed - baseline).abs() >= spec.min_absolute
}

fn make_finding(
    kind: FindingKind,
    spec: &MetricSpec,
    subject: &str,
    z: f64,
    observed: f64,
    baseline: f64,
) -> Finding {
    let score = z.abs() * spec.weight * kind.weight();
    let direction = if observed >= baseline {
        "above"
    } else {
        "below"
    };
    let summary = format!(
        "{} on {}: {:.4} vs baseline {:.4} ({} {:.1}σ, {})",
        spec.name,
        subject,
        observed,
        baseline,
        direction,
        z.abs(),
        kind.label()
    );
    Finding {
        kind,
        metric: spec.name.to_string(),
        subject: subject.to_string(),
        score,
        z,
        observed,
        baseline,
        rationale: spec.rationale,
        summary,
    }
}

/// Group findings by subject so one incident does not occupy the whole digest.
pub(crate) fn group_by_subject(findings: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut out: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        out.entry(f.subject.clone()).or_default().push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> MetricSpec {
        MetricSpec {
            name: "test_metric",
            query: "test",
            weight: 1.5,
            rationale: "test rationale",
            detectors: &[Detector::Residual],
            min_absolute: 0.0,
        }
    }

    fn spec_named(name: &'static str, detectors: &'static [Detector]) -> MetricSpec {
        MetricSpec {
            name,
            query: "test",
            weight: 1.0,
            rationale: "test rationale",
            detectors,
            min_absolute: 1.0,
        }
    }

    /// 15m recent window at a 5m step = a 3-sample recent window, which also
    /// satisfies window_shift's min_samples requirement on the recent side.
    fn fixture_config() -> SweepConfig {
        SweepConfig {
            recent: ChronoDuration::minutes(15),
            min_samples: 3,
            ..SweepConfig::default()
        }
    }

    fn host_series(host: &str, values: &[f64]) -> Series {
        let mut labels = BTreeMap::new();
        labels.insert("host".to_string(), host.to_string());
        Series {
            labels,
            samples: values
                .iter()
                .enumerate()
                .map(|(i, v)| (i as f64, *v))
                .collect(),
        }
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        let end = Utc::now();
        (end - ChronoDuration::hours(24), end)
    }

    #[test]
    fn build_report_errors_when_every_query_failed() {
        let config = fixture_config();
        let specs = [
            spec_named("a", &[Detector::Residual]),
            spec_named("b", &[Detector::Residual]),
        ];
        let fetched = vec![Err(anyhow::anyhow!("boom")), Err(anyhow::anyhow!("boom"))];
        let (start, end) = window();
        let err = build_report(&config, &specs, fetched, start, end).unwrap_err();
        assert!(err.to_string().contains("all 2 sweep queries failed"));
    }

    #[test]
    fn build_report_records_failed_and_empty_metrics() {
        let config = fixture_config();
        let specs = [
            spec_named("broken", &[Detector::Residual]),
            spec_named("silent", &[Detector::Residual]),
            spec_named("flat", &[Detector::Residual]),
        ];
        let fetched = vec![
            Err(anyhow::anyhow!("boom")),
            Ok(vec![]),
            Ok(vec![host_series("node01", &[10.0; 24])]),
        ];
        let (start, end) = window();
        let report = build_report(&config, &specs, fetched, start, end).unwrap();
        assert_eq!(report.failed_metrics, vec!["broken"]);
        assert_eq!(report.empty_metrics, vec!["silent"]);
        assert_eq!(report.series_examined, 1);
        assert!(report.findings.is_empty(), "flat series must not fire");
    }

    #[test]
    fn change_point_fires_when_recent_window_steps_to_new_level() {
        let config = fixture_config();
        let specs = [spec_named("stepped", &[Detector::ChangePoint])];
        // 21 baseline samples at 10.0, then a 3-sample recent window at 100.0.
        let mut values = vec![10.0; 21];
        values.extend_from_slice(&[100.0; 3]);
        let fetched = vec![Ok(vec![host_series("node01", &values)])];
        let (start, end) = window();
        let report = build_report(&config, &specs, fetched, start, end).unwrap();
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.kind, FindingKind::ChangePoint);
        assert_eq!(f.subject, "node01");
        // The split must put exactly the recent window on the "after" side:
        // median(recent) = 100, median(baseline) = 10.
        assert_eq!(f.observed, 100.0);
        assert_eq!(f.baseline, 10.0);
    }

    #[test]
    fn peer_group_outlier_is_flagged_across_hosts() {
        let config = fixture_config();
        let specs = [spec_named("peers", &[Detector::PeerGroup])];
        let fetched = vec![Ok(vec![
            host_series("node01", &[10.0; 24]),
            host_series("node02", &[10.0; 24]),
            host_series("node03", &[10.0; 24]),
            host_series("node04", &[100.0; 24]),
        ])];
        let (start, end) = window();
        let report = build_report(&config, &specs, fetched, start, end).unwrap();
        assert_eq!(report.findings.len(), 1);
        let f = &report.findings[0];
        assert_eq!(f.kind, FindingKind::PeerGroupOutlier);
        assert_eq!(f.subject, "node04");
    }

    #[test]
    fn series_below_min_samples_is_examined_but_never_scored() {
        let config = fixture_config();
        let specs = [spec_named("short", ALL_DETECTORS)];
        let fetched = vec![Ok(vec![host_series("node01", &[10.0, 100.0])])];
        let (start, end) = window();
        let report = build_report(&config, &specs, fetched, start, end).unwrap();
        assert_eq!(report.series_examined, 1);
        assert!(report.findings.is_empty());
    }

    const ALL_DETECTORS: &[Detector] = &[
        Detector::Residual,
        Detector::PeerGroup,
        Detector::ChangePoint,
    ];

    #[test]
    fn score_combines_magnitude_metric_weight_and_kind() {
        let f = make_finding(
            FindingKind::PeerGroupOutlier,
            &spec(),
            "host-a",
            -4.0,
            1.0,
            9.0,
        );
        // |z| 4.0 * metric weight 1.5 * peer-group kind weight 1.2
        assert!((f.score - 7.2).abs() < 1e-9, "score was {}", f.score);
    }

    #[test]
    fn peer_group_outranks_residual_at_equal_magnitude() {
        let a = make_finding(FindingKind::PeerGroupOutlier, &spec(), "h", 4.0, 5.0, 1.0);
        let b = make_finding(FindingKind::ResidualSpike, &spec(), "h", 4.0, 5.0, 1.0);
        assert!(
            a.score > b.score,
            "cross-sectional evidence should outrank single-series"
        );
    }

    #[test]
    fn summary_reports_direction_correctly() {
        let up = make_finding(FindingKind::ResidualSpike, &spec(), "h", 4.0, 9.0, 1.0);
        assert!(up.summary.contains("above"), "{}", up.summary);
        let down = make_finding(FindingKind::ResidualSpike, &spec(), "h", -4.0, 1.0, 9.0);
        assert!(down.summary.contains("below"), "{}", down.summary);
    }

    #[test]
    fn parses_prometheus_step_durations() {
        assert_eq!(parse_step_seconds("30s"), Some(30));
        assert_eq!(parse_step_seconds("5m"), Some(300));
        assert_eq!(parse_step_seconds("2h"), Some(7200));
        assert_eq!(parse_step_seconds("1d"), Some(86400));
        assert_eq!(parse_step_seconds("5"), None);
        assert_eq!(parse_step_seconds("5y"), None);
    }

    #[test]
    fn effect_floor_suppresses_statistically_large_but_tiny_deviations() {
        // The live-digest noise this fixes: 0.0034 announcements/sec against a
        // peer baseline of exactly 0.0 is a huge robust deviation and an
        // operationally meaningless one.
        let mut s = spec();
        s.min_absolute = 0.05;
        assert!(!clears_effect_floor(&s, 0.0034, 0.0));
        // A move that actually matters still passes.
        assert!(clears_effect_floor(&s, 0.9, 0.0));
    }

    #[test]
    fn effect_floor_is_direction_agnostic() {
        let mut s = spec();
        s.min_absolute = 2.0;
        assert!(
            clears_effect_floor(&s, 1.0, 9.0),
            "a large drop must clear it"
        );
        assert!(!clears_effect_floor(&s, 9.0, 8.5), "a small rise must not");
    }

    #[test]
    fn zero_floor_admits_everything() {
        // Metrics that opt out (min_absolute 0.0) behave as before.
        assert!(clears_effect_floor(&spec(), 0.000_001, 0.0));
    }

    #[test]
    fn smoothed_tail_rejects_a_single_sample_transient() {
        // The live failure this guards: ping_duration sat at ~0.14 and one
        // 5-minute sample landed on a 1.46 spike, which the old single-sample
        // residual scored as an excursion.
        let mut values = vec![0.14; 20];
        values.push(1.46);
        let smoothed = smoothed_tail(&values, RESIDUAL_TAIL_SAMPLES).expect("non-empty");
        assert!(
            (smoothed - 0.14).abs() < 1e-9,
            "one transient moved the smoothed tail: {smoothed}"
        );
    }

    #[test]
    fn smoothed_tail_still_sees_a_sustained_excursion() {
        // Smoothing must not blind the detector: three consecutive high samples
        // is a real brief excursion and must survive.
        let mut values = vec![0.14; 20];
        values.extend_from_slice(&[1.46, 1.50, 1.48]);
        let smoothed = smoothed_tail(&values, RESIDUAL_TAIL_SAMPLES).expect("non-empty");
        assert!(
            smoothed > 1.4,
            "sustained excursion was smoothed away: {smoothed}"
        );
    }

    #[test]
    fn smoothed_tail_handles_short_series() {
        assert_eq!(smoothed_tail(&[], 3), None);
        assert_eq!(smoothed_tail(&[5.0], 3), Some(5.0));
        assert_eq!(smoothed_tail(&[1.0, 2.0], 3), Some(1.5));
    }

    #[test]
    fn recent_sample_count_is_at_least_one() {
        let cfg = SweepConfig {
            recent: ChronoDuration::seconds(0),
            ..SweepConfig::default()
        };
        assert_eq!(recent_sample_count(&cfg), 1);
    }

    #[test]
    fn recent_sample_count_divides_window_by_step() {
        let cfg = SweepConfig {
            recent: ChronoDuration::hours(1),
            step: "5m".to_string(),
            ..SweepConfig::default()
        };
        assert_eq!(recent_sample_count(&cfg), 12);
    }

    #[test]
    fn grouping_collects_by_subject() {
        let f1 = make_finding(FindingKind::ResidualSpike, &spec(), "host-a", 4.0, 5.0, 1.0);
        let f2 = make_finding(FindingKind::ChangePoint, &spec(), "host-a", 4.0, 5.0, 1.0);
        let f3 = make_finding(FindingKind::ResidualSpike, &spec(), "host-b", 4.0, 5.0, 1.0);
        let all = [f1, f2, f3];
        let g = group_by_subject(&all);
        assert_eq!(g.len(), 2);
        assert_eq!(g["host-a"].len(), 2);
        assert_eq!(g["host-b"].len(), 1);
    }
}
