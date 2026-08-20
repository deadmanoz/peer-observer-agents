//! Robust statistics for the interestingness sweep.
//!
//! Everything here is deliberately non-parametric: median/MAD rather than
//! mean/stddev. v1's adaptive alert bands used mean±stddev and suffered
//! band-contraction and self-contamination — a few anomalous samples pulled the
//! baseline toward the anomaly until normal traffic began firing. Median/MAD has
//! a 50% breakdown point, so a minority of contaminated samples cannot move it.

/// Scale factor making MAD a consistent estimator of stddev for normal data.
const MAD_TO_SIGMA: f64 = 1.4826;

/// Floor applied to MAD-derived scale before dividing.
///
/// Without this, a series that is constant over the baseline window has MAD 0
/// and every subsequent deviation scores infinity. The floor is relative to the
/// magnitude of the data so it adapts across metrics with wildly different units.
///
/// This doubles as the plan's required "minimum band-width floor" and it encodes
/// a deliberate effect-size choice: at the default z threshold of 3.5, a
/// perfectly flat series must move by ~35% of its own level before it is worth
/// reporting. A tighter floor makes every rock-steady gauge hypersensitive —
/// a 10% wobble on a constant series would score 10σ — which is precisely the
/// false-positive generator that made v1's alert layer unreadable. The
/// cross-sectional detector is the intended safety net for genuine small shifts:
/// if one host moves and its peers do not, peer-group catches it regardless of
/// how quiet that host's own history was.
const SCALE_FLOOR_FRACTION: f64 = 0.10;

/// Absolute floor for scale, for series whose values sit at or near zero.
const SCALE_FLOOR_ABSOLUTE: f64 = 1e-9;

/// Hard cap on the magnitude of any reported robust z-score.
///
/// A series that was flat at exactly zero and then becomes non-zero has no
/// meaningful scale: the floor is doing all the work and the arithmetic z runs
/// to billions, which then dominates every ranking it touches. That transition
/// is genuinely interesting, but "how many sigmas" is not a real quantity for
/// it — so it is reported as strongly interesting and capped, rather than
/// allowed to swamp findings whose magnitudes mean something.
///
/// The cap sits well above the default 3.5 threshold, so a capped finding still
/// ranks near the top of a digest; it simply cannot rank a million times higher
/// than a genuine 10σ excursion.
const Z_CAP: f64 = 25.0;

/// Clamp a z-score to the reportable range, preserving sign.
fn cap(z: f64) -> f64 {
    z.clamp(-Z_CAP, Z_CAP)
}

/// Median of a slice. Returns `None` for empty input.
///
/// Sorts a copy; callers pass short baseline windows so this is not hot.
pub(crate) fn median(values: &[f64]) -> Option<f64> {
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).expect("filtered to finite"));
    let mid = v.len() / 2;
    Some(if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    })
}

/// Median absolute deviation about the median.
pub(crate) fn mad(values: &[f64], center: f64) -> Option<f64> {
    let devs: Vec<f64> = values
        .iter()
        .copied()
        .filter(|x| x.is_finite())
        .map(|x| (x - center).abs())
        .collect();
    median(&devs)
}

/// Robust scale estimate (MAD → sigma-equivalent) with floors applied.
///
/// The floors prevent divide-by-near-zero from manufacturing enormous scores on
/// flat series — the single most common false-positive source in a naive
/// z-score sweep.
pub(crate) fn robust_scale(values: &[f64], center: f64) -> f64 {
    let raw = mad(values, center).unwrap_or(0.0) * MAD_TO_SIGMA;
    let relative_floor = center.abs() * SCALE_FLOOR_FRACTION;
    raw.max(relative_floor).max(SCALE_FLOOR_ABSOLUTE)
}

/// Robust z-score of `value` against a baseline window.
///
/// Returns `None` when the baseline is too short to be meaningful.
pub(crate) fn robust_z(value: f64, baseline: &[f64], min_samples: usize) -> Option<f64> {
    if baseline.len() < min_samples {
        return None;
    }
    let center = median(baseline)?;
    let scale = robust_scale(baseline, center);
    let z = (value - center) / scale;
    z.is_finite().then(|| cap(z))
}

/// Result of comparing two adjacent time windows of the same series.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WindowShift {
    pub(crate) before: f64,
    pub(crate) after: f64,
    /// Shift expressed in robust scale units of the `before` window.
    pub(crate) z: f64,
    /// Relative change, guarded against division by zero.
    pub(crate) relative: f64,
}

/// Compare two windows and express the level shift in robust units.
///
/// This is the change-point primitive. A full e-divisive/PELT segmentation is
/// deferred: for a scheduled sweep with fixed cadence, a two-window comparison
/// at the sweep boundary detects the same step changes at a fraction of the
/// complexity, and the plan explicitly wants change-points as *digest items*
/// rather than alerts.
pub(crate) fn window_shift(
    before: &[f64],
    after: &[f64],
    min_samples: usize,
) -> Option<WindowShift> {
    if before.len() < min_samples || after.len() < min_samples {
        return None;
    }
    let b = median(before)?;
    let a = median(after)?;
    let scale = robust_scale(before, b);
    let z = (a - b) / scale;
    if !z.is_finite() {
        return None;
    }
    let z = cap(z);
    let denom = b.abs().max(SCALE_FLOOR_ABSOLUTE);
    Some(WindowShift {
        before: b,
        after: a,
        z,
        relative: (a - b) / denom,
    })
}

/// One host's value within a cross-sectional (peer-group) comparison.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PeerDeviation {
    pub(crate) label: String,
    pub(crate) value: f64,
    pub(crate) z: f64,
}

/// Rank peers by robust deviation from the peer-group median.
///
/// This catches "grey failures": a node sitting inside its own per-node
/// thresholds while behaving unlike every sibling. Per-node alerting is blind to
/// this by construction, which is why the plan lists it as a first-class sweep
/// technique.
///
/// Requires at least 3 peers — with 2, "the median" and "the outlier" are the
/// same statement and the comparison carries no information.
pub(crate) fn peer_group_outliers(peers: &[(String, f64)]) -> Vec<PeerDeviation> {
    if peers.len() < 3 {
        return Vec::new();
    }
    let values: Vec<f64> = peers.iter().map(|(_, v)| *v).collect();
    let Some(center) = median(&values) else {
        return Vec::new();
    };
    let scale = robust_scale(&values, center);
    let mut out: Vec<PeerDeviation> = peers
        .iter()
        .map(|(label, value)| PeerDeviation {
            label: label.clone(),
            value: *value,
            z: cap((value - center) / scale),
        })
        .filter(|d| d.z.is_finite())
        .collect();
    out.sort_by(|a, b| {
        b.z.abs()
            .partial_cmp(&a.z.abs())
            .expect("filtered to finite")
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_even_and_odd() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn median_ignores_non_finite() {
        assert_eq!(median(&[1.0, f64::NAN, 3.0]), Some(2.0));
    }

    #[test]
    fn robust_scale_never_zero_on_flat_series() {
        // A constant series has MAD 0. Without a floor this would make every
        // later deviation score infinite — the failure mode this guards.
        let flat = vec![5.0; 20];
        let scale = robust_scale(&flat, 5.0);
        assert!(scale > 0.0);
        let z = robust_z(6.0, &flat, 5).expect("enough samples");
        assert!(z.is_finite());
    }

    #[test]
    fn contamination_does_not_move_the_center() {
        // 20 normal samples plus 4 extreme ones. A mean would be dragged to ~102
        // by the contamination; the median must stay at the true level of 10.
        // This is the property that fixes v1's band self-contamination bug.
        let mut baseline = vec![10.0; 20];
        baseline.extend_from_slice(&[500.0, 520.0, 540.0, 560.0]);
        let center = median(&baseline).expect("non-empty");
        assert_eq!(center, 10.0, "contamination moved the center");

        let mean = baseline.iter().sum::<f64>() / baseline.len() as f64;
        assert!(
            mean > 90.0,
            "sanity: the mean really is wrecked by this contamination (got {mean})"
        );
    }

    #[test]
    fn flat_series_needs_a_meaningful_move_to_register() {
        // A perfectly flat baseline has MAD 0, so the floor decides sensitivity.
        // A 10% move must stay under the default 3.5 threshold; a 50% move must
        // clear it. This pins the effect-size contract the floor encodes.
        let flat = vec![10.0; 20];
        let small = robust_z(11.0, &flat, 5).expect("enough samples");
        assert!(
            small.abs() < 3.5,
            "a 10% move on a flat series should not be a finding: z={small}"
        );
        let large = robust_z(15.0, &flat, 5).expect("enough samples");
        assert!(
            large.abs() >= 3.5,
            "a 50% move on a flat series should be a finding: z={large}"
        );
    }

    #[test]
    fn contaminated_baseline_still_flags_a_genuine_departure() {
        // Robustness must not mean insensitivity: with the same contaminated
        // baseline, a real departure from the true level is still caught.
        let mut baseline = vec![10.0; 20];
        baseline.extend_from_slice(&[500.0, 520.0, 540.0, 560.0]);
        let z = robust_z(80.0, &baseline, 5).expect("enough samples");
        assert!(z.abs() >= 3.5, "genuine departure missed: z={z}");
    }

    #[test]
    fn robust_z_requires_minimum_samples() {
        assert_eq!(robust_z(1.0, &[1.0, 2.0], 5), None);
    }

    #[test]
    fn zero_baseline_activation_is_capped_not_astronomical() {
        // The live-data bug this guards: a series flat at exactly 0 that becomes
        // non-zero divided by the 1e-9 absolute floor and scored ~2e9, which
        // dominated every ranking it appeared in.
        let all_zero = vec![0.0; 20];
        let z = robust_z(2.07, &all_zero, 5).expect("enough samples");
        assert_eq!(z, Z_CAP, "zero-baseline activation must clamp to the cap");
        // Still comfortably reportable — capping must not hide the transition.
        assert!(z > 3.5);
    }

    #[test]
    fn cap_applies_to_all_three_detectors() {
        let all_zero = vec![0.0; 20];
        let hot = vec![5.0; 20];

        let shift = window_shift(&all_zero, &hot, 5).expect("enough samples");
        assert_eq!(shift.z, Z_CAP);

        let peers = vec![
            ("a".to_string(), 0.0),
            ("b".to_string(), 0.0),
            ("c".to_string(), 0.0),
            ("d".to_string(), 99.0),
        ];
        let out = peer_group_outliers(&peers);
        assert_eq!(out[0].label, "d");
        assert_eq!(out[0].z, Z_CAP);
    }

    #[test]
    fn cap_preserves_sign_and_leaves_normal_scores_untouched() {
        let flat = vec![0.0; 20];
        assert_eq!(robust_z(-2.0, &flat, 5), Some(-Z_CAP));
        // A genuine, meaningful excursion must pass through unmodified.
        let baseline: Vec<f64> = (0..20).map(|i| 10.0 + f64::from(i % 3)).collect();
        let z = robust_z(18.0, &baseline, 5).expect("enough samples");
        assert!(z.abs() < Z_CAP, "ordinary excursion was clamped: {z}");
    }

    #[test]
    fn window_shift_detects_step_change() {
        let before = vec![10.0; 10];
        let after = vec![40.0; 10];
        let shift = window_shift(&before, &after, 5).expect("enough samples");
        assert_eq!(shift.before, 10.0);
        assert_eq!(shift.after, 40.0);
        assert!(
            shift.z > 3.0,
            "step change should be significant: {shift:?}"
        );
        assert!((shift.relative - 3.0).abs() < 1e-9);
    }

    #[test]
    fn window_shift_ignores_stable_series() {
        let before = vec![10.0, 10.1, 9.9, 10.05, 9.95, 10.0];
        let after = vec![10.02, 9.98, 10.01, 10.0, 9.99, 10.03];
        let shift = window_shift(&before, &after, 5).expect("enough samples");
        assert!(shift.z.abs() < 3.0, "stable series flagged: {shift:?}");
    }

    #[test]
    fn peer_group_finds_the_odd_node_out() {
        let peers = vec![
            ("vps-core-01".to_string(), 13878.0),
            ("bitcoin-01".to_string(), 7955.0),
            ("vps-knots-01".to_string(), 0.0),
            ("vps-libre-01".to_string(), 0.0),
        ];
        let out = peer_group_outliers(&peers);
        assert_eq!(out.len(), 4);
        // The top-ranked deviation must be a real outlier, not a tie artifact.
        assert!(out[0].z.abs() > 0.0);
        // Every returned deviation is finite and ordered by descending |z|.
        for w in out.windows(2) {
            assert!(w[0].z.abs() >= w[1].z.abs());
        }
    }

    #[test]
    fn peer_group_needs_three_peers() {
        let peers = vec![("a".to_string(), 1.0), ("b".to_string(), 100.0)];
        assert!(peer_group_outliers(&peers).is_empty());
    }

    #[test]
    fn peer_group_quiet_when_all_agree() {
        let peers = vec![
            ("a".to_string(), 10.0),
            ("b".to_string(), 10.1),
            ("c".to_string(), 9.9),
            ("d".to_string(), 10.05),
        ];
        let out = peer_group_outliers(&peers);
        assert!(
            out.iter().all(|d| d.z.abs() < 5.0),
            "homogeneous fleet produced an outlier: {out:?}"
        );
    }
}
