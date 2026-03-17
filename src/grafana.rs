use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::annotation::{strip_annotation_html, Verdict};
use crate::correlation::{build_annotation_tags, build_idempotency_tags, AlertId};
use crate::state::AppState;
use crate::types::Alert;

// Grafana annotation payload.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrafanaAnnotation {
    time: i64,
    time_end: i64,
    tags: Vec<String>,
    text: String,
}

// Grafana annotation read from the API.
#[derive(Debug, Deserialize)]
pub(crate) struct GrafanaAnnotationResponse {
    pub(crate) tags: Vec<String>,
    pub(crate) text: String,
    pub(crate) time: i64,
}

/// Compute the annotation end time, treating non-positive timestamps as point-in-time.
///
/// Alertmanager uses "0001-01-01T00:00:00Z" for still-firing alerts. We require
/// `ends_at` to be strictly after the Unix epoch (timestamp > 0); anything at or
/// before it (including the epoch itself) falls back to `time_ms`.
fn compute_annotation_time_end(time_ms: i64, ends_at: Option<DateTime<Utc>>) -> i64 {
    ends_at
        .filter(|t| t.timestamp() > 0)
        .map(|t| t.timestamp_millis())
        .unwrap_or(time_ms)
}

pub(crate) async fn post_grafana_annotation(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
    text: &str,
    verdict: Option<&Verdict>,
) -> Result<()> {
    let time_ms = alert.starts_at.timestamp_millis();
    let time_end_ms = compute_annotation_time_end(time_ms, alert.ends_at);

    // Idempotency key: stable tag set (3 or 4 elements depending on threadname
    // presence). Verdict is NOT part of the key so that a retry where one attempt
    // falls back to raw text and another succeeds with structured output will
    // still match as a duplicate.
    let key_tags = build_idempotency_tags(aid);

    if annotation_exists(state, &key_tags, time_ms).await {
        info!(
            alert_id = %aid,
            "annotation already exists, skipping duplicate post"
        );
        return Ok(());
    }

    // Posted tags: key tags + verdict (if structured parsing succeeded).
    let tags = build_annotation_tags(aid, verdict);

    let annotation = GrafanaAnnotation {
        time: time_ms,
        time_end: time_end_ms,
        tags,
        text: text.to_string(),
    };

    let resp = state
        .http
        .post(format!("{}/api/annotations", state.grafana_url))
        .header("Authorization", format!("Bearer {}", state.grafana_api_key))
        .header("Content-Type", "application/json")
        .json(&annotation)
        .send()
        .await
        .context("grafana annotation request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("grafana API returned {status}: {text}");
    }

    Ok(())
}

/// Check whether an annotation with the given tags already exists at the given time.
/// Uses a narrow ±1 second window around the alert start time.
///
/// This is a best-effort check, not atomic: two concurrent webhook deliveries could
/// both pass the check before either posts. That's acceptable — the worst case is a
/// duplicate annotation, not data loss.
async fn annotation_exists(state: &AppState, tags: &[String], time_ms: i64) -> bool {
    let url = format!("{}/api/annotations", state.grafana_url);
    let from = (time_ms - 1000).to_string();
    let to = (time_ms + 1000).to_string();

    let mut params: Vec<(&str, &str)> = vec![("from", &from), ("to", &to), ("limit", "1")];
    for tag in tags {
        params.push(("tags", tag));
    }

    let result = state
        .http
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.grafana_api_key))
        .query(&params)
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => resp
            .json::<Vec<GrafanaAnnotationResponse>>()
            .await
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        _ => false, // On error, proceed to post (better to duplicate than to lose)
    }
}

/// Fetch recent AI annotations from Grafana to provide as context for the investigation.
/// Looks back 1 hour for annotations tagged with `ai-annotation` from the same host.
pub(crate) async fn fetch_recent_annotations(
    state: &AppState,
    alert: &Alert,
) -> Vec<GrafanaAnnotationResponse> {
    let from = alert.starts_at.timestamp_millis() - 3_600_000; // 1 hour before
    let to = alert.starts_at.timestamp_millis();
    let host = alert
        .labels
        .get("host")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let url = format!("{}/api/annotations", state.grafana_url);

    let result = state
        .http
        .get(&url)
        .header("Authorization", format!("Bearer {}", state.grafana_api_key))
        .query(&[
            ("tags", "ai-annotation"),
            ("tags", &host),
            ("from", &from.to_string()),
            ("to", &to.to_string()),
            ("limit", "10"),
        ])
        .send()
        .await;

    match result {
        Ok(resp) if resp.status().is_success() => resp
            .json::<Vec<GrafanaAnnotationResponse>>()
            .await
            .unwrap_or_default(),
        Ok(resp) => {
            warn!("failed to fetch recent annotations: HTTP {}", resp.status());
            Vec::new()
        }
        Err(e) => {
            warn!("failed to fetch recent annotations: {e}");
            Vec::new()
        }
    }
}

/// Format prior Grafana annotations into a context string for the investigation prompt.
pub(crate) fn format_prior_context(recent: &[GrafanaAnnotationResponse]) -> String {
    if recent.is_empty() {
        return String::new();
    }

    let mut ctx = String::from(
        "\n## Prior Annotations (last 1 hour, same host)\n\n\
         The following AI annotations were created for recent alerts on the same host. \
         They may or may not be related to this alert — use your judgement to determine \
         if they are part of the same incident. If they are, reference the prior findings \
         and avoid repeating the same investigation.\n\n",
    );
    for ann in recent {
        let ts = chrono::DateTime::from_timestamp_millis(ann.time)
            .map(|t| t.format("%H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let tags = ann.tags.join(", ");
        // Strip HTML tags from prior annotations so Claude sees clean structured text.
        // Prior annotations may be HTML (from structured format) or plain text (from
        // raw fallback) — strip_annotation_html handles both safely.
        let clean_text = strip_annotation_html(&ann.text);
        ctx.push_str(&format!("### [{tags}] at {ts}\n{clean_text}\n\n"));
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ── Annotation time computation ────────────────────────────────────

    #[test]
    fn time_end_uses_ends_at_when_valid() {
        let start_ms = 1_718_452_800_000i64; // 2024-06-15T12:00:00Z
        let end = Utc.with_ymd_and_hms(2024, 6, 15, 12, 30, 0).unwrap();
        let result = compute_annotation_time_end(start_ms, Some(end));
        assert_eq!(result, end.timestamp_millis());
    }

    #[test]
    fn time_end_falls_back_for_sentinel() {
        let start_ms = 1_718_452_800_000i64; // 2024-06-15T12:00:00Z
                                             // Alertmanager sentinel: "0001-01-01T00:00:00Z" has a negative timestamp
        let sentinel = chrono::DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let result = compute_annotation_time_end(start_ms, Some(sentinel));
        assert_eq!(result, start_ms);
    }

    #[test]
    fn time_end_falls_back_for_none() {
        let start_ms = 1_718_452_800_000i64; // 2024-06-15T12:00:00Z
        let result = compute_annotation_time_end(start_ms, None);
        assert_eq!(result, start_ms);
    }

    #[test]
    fn time_end_rejects_exactly_epoch() {
        let start_ms = 1_718_452_800_000i64; // 2024-06-15T12:00:00Z
        let epoch = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        // timestamp() == 0, filter requires > 0
        let result = compute_annotation_time_end(start_ms, Some(epoch));
        assert_eq!(result, start_ms);
    }

    // ── Prior context formatting ───────────────────────────────────────

    #[test]
    fn format_prior_context_empty() {
        assert!(format_prior_context(&[]).is_empty());
    }

    #[test]
    fn format_prior_context_with_annotations() {
        let annotations = vec![
            GrafanaAnnotationResponse {
                tags: vec!["ai-annotation".into(), "TestAlert".into()],
                text: "First annotation.".into(),
                time: 1_718_449_200_000, // 11:00 UTC
            },
            GrafanaAnnotationResponse {
                tags: vec!["ai-annotation".into(), "OtherAlert".into()],
                text: "Second annotation.".into(),
                time: 1_718_452_800_000, // 12:00 UTC
            },
        ];
        let ctx = format_prior_context(&annotations);
        assert!(ctx.contains("Prior Annotations (last 1 hour, same host)"));
        assert!(ctx.contains("First annotation."));
        assert!(ctx.contains("Second annotation."));
        assert!(ctx.contains("ai-annotation, TestAlert"));
        assert!(ctx.contains("ai-annotation, OtherAlert"));
    }

    // ── Grafana annotation construction ────────────────────────────────

    #[test]
    fn grafana_annotation_serialization() {
        let ann = GrafanaAnnotation {
            time: 1_718_452_800_000,
            time_end: 1_718_454_600_000,
            tags: vec![
                "ai-annotation".into(),
                "TestAlert".into(),
                "bitcoin-03".into(),
            ],
            text: "Test annotation".into(),
        };
        let json = serde_json::to_value(&ann).unwrap();
        assert_eq!(json["time"], 1_718_452_800_000i64);
        assert_eq!(json["timeEnd"], 1_718_454_600_000i64);
        assert_eq!(json["tags"][0], "ai-annotation");
        assert_eq!(json["text"], "Test annotation");
    }

    // ── Prior context HTML stripping ──────────────────────────────────

    #[test]
    fn format_prior_context_strips_html() {
        let annotations = vec![GrafanaAnnotationResponse {
            tags: vec!["ai-annotation".into(), "TestAlert".into()],
            text: "<b>VERDICT:</b> BENIGN<br><b>SUMMARY:</b> test".into(),
            time: 1_718_449_200_000,
        }];
        let ctx = format_prior_context(&annotations);
        assert!(
            !ctx.contains("<b>"),
            "prior context should not contain HTML tags"
        );
        assert!(ctx.contains("VERDICT:"));
        assert!(ctx.contains("SUMMARY:"));
    }
}
