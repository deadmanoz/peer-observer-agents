use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::annotation::{
    parse_structured_annotation, render_annotation_html, sanitize_raw_fallback, AnnotationError,
    POLICY_VIOLATION_STUB,
};
use crate::cooldown::{try_claim_cooldown, CooldownKey, SuppressReason};
use crate::correlation::AlertId;
use crate::grafana::post_grafana_annotation;
use crate::investigation::call_claude;
use crate::state::AppState;
use crate::types::Alert;
use crate::viewer::{LogEntry, Telemetry};

pub(crate) async fn process_alert(state: &AppState, alert: &Alert, aid: &AlertId) -> Result<()> {
    // Cooldown suppression: coalesce retriggers of the same (alertname, host, threadname)
    // within the cooldown window. Checked before the semaphore to avoid holding
    // a concurrency slot for suppressed alerts.
    let cooldown_guard = if !state.cooldown.is_zero() {
        let key: CooldownKey = (
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
        );
        match try_claim_cooldown(key, &state.cooldown_map, state.cooldown) {
            Ok(guard) => Some(guard),
            Err(SuppressReason::InFlight) => {
                info!(alert_id = %aid, "skipping: investigation already in flight");
                return Ok(());
            }
            Err(SuppressReason::RecentlyCompleted { ago }) => {
                info!(
                    alert_id = %aid,
                    cooldown_secs = state.cooldown.as_secs(),
                    elapsed_secs = ago.as_secs(),
                    "skipping: recent investigation within cooldown window"
                );
                return Ok(());
            }
        }
    } else {
        None
    };

    let _permit = state
        .investigation_semaphore
        .acquire()
        .await
        .context("investigation semaphore closed")?;
    let claude_output = call_claude(state, alert, aid).await?;
    let telemetry = Telemetry::from(&claude_output);

    match parse_structured_annotation(&claude_output.result) {
        Ok(ann) => {
            let html = render_annotation_html(&ann);
            post_grafana_annotation(state, alert, aid, &html, Some(&ann.verdict)).await?;
            append_log(state, alert, aid, Some(&ann), None, &telemetry).await;
            info!(alert_id = %aid, verdict = %ann.verdict, "annotation posted successfully");
        }
        Err(AnnotationError::PolicyViolation(msg)) => {
            // Structured path detected a policy violation (e.g., via deserialized
            // fields that resolved JSON Unicode escapes). Force redaction regardless
            // of whether the raw scan also catches it.
            warn!(
                alert_id = %aid,
                error = %msg,
                "structured annotation rejected by peer-intervention policy"
            );
            // Log full original output for forensic audit — only to tracing,
            // never persisted in Grafana or the /logs viewer.
            warn!(
                alert_id = %aid,
                raw_output = %claude_output.result,
                "original output for policy violation (not posted to Grafana)"
            );
            post_grafana_annotation(
                state,
                alert,
                aid,
                &format!("<b>POLICY VIOLATION:</b> {POLICY_VIOLATION_STUB}"),
                None,
            )
            .await?;
            append_log(
                state,
                alert,
                aid,
                None,
                Some(POLICY_VIOLATION_STUB),
                &telemetry,
            )
            .await;
            info!(alert_id = %aid, "annotation posted (policy violation stub)");
        }
        Err(AnnotationError::ParseError(e)) => {
            warn!(
                alert_id = %aid,
                error = %e,
                "failed to parse structured annotation, using raw text"
            );
            let fallback = sanitize_raw_fallback(&claude_output.result);
            if fallback.policy_violated {
                warn!(
                    alert_id = %aid,
                    pattern = fallback.matched_pattern.unwrap_or("unknown"),
                    "raw annotation redacted: peer-intervention command detected"
                );
                // Forensic audit — mirrors the structured PolicyViolation path.
                warn!(
                    alert_id = %aid,
                    raw_output = %claude_output.result,
                    "original output for policy violation (not posted to Grafana)"
                );
            }
            post_grafana_annotation(state, alert, aid, &fallback.grafana_body, None).await?;
            append_log(
                state,
                alert,
                aid,
                None,
                Some(&fallback.log_text),
                &telemetry,
            )
            .await;
            if fallback.policy_violated {
                info!(alert_id = %aid, "annotation posted (policy violation stub)");
            } else {
                info!(alert_id = %aid, "annotation posted successfully (raw fallback)");
            }
        }
    }

    // Mark cooldown as completed only after both Claude AND Grafana succeed.
    // If Grafana fails, the guard drops without complete(), clearing the
    // InFlight entry so Alertmanager retries are not suppressed.
    //
    // Trade-off: during a sustained Grafana outage, every Alertmanager retry
    // re-invokes Claude (expensive) because the cooldown is never committed.
    // This is intentional — the alternative (completing after Claude only)
    // silently drops annotations when Grafana recovers, because the cooldown
    // suppresses the retry before `annotation_exists` is ever reached.
    if let Some(guard) = cooldown_guard {
        guard.complete();
    }

    Ok(())
}

async fn append_log(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
    ann: Option<&crate::annotation::StructuredAnnotation>,
    raw_text: Option<&str>,
    telemetry: &Telemetry,
) {
    let Some(ref path) = state.log_file else {
        return;
    };
    let entry = match ann {
        Some(ann) => LogEntry::structured(
            alert.starts_at,
            aid.to_string(),
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
            ann.verdict.as_tag(),
            ann.action.clone(),
            ann.summary.clone(),
            ann.cause.clone(),
            ann.scope.clone(),
            ann.evidence.clone(),
            telemetry.clone(),
        ),
        None => LogEntry::raw_fallback(
            alert.starts_at,
            aid.to_string(),
            aid.alertname.clone(),
            aid.host.clone(),
            aid.threadname.clone(),
            raw_text.unwrap_or("").to_string(),
            telemetry.clone(),
        ),
    };
    crate::viewer::append_jsonl_log(path, &entry, &state.log_write_mutex).await;
}
