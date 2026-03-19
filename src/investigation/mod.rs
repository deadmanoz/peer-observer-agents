mod collector;
mod runner;

use anyhow::Result;

use crate::correlation::AlertId;
use crate::prompt::AlertContext;
use crate::state::AppState;
use crate::types::{Alert, ClaudeOutput};

/// Call the Claude Code CLI with Prometheus MCP tools to investigate the alert.
///
/// Claude has access to Prometheus via MCP and can autonomously query metrics,
/// drill into per-peer data, and correlate across hosts to determine root cause.
pub(crate) async fn call_claude(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
) -> Result<ClaudeOutput> {
    let prefetch = collector::collect_context(state, alert, aid).await;
    let ctx =
        AlertContext::from_alert(&alert.labels, &alert.annotations, alert.starts_at, prefetch);
    runner::run_claude(state, &ctx, aid).await
}
