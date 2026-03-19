use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

use crate::correlation::AlertId;
use crate::grafana::{fetch_recent_annotations, format_prior_context};
use crate::prompt::{AlertContext, PreFetchData};
use crate::state::AppState;
use crate::types::{Alert, ClaudeOutput};

/// Parse Claude CLI JSON output into structured telemetry.
pub(crate) fn parse_claude_output(raw: &str) -> Result<ClaudeOutput> {
    let json: serde_json::Value =
        serde_json::from_str(raw).context("failed to parse claude JSON output")?;

    Ok(ClaudeOutput {
        result: json
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string(),
        is_error: json
            .get("is_error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        num_turns: json.get("num_turns").and_then(|v| v.as_u64()).unwrap_or(0),
        duration_ms: json
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        duration_api_ms: json
            .get("duration_api_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        cost_usd: json
            .get("total_cost_usd")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        input_tokens: json
            .pointer("/usage/input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_tokens: json
            .pointer("/usage/output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        stop_reason: json
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        session_id: json
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
    })
}

/// Call the Claude Code CLI with Prometheus MCP tools to investigate the alert.
///
/// Claude has access to Prometheus via MCP and can autonomously query metrics,
/// drill into per-peer data, and correlate across hosts to determine root cause.
pub(crate) async fn call_claude(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
) -> Result<ClaudeOutput> {
    // Fetch prior annotations, RPC data, and Parca profiles concurrently —
    // they're independent and can each take up to 30s (Grafana HTTP timeout) /
    // 10s (RPC deadline) / 10s (Parca deadline).
    let host = alert
        .labels
        .get("host")
        .map(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();
    let alertname = alert
        .labels
        .get("alertname")
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let aid_str = aid.to_string();

    let (
        recent,
        (rpc_context, rpc_fetched_at),
        (parca_context, parca_fetched_at),
        (debug_log_context, debug_log_fetched_at),
    ) = tokio::join!(
        fetch_recent_annotations(state, alert),
        async {
            match &state.rpc_client {
                Some(rpc) => rpc.prefetch(&host, &alertname, &aid_str).await,
                None => (String::new(), None),
            }
        },
        async {
            match &state.parca_client {
                Some(parca) => {
                    parca
                        .prefetch(&host, &alertname, &aid_str, alert.starts_at)
                        .await
                }
                None => (String::new(), None),
            }
        },
        async {
            match &state.debug_log_client {
                Some(client) => {
                    client
                        .prefetch(&host, &alertname, &aid_str, alert.starts_at)
                        .await
                }
                None => (String::new(), None),
            }
        }
    );
    let prior_context = format_prior_context(&recent);

    let prefetch = PreFetchData {
        prior_context,
        rpc_context,
        rpc_fetched_at,
        parca_context,
        parca_fetched_at,
        debug_log_context,
        debug_log_fetched_at,
    };
    let ctx =
        AlertContext::from_alert(&alert.labels, &alert.annotations, alert.starts_at, prefetch);

    info!(alert_id = %aid, "calling claude with MCP prometheus tools");

    // SAFETY: setsid() is async-signal-safe per POSIX. It creates a new
    // session/process group so that on timeout we can kill the entire tree
    // (Claude + any MCP subprocesses it spawns).
    let child = unsafe {
        Command::new(&state.claude_bin)
            .args([
                "--dangerously-skip-permissions",
                "--mcp-config",
                &state.mcp_config,
                "-p",
                &crate::prompt::build_investigation_prompt(&ctx),
                "--model",
                &state.claude_model,
                "--output-format",
                "json",
            ])
            .pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn claude process at '{}'", state.claude_bin))?
    };

    let pid = child.id().context("failed to get claude child PID")? as i32;

    let result = tokio::time::timeout(state.claude_timeout, child.wait_with_output()).await;

    let output = match result {
        Ok(output) => output.context("failed to wait on claude process")?,
        Err(_) => {
            // Timeout: kill the entire process group (negative PID = group).
            // SAFETY: pid is valid and we created the group via setsid().
            warn!(alert_id = %aid, "claude investigation timed out, killing process group");
            let kill_ret = unsafe { libc::kill(-pid, libc::SIGKILL) };
            if kill_ret == -1 {
                let err = std::io::Error::last_os_error();
                warn!(alert_id = %aid, "failed to kill process group {pid}: {err}");
            }
            anyhow::bail!(
                "claude investigation timed out after {:?}",
                state.claude_timeout
            );
        }
    };

    // Log stderr if present (may contain MCP server startup info or warnings).
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    if !stderr_text.trim().is_empty() {
        warn!(alert_id = %aid, stderr = %stderr_text.trim(), "claude stderr output");
    }

    if !output.status.success() {
        anyhow::bail!(
            "claude process exited with {}: {stderr_text}",
            output.status
        );
    }

    let raw = String::from_utf8(output.stdout).context("claude output is not valid UTF-8")?;

    let parsed = parse_claude_output(&raw)?;

    info!(
        alert_id = %aid,
        num_turns = parsed.num_turns,
        duration_ms = parsed.duration_ms,
        duration_api_ms = parsed.duration_api_ms,
        cost_usd = parsed.cost_usd,
        input_tokens = parsed.input_tokens,
        output_tokens = parsed.output_tokens,
        stop_reason = parsed.stop_reason,
        is_error = parsed.is_error,
        session_id = parsed.session_id,
        "claude investigation completed"
    );

    if parsed.is_error {
        anyhow::bail!("claude returned error: {}", parsed.result);
    }

    if parsed.result.is_empty() {
        anyhow::bail!("claude returned empty result");
    }

    if parsed.result.contains("Reached max turns") {
        anyhow::bail!("claude hit max turns limit without producing an annotation");
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Claude output parsing ──────────────────────────────────────────

    #[test]
    fn parse_successful_claude_output() {
        let json = r#"{
            "result": "Inbound connections dropped due to Tor network instability.",
            "is_error": false,
            "num_turns": 5,
            "duration_ms": 12000,
            "duration_api_ms": 10000,
            "total_cost_usd": 0.025,
            "stop_reason": "end_turn",
            "session_id": "abc-123",
            "usage": {"input_tokens": 5000, "output_tokens": 200}
        }"#;
        let output = parse_claude_output(json).unwrap();
        assert_eq!(
            output.result,
            "Inbound connections dropped due to Tor network instability."
        );
        assert!(!output.is_error);
        assert_eq!(output.num_turns, 5);
        assert_eq!(output.duration_ms, 12000);
        assert_eq!(output.duration_api_ms, 10000);
        assert!((output.cost_usd - 0.025).abs() < f64::EPSILON);
        assert_eq!(output.input_tokens, 5000);
        assert_eq!(output.output_tokens, 200);
        assert_eq!(output.stop_reason, "end_turn");
        assert_eq!(output.session_id, "abc-123");
    }

    #[test]
    fn parse_error_claude_output() {
        let json = r#"{
            "result": "MCP server failed to start",
            "is_error": true,
            "num_turns": 1
        }"#;
        let output = parse_claude_output(json).unwrap();
        assert!(output.is_error);
        assert_eq!(output.result, "MCP server failed to start");
    }

    #[test]
    fn parse_claude_output_with_missing_fields() {
        let json = r#"{"result": "some text"}"#;
        let output = parse_claude_output(json).unwrap();
        assert_eq!(output.result, "some text");
        assert!(!output.is_error);
        assert_eq!(output.num_turns, 0);
        assert_eq!(output.duration_ms, 0);
        assert_eq!(output.cost_usd, 0.0);
        assert_eq!(output.input_tokens, 0);
        assert_eq!(output.output_tokens, 0);
        assert_eq!(output.stop_reason, "unknown");
        assert_eq!(output.session_id, "unknown");
    }

    #[test]
    fn parse_claude_output_trims_whitespace() {
        let json = r#"{"result": "  annotation text with spaces  "}"#;
        let output = parse_claude_output(json).unwrap();
        assert_eq!(output.result, "annotation text with spaces");
    }

    #[test]
    fn parse_claude_output_empty_result() {
        let json = r#"{"result": ""}"#;
        let output = parse_claude_output(json).unwrap();
        assert!(output.result.is_empty());
    }

    #[test]
    fn parse_claude_output_null_result() {
        let json = r#"{"result": null}"#;
        let output = parse_claude_output(json).unwrap();
        assert!(output.result.is_empty());
    }

    #[test]
    fn parse_claude_output_invalid_json() {
        let result = parse_claude_output("not json at all");
        assert!(result.is_err());
    }
}
