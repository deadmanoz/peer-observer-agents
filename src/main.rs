mod annotation;
mod prompt;
mod rpc;

use crate::annotation::{
    html_escape, parse_structured_annotation, render_annotation_html, render_annotation_plaintext,
    sanitize_log_field, strip_annotation_html, Verdict,
};
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use prompt::AlertContext;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap, env, fmt, net::SocketAddr, sync::Arc, time::Duration, time::Instant,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, process::Command};
use tracing::{error, info, warn};

/// Default HTTP client timeout for Grafana API calls.
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// Default maximum wall-clock time for a Claude CLI investigation.
const DEFAULT_CLAUDE_TIMEOUT_SECS: u64 = 600;

/// Default maximum number of concurrent Claude investigations.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Default cooldown window (seconds) for suppressing retriggers of the same
/// `(alertname, host)` pair. 0 = disabled.
const DEFAULT_COOLDOWN_SECS: u64 = 1800;

// ── Cooldown suppression ──────────────────────────────────────────────

#[derive(Debug, Clone)]
enum CooldownState {
    InFlight,
    Completed(Instant),
}

type CooldownKey = (String, String);
type CooldownMap = std::sync::Mutex<HashMap<CooldownKey, CooldownState>>;

/// Why a claim was rejected.
#[derive(Debug)]
enum SuppressReason {
    InFlight,
    RecentlyCompleted { elapsed_secs: u64 },
}

/// RAII guard that manages cooldown state transitions.
/// - Created by `try_claim_cooldown` which atomically checks + inserts `InFlight`.
/// - `complete()`: transitions to `Completed(Instant::now())`.
/// - Drop without `complete()`: removes the entry (failure/panic cleanup).
struct CooldownGuard<'a> {
    key: CooldownKey,
    map: &'a CooldownMap,
    completed: bool,
}

impl<'a> CooldownGuard<'a> {
    fn complete(mut self) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(self.key.clone(), CooldownState::Completed(Instant::now()));
        self.completed = true;
    }
}

impl Drop for CooldownGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&self.key);
        }
    }
}

/// Atomically check existing state and claim InFlight if allowed.
/// Single mutex acquisition — no TOCTOU race between check and insert.
/// Also sweeps stale `Completed` entries (expired beyond the cooldown window)
/// to prevent unbounded growth on long-lived instances.
fn try_claim_cooldown<'a>(
    key: CooldownKey,
    map: &'a CooldownMap,
    cooldown: Duration,
) -> std::result::Result<CooldownGuard<'a>, SuppressReason> {
    let mut locked = map.lock().unwrap_or_else(|e| e.into_inner());

    // Sweep stale entries while we hold the lock.
    locked.retain(|_, v| match v {
        CooldownState::InFlight => true,
        CooldownState::Completed(at) => at.elapsed() < cooldown,
    });

    match locked.get(&key) {
        Some(CooldownState::InFlight) => {
            return Err(SuppressReason::InFlight);
        }
        Some(CooldownState::Completed(at)) => {
            let elapsed = at.elapsed();
            if elapsed < cooldown {
                return Err(SuppressReason::RecentlyCompleted {
                    elapsed_secs: elapsed.as_secs(),
                });
            }
        }
        _ => {}
    }
    locked.insert(key.clone(), CooldownState::InFlight);
    Ok(CooldownGuard {
        key,
        map,
        completed: false,
    })
}

struct AppState {
    grafana_url: String,
    grafana_api_key: String,
    claude_bin: String,
    claude_model: String,
    mcp_config: String,
    log_file: Option<String>,
    claude_timeout: Duration,
    http: reqwest::Client,
    /// Optional Bitcoin Core RPC client for pre-fetching node data.
    /// `None` when `ANNOTATION_AGENT_RPC_HOSTS` is not set (feature disabled).
    rpc_client: Option<rpc::RpcClient>,
    /// Limits the number of concurrent Claude investigations to prevent
    /// resource exhaustion when Alertmanager delivers large grouped batches.
    investigation_semaphore: Semaphore,
    /// Cooldown window for suppressing retriggers of the same `(alertname, host)`.
    /// `Duration::ZERO` disables suppression.
    cooldown: Duration,
    /// In-process state for cooldown suppression.
    cooldown_map: CooldownMap,
}

// Alertmanager webhook payload types.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlertmanagerPayload {
    alerts: Vec<Alert>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Alert {
    status: String,
    labels: HashMap<String, String>,
    annotations: Option<HashMap<String, String>>,
    starts_at: DateTime<Utc>,
    ends_at: Option<DateTime<Utc>>,
}

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
struct GrafanaAnnotationResponse {
    tags: Vec<String>,
    text: String,
    time: i64,
}

/// Stable correlation ID for an alert, derived from (alertname, host, startsAt).
/// Logged through all processing stages so a single alert can be traced end-to-end.
#[derive(Debug, Clone)]
struct AlertId {
    alertname: String,
    host: String,
    started: DateTime<Utc>,
}

impl AlertId {
    fn from_alert(alert: &Alert) -> Self {
        Self {
            alertname: alert.labels.get("alertname").cloned().unwrap_or_default(),
            host: alert
                .labels
                .get("host")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            started: alert.starts_at,
        }
    }
}

impl fmt::Display for AlertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.alertname,
            self.host,
            self.started.format("%Y%m%dT%H%M%SZ")
        )
    }
}

/// Build the stable tag set used for idempotency checks.
/// Verdict is NOT included — it may differ between retries (fallback vs structured).
fn build_idempotency_tags(aid: &AlertId) -> Vec<String> {
    vec![
        "ai-annotation".to_string(),
        aid.alertname.clone(),
        aid.host.clone(),
    ]
}

/// Build the full tag set posted to Grafana (idempotency tags + verdict).
fn build_annotation_tags(aid: &AlertId, verdict: Option<&Verdict>) -> Vec<String> {
    let mut tags = build_idempotency_tags(aid);
    if let Some(v) = verdict {
        tags.push(v.as_tag().to_string());
    }
    tags
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "peer_observer_agent=info".into()),
        )
        .init();

    let listen_addr: SocketAddr = env::var("ANNOTATION_AGENT_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9099".to_string())
        .parse()
        .context("invalid listen address")?;

    let http_timeout_secs: u64 = env::var("ANNOTATION_AGENT_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_HTTP_TIMEOUT_SECS);

    let claude_timeout_secs: u64 = env::var("ANNOTATION_AGENT_CLAUDE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CLAUDE_TIMEOUT_SECS);

    let max_concurrent: usize = env::var("ANNOTATION_AGENT_MAX_CONCURRENT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONCURRENT)
        .max(1); // Prevent deadlock: 0 permits would block all investigations forever.

    let cooldown_secs: u64 = env::var("ANNOTATION_AGENT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_COOLDOWN_SECS);

    // Bitcoin Core RPC client: enabled when ANNOTATION_AGENT_RPC_HOSTS is set.
    // Partial/malformed config fails fast at startup.
    let rpc_client = match env::var("ANNOTATION_AGENT_RPC_HOSTS") {
        Ok(hosts_json) => {
            let rpc_password = env::var("ANNOTATION_AGENT_RPC_PASSWORD").context(
                "ANNOTATION_AGENT_RPC_PASSWORD must be set when ANNOTATION_AGENT_RPC_HOSTS is set",
            )?;
            anyhow::ensure!(
                !rpc_password.is_empty(),
                "ANNOTATION_AGENT_RPC_PASSWORD must not be empty"
            );
            let rpc_user = env::var("ANNOTATION_AGENT_RPC_USER")
                .unwrap_or_else(|_| "rpc-extractor".to_string());
            anyhow::ensure!(
                !rpc_user.is_empty(),
                "ANNOTATION_AGENT_RPC_USER must not be empty"
            );
            let rpc_port: u16 = match env::var("ANNOTATION_AGENT_RPC_PORT") {
                Ok(v) => {
                    let p: u16 = v.parse().with_context(|| {
                        format!("ANNOTATION_AGENT_RPC_PORT '{v}' is not a valid port number")
                    })?;
                    anyhow::ensure!(p != 0, "ANNOTATION_AGENT_RPC_PORT must not be 0");
                    p
                }
                Err(_) => 9000,
            };
            let client = rpc::RpcClient::new(&hosts_json, rpc_user, rpc_password, rpc_port)
                .context("invalid RPC configuration")?;
            info!("RPC prefetch enabled");
            Some(client)
        }
        Err(_) => {
            info!("RPC prefetch disabled (ANNOTATION_AGENT_RPC_HOSTS not set)");
            None
        }
    };

    let state = Arc::new(AppState {
        grafana_url: env::var("ANNOTATION_AGENT_GRAFANA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:9321".to_string()),
        grafana_api_key: {
            let key = env::var("ANNOTATION_AGENT_GRAFANA_API_KEY")
                .context("ANNOTATION_AGENT_GRAFANA_API_KEY must be set")?;
            anyhow::ensure!(
                !key.is_empty(),
                "ANNOTATION_AGENT_GRAFANA_API_KEY must not be empty"
            );
            key
        },
        claude_bin: env::var("ANNOTATION_AGENT_CLAUDE_BIN")
            .unwrap_or_else(|_| "claude".to_string()),
        claude_model: env::var("ANNOTATION_AGENT_CLAUDE_MODEL")
            .unwrap_or_else(|_| "claude-sonnet-4-6".to_string()),
        mcp_config: {
            let path = env::var("ANNOTATION_AGENT_MCP_CONFIG")
                .context("ANNOTATION_AGENT_MCP_CONFIG must be set")?;
            anyhow::ensure!(
                std::path::Path::new(&path).exists(),
                "ANNOTATION_AGENT_MCP_CONFIG path does not exist: {path}"
            );
            path
        },
        log_file: env::var("ANNOTATION_AGENT_LOG_FILE").ok(),
        claude_timeout: Duration::from_secs(claude_timeout_secs),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(http_timeout_secs))
            .build()
            .context("failed to build HTTP client")?,
        rpc_client,
        investigation_semaphore: Semaphore::new(max_concurrent),
        cooldown: Duration::from_secs(cooldown_secs),
        cooldown_map: std::sync::Mutex::new(HashMap::new()),
    });

    if state.cooldown.is_zero() {
        info!("cooldown suppression disabled");
    } else {
        info!(
            cooldown_secs = state.cooldown.as_secs(),
            "cooldown suppression enabled"
        );
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/webhook", post(handle_webhook))
        .with_state(state);

    info!("annotation-agent listening on {listen_addr}");
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AlertmanagerPayload>,
) -> StatusCode {
    let firing: Vec<Alert> = payload
        .alerts
        .into_iter()
        .filter(|a| a.status == "firing")
        .collect();
    info!("received webhook with {} firing alerts", firing.len());

    // Process all firing alerts concurrently (but not detached — we await
    // them so failures propagate back as HTTP 500, preserving Alertmanager's
    // retry semantics).
    let mut tasks = JoinSet::new();
    for alert in firing {
        let state = Arc::clone(&state);
        tasks.spawn(async move {
            let aid = AlertId::from_alert(&alert);
            if let Err(e) = process_alert(&state, &alert, &aid).await {
                error!(alert_id = %aid, "failed to process alert: {e:#}");
                return Err(());
            }
            Ok(())
        });
    }

    let mut had_failure = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Err(())) | Err(_) => had_failure = true,
            Ok(Ok(())) => {}
        }
    }

    if had_failure {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

async fn process_alert(state: &AppState, alert: &Alert, aid: &AlertId) -> Result<()> {
    // Cooldown suppression: coalesce retriggers of the same (alertname, host)
    // within the cooldown window. Checked before the semaphore to avoid holding
    // a concurrency slot for suppressed alerts.
    let cooldown_guard = if !state.cooldown.is_zero() {
        let key: CooldownKey = (aid.alertname.clone(), aid.host.clone());
        match try_claim_cooldown(key, &state.cooldown_map, state.cooldown) {
            Ok(guard) => Some(guard),
            Err(SuppressReason::InFlight) => {
                info!(alert_id = %aid, "skipping: investigation already in flight");
                return Ok(());
            }
            Err(SuppressReason::RecentlyCompleted { elapsed_secs }) => {
                info!(
                    alert_id = %aid,
                    cooldown_secs = state.cooldown.as_secs(),
                    elapsed_secs,
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
    let raw_explanation = call_claude(state, alert, aid).await?;

    match parse_structured_annotation(&raw_explanation) {
        Ok(ann) => {
            let html = render_annotation_html(&ann);
            let log_text = render_annotation_plaintext(&ann);
            post_grafana_annotation(state, alert, aid, &html, Some(&ann.verdict)).await?;
            append_log(state, alert, &aid.alertname, &log_text).await;
            info!(alert_id = %aid, verdict = %ann.verdict, "annotation posted successfully");
        }
        Err(e) => {
            warn!(
                alert_id = %aid,
                error = %e,
                "failed to parse structured annotation, using raw text"
            );
            let escaped = html_escape(&raw_explanation);
            post_grafana_annotation(state, alert, aid, &escaped, None).await?;
            let sanitized = sanitize_log_field(&raw_explanation);
            append_log(state, alert, &aid.alertname, &sanitized).await;
            info!(alert_id = %aid, "annotation posted successfully (raw fallback)");
        }
    }

    if let Some(guard) = cooldown_guard {
        guard.complete();
    }

    Ok(())
}

async fn append_log(state: &AppState, alert: &Alert, alertname: &str, explanation: &str) {
    let Some(ref path) = state.log_file else {
        return;
    };
    let host = alert
        .labels
        .get("host")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let safe_alertname = sanitize_log_field(alertname);
    let safe_host = sanitize_log_field(&host);
    let line = format_log_line(&alert.starts_at, &safe_alertname, &safe_host, explanation);
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes()).await;
        }
        Err(e) => warn!(path, "failed to write annotation log: {e}"),
    }
}

/// Fetch recent AI annotations from Grafana to provide as context for the investigation.
/// Looks back 1 hour for annotations tagged with `ai-annotation` from the same host.
async fn fetch_recent_annotations(
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
fn format_prior_context(recent: &[GrafanaAnnotationResponse]) -> String {
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

/// Call the Claude Code CLI with Prometheus MCP tools to investigate the alert.
///
/// Claude has access to Prometheus via MCP and can autonomously query metrics,
/// drill into per-peer data, and correlate across hosts to determine root cause.
async fn call_claude(state: &AppState, alert: &Alert, aid: &AlertId) -> Result<String> {
    // Fetch prior annotations and RPC data concurrently — they're independent
    // and can each take up to 30s (Grafana HTTP timeout) / 10s (RPC deadline).
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

    let (recent, (rpc_context, rpc_fetched_at)) =
        tokio::join!(fetch_recent_annotations(state, alert), async {
            match &state.rpc_client {
                Some(rpc) => rpc.prefetch(&host, &alertname, &aid_str).await,
                None => (String::new(), None),
            }
        });
    let prior_context = format_prior_context(&recent);

    let ctx = AlertContext::from_alert(
        &alert.labels,
        &alert.annotations,
        alert.starts_at,
        prior_context,
        rpc_context,
        rpc_fetched_at,
    );

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
                &prompt::build_investigation_prompt(&ctx),
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

    Ok(parsed.result)
}

/// Parsed Claude CLI JSON output with telemetry fields.
#[derive(Debug)]
struct ClaudeOutput {
    result: String,
    is_error: bool,
    num_turns: u64,
    duration_ms: u64,
    duration_api_ms: u64,
    cost_usd: f64,
    input_tokens: u64,
    output_tokens: u64,
    stop_reason: String,
    session_id: String,
}

/// Parse Claude CLI JSON output into structured telemetry.
fn parse_claude_output(raw: &str) -> Result<ClaudeOutput> {
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

/// Format a log line for the annotation log file.
fn format_log_line(
    starts_at: &DateTime<Utc>,
    alertname: &str,
    host: &str,
    explanation: &str,
) -> String {
    format!(
        "[{}] {} on {} — {}\n",
        starts_at.format("%Y-%m-%d %H:%M:%S UTC"),
        alertname,
        host,
        explanation,
    )
}

async fn post_grafana_annotation(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
    text: &str,
    verdict: Option<&Verdict>,
) -> Result<()> {
    let time_ms = alert.starts_at.timestamp_millis();
    let time_end_ms = compute_annotation_time_end(time_ms, alert.ends_at);

    // Idempotency key: stable 3-tag set. Verdict is NOT part of the key so that
    // a retry where one attempt falls back to raw text and another succeeds with
    // structured output will still match as a duplicate.
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: Semaphore::new(DEFAULT_MAX_CONCURRENT),
            cooldown: Duration::ZERO,
            cooldown_map: std::sync::Mutex::new(HashMap::new()),
        })
    }

    // ── Alertmanager payload deserialization ────────────────────────────

    fn sample_webhook_json() -> &'static str {
        r#"{
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "PeerObserverInboundConnectionDrop", "host": "bitcoin-03", "severity": "warning", "category": "connections"},
                    "annotations": {"description": "Inbound connections dropped below lower band", "dashboard": "https://grafana.example.com/d/abc"},
                    "startsAt": "2025-06-15T12:00:00Z",
                    "endsAt": "0001-01-01T00:00:00Z"
                },
                {
                    "status": "resolved",
                    "labels": {"alertname": "PeerObserverBlockStale", "host": "bitcoin-04"},
                    "annotations": null,
                    "startsAt": "2025-06-15T11:00:00Z",
                    "endsAt": "2025-06-15T11:30:00Z"
                }
            ]
        }"#
    }

    #[test]
    fn deserialize_alertmanager_payload() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        assert_eq!(payload.alerts.len(), 2);
        assert_eq!(payload.alerts[0].status, "firing");
        assert_eq!(
            payload.alerts[0].labels.get("alertname").unwrap(),
            "PeerObserverInboundConnectionDrop"
        );
        assert_eq!(payload.alerts[1].status, "resolved");
    }

    #[test]
    fn deserialize_alert_with_null_annotations() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        assert!(payload.alerts[1].annotations.is_none());
    }

    #[test]
    fn deserialize_alert_timestamps() {
        let payload: AlertmanagerPayload = serde_json::from_str(sample_webhook_json()).unwrap();
        let firing = &payload.alerts[0];
        assert_eq!(
            firing.starts_at,
            Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap()
        );
        // Sentinel date for still-firing
        let ends = firing.ends_at.unwrap();
        assert!(ends.timestamp() < 0, "sentinel date should be pre-epoch");
    }

    #[test]
    fn deserialize_empty_alerts() {
        let json = r#"{"alerts": []}"#;
        let payload: AlertmanagerPayload = serde_json::from_str(json).unwrap();
        assert!(payload.alerts.is_empty());
    }

    #[test]
    fn deserialize_minimal_alert() {
        let json = r#"{
            "alerts": [{
                "status": "firing",
                "labels": {},
                "startsAt": "2025-01-01T00:00:00Z"
            }]
        }"#;
        let payload: AlertmanagerPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.alerts.len(), 1);
        assert!(payload.alerts[0].annotations.is_none());
        assert!(payload.alerts[0].ends_at.is_none());
    }

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

    // ── Log line formatting ────────────────────────────────────────────

    #[test]
    fn format_log_line_basic() {
        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let line = format_log_line(
            &ts,
            "PeerObserverBlockStale",
            "bitcoin-03",
            "No new block in 1 hour",
        );
        assert_eq!(
            line,
            "[2025-06-15 12:00:00 UTC] PeerObserverBlockStale on bitcoin-03 — No new block in 1 hour\n"
        );
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

    // ── Webhook handler (integration test with axum) ───────────────────

    #[tokio::test]
    async fn webhook_returns_ok_for_resolved_only() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        // Only resolved alerts — should return 200 with no processing
        let body = r#"{"alerts": [{"status": "resolved", "labels": {}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn webhook_returns_error_when_processing_fails() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        // A firing alert that will fail (claude_bin is "echo", Grafana is unreachable)
        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "firing alert with unreachable backends should return 500"
        );
    }

    #[tokio::test]
    async fn webhook_rejects_invalid_payload() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Build a test state with cooldown enabled and a pre-populated cooldown map.
    fn test_state_with_cooldown(key: CooldownKey, entry: CooldownState) -> Arc<AppState> {
        let mut map = HashMap::new();
        map.insert(key, entry);
        Arc::new(AppState {
            grafana_url: "http://localhost:3000".into(),
            grafana_api_key: "test-key".into(),
            claude_bin: "echo".into(),
            claude_model: "claude-sonnet-4-6".into(),
            mcp_config: "/dev/null".into(),
            log_file: None,
            claude_timeout: Duration::from_secs(DEFAULT_CLAUDE_TIMEOUT_SECS),
            http: reqwest::Client::new(),
            rpc_client: None,
            investigation_semaphore: Semaphore::new(DEFAULT_MAX_CONCURRENT),
            cooldown: Duration::from_secs(1800),
            cooldown_map: std::sync::Mutex::new(map),
        })
    }

    #[tokio::test]
    async fn webhook_suppresses_recently_completed_alert() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Pre-populate: TestAlert on "unknown" host was just investigated.
        let state = test_state_with_cooldown(
            ("TestAlert".into(), "unknown".into()),
            CooldownState::Completed(Instant::now()),
        );
        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(state);

        // Same alert fires again — without cooldown this would return 500
        // (unreachable Claude/Grafana), but cooldown suppresses it → 200.
        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "recently-completed alert should be suppressed and return 200"
        );
    }

    #[tokio::test]
    async fn webhook_suppresses_inflight_alert() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Pre-populate: TestAlert on "unknown" host is currently being investigated.
        let state = test_state_with_cooldown(
            ("TestAlert".into(), "unknown".into()),
            CooldownState::InFlight,
        );
        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .with_state(state);

        let body = r#"{"alerts": [{"status": "firing", "labels": {"alertname": "TestAlert"}, "startsAt": "2025-01-01T00:00:00Z"}]}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/webhook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "in-flight alert should be suppressed and return 200"
        );
    }

    // ── Health endpoint ────────────────────────────────────────────────

    #[tokio::test]
    async fn healthz_returns_ok() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/webhook", post(handle_webhook))
            .with_state(test_state());

        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── AlertId correlation ────────────────────────────────────────────

    #[test]
    fn alert_id_display_format() {
        let alert = Alert {
            status: "firing".into(),
            labels: {
                let mut m = HashMap::new();
                m.insert("alertname".into(), "TestAlert".into());
                m.insert("host".into(), "bitcoin-03".into());
                m
            },
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert_eq!(aid.to_string(), "TestAlert:bitcoin-03:20250615T120000Z");
    }

    #[test]
    fn alert_id_missing_labels() {
        let alert = Alert {
            status: "firing".into(),
            labels: HashMap::new(),
            annotations: None,
            starts_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            ends_at: None,
        };
        let aid = AlertId::from_alert(&alert);
        assert_eq!(aid.to_string(), ":unknown:20250101T000000Z");
    }

    // ── Tag building (idempotency split) ──────────────────────────────

    fn test_aid() -> AlertId {
        AlertId {
            alertname: "TestAlert".into(),
            host: "bitcoin-03".into(),
            started: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
        }
    }

    #[test]
    fn idempotency_tags_are_stable_three_element() {
        let tags = build_idempotency_tags(&test_aid());
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0], "ai-annotation");
        assert_eq!(tags[1], "TestAlert");
        assert_eq!(tags[2], "bitcoin-03");
    }

    #[test]
    fn annotation_tags_include_verdict() {
        let tags = build_annotation_tags(&test_aid(), Some(&Verdict::Benign));
        assert_eq!(tags.len(), 4);
        assert_eq!(tags[3], "benign");

        let tags = build_annotation_tags(&test_aid(), Some(&Verdict::ActionRequired));
        assert_eq!(tags[3], "action_required");
    }

    #[test]
    fn annotation_tags_without_verdict_match_idempotency() {
        let key = build_idempotency_tags(&test_aid());
        let posted = build_annotation_tags(&test_aid(), None);
        assert_eq!(key, posted);
    }

    #[test]
    fn annotation_tags_superset_of_idempotency_tags() {
        let key = build_idempotency_tags(&test_aid());
        let posted = build_annotation_tags(&test_aid(), Some(&Verdict::Investigate));
        // First 3 elements must match
        assert_eq!(&posted[..3], &key[..]);
        assert_eq!(posted.len(), key.len() + 1);
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

    // ── Cooldown suppression ──────────────────────────────────────────

    #[test]
    fn default_cooldown_is_30_minutes() {
        assert_eq!(DEFAULT_COOLDOWN_SECS, 1800);
    }

    #[test]
    fn try_claim_succeeds_on_empty_map() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        let guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30));
        assert!(guard.is_ok());
        let locked = map.lock().unwrap();
        assert!(matches!(locked.get(&key), Some(CooldownState::InFlight)));
    }

    #[test]
    fn try_claim_suppresses_inflight() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
        let result = try_claim_cooldown(key, &map, Duration::from_secs(30));
        assert!(matches!(result, Err(SuppressReason::InFlight)));
    }

    #[test]
    fn try_claim_suppresses_completed_within_window() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(Instant::now()));
        let result = try_claim_cooldown(key, &map, Duration::from_secs(30));
        assert!(matches!(
            result,
            Err(SuppressReason::RecentlyCompleted { .. })
        ));
    }

    #[test]
    fn try_claim_allows_completed_beyond_window() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        let past = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(past));
        let result = try_claim_cooldown(key, &map, Duration::from_secs(1));
        assert!(result.is_ok());
    }

    #[test]
    fn try_claim_allows_different_key() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key_a = ("AlertA".to_string(), "host1".to_string());
        let key_b = ("AlertB".to_string(), "host1".to_string());
        let _guard_a = try_claim_cooldown(key_a, &map, Duration::from_secs(30)).unwrap();
        let result = try_claim_cooldown(key_b, &map, Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn guard_complete_transitions_to_completed() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        let guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
        guard.complete();
        let locked = map.lock().unwrap();
        assert!(matches!(
            locked.get(&key),
            Some(CooldownState::Completed(_))
        ));
    }

    #[test]
    fn guard_drop_without_complete_clears_entry() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        {
            let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
            // guard drops here without complete()
        }
        let locked = map.lock().unwrap();
        assert!(locked.get(&key).is_none());
    }

    #[test]
    fn guard_panic_safety() {
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = try_claim_cooldown(key.clone(), &map, Duration::from_secs(30)).unwrap();
            panic!("simulated failure");
        }));
        assert!(result.is_err());
        let locked = map.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            locked.get(&key).is_none(),
            "entry should be cleared after panic"
        );
    }

    #[test]
    fn cooldown_zero_does_not_suppress() {
        // Duration::ZERO passed to try_claim_cooldown means the Completed window
        // is always expired, so even a just-completed entry won't suppress.
        let map: CooldownMap = std::sync::Mutex::new(HashMap::new());
        let key = ("AlertA".to_string(), "host1".to_string());
        map.lock()
            .unwrap()
            .insert(key.clone(), CooldownState::Completed(Instant::now()));

        // With zero cooldown, the Completed(now) entry should NOT suppress because
        // elapsed (≥0) is never < Duration::ZERO.
        let result = try_claim_cooldown(key, &map, Duration::ZERO);
        assert!(
            result.is_ok(),
            "zero cooldown should not suppress even a just-completed entry"
        );
    }
}
