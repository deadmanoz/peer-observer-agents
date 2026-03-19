use crate::cooldown::CooldownMap;
use crate::parca;
use crate::profiles::ProfileDb;
use crate::rpc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub(crate) struct AppState {
    pub(crate) grafana_url: String,
    pub(crate) grafana_api_key: String,
    pub(crate) claude_bin: String,
    pub(crate) claude_model: String,
    pub(crate) mcp_config: String,
    pub(crate) log_file: Option<String>,
    pub(crate) claude_timeout: Duration,
    pub(crate) http: reqwest::Client,
    /// Optional Bitcoin Core RPC client for pre-fetching node data.
    /// `None` when `ANNOTATION_AGENT_RPC_HOSTS` is not set (feature disabled).
    pub(crate) rpc_client: Option<rpc::RpcClient>,
    /// Optional Parca profiling client for pre-fetching CPU profile data.
    /// `None` when `ANNOTATION_AGENT_PARCA_HOSTS` is not set (feature disabled).
    pub(crate) parca_client: Option<parca::ParcaClient>,
    /// Limits the number of concurrent Claude investigations to prevent
    /// resource exhaustion when Alertmanager delivers large grouped batches.
    pub(crate) investigation_semaphore: Semaphore,
    /// Cooldown window for suppressing retriggers of the same `(alertname, host, threadname)`.
    /// `Duration::ZERO` disables suppression.
    pub(crate) cooldown: Duration,
    /// In-process state for cooldown suppression.
    pub(crate) cooldown_map: CooldownMap,
    /// Bearer token for viewer endpoints (`/logs`, `/api/logs`, `/peers`, `/api/peers/*`).
    /// When `None`, viewer routes return 404.
    pub(crate) viewer_auth_token: Option<String>,
    /// Serializes JSONL log writes to prevent interleaved bytes from
    /// concurrent investigations.
    pub(crate) log_write_mutex: tokio::sync::Mutex<()>,
    /// Optional SQLite peer profiles database.
    /// `None` when `ANNOTATION_AGENT_PROFILES_DB` is not set.
    pub(crate) profile_db: Option<Arc<ProfileDb>>,
    /// Poll interval for peer profiles (default 300s).
    pub(crate) profiles_poll_interval: Duration,
    /// Retention for observations in days (default 90).
    pub(crate) profiles_retention_days: u64,
}
