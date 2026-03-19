use crate::context::ContextSection;
use crate::correlation::AlertId;
use crate::grafana::{fetch_recent_annotations, format_prior_context};
use crate::prompt::PreFetchData;
use crate::state::AppState;
use crate::types::Alert;

/// Collects prior Grafana annotations, RPC data, Parca CPU profiles, and
/// debug log lines concurrently.
pub(super) async fn collect_context(
    state: &AppState,
    alert: &Alert,
    aid: &AlertId,
) -> PreFetchData {
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

    let (recent, rpc_section, parca_section, debug_log_section) = tokio::join!(
        fetch_recent_annotations(state, alert),
        async {
            match &state.rpc_client {
                Some(rpc) => rpc.prefetch(&host, &alertname, &aid_str).await,
                None => None,
            }
        },
        async {
            match &state.parca_client {
                Some(parca) => {
                    parca
                        .prefetch(&host, &alertname, &aid_str, alert.starts_at)
                        .await
                }
                None => None,
            }
        },
        async {
            match &state.debug_log_client {
                Some(client) => {
                    client
                        .prefetch(&host, &alertname, &aid_str, alert.starts_at)
                        .await
                }
                None => None,
            }
        }
    );

    let prior_context = format_prior_context(&recent);
    let sections: Vec<ContextSection> = [rpc_section, parca_section, debug_log_section]
        .into_iter()
        .flatten()
        .collect();

    PreFetchData {
        prior_context,
        sections,
    }
}
