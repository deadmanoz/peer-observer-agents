mod alerts;
mod annotation;
mod config;
mod context;
mod cooldown;
mod correlation;
mod debug_logs;
mod grafana;
mod investigation;
mod parca;
mod processor;
mod profiles;
mod prompt;
mod rpc;
mod sanitization;
mod server;
mod state;
mod sweep;
mod types;
mod viewer;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "peer_observer_agent=info".into()),
        )
        .init();

    // Binary modes: the default is the HTTP service; `sweep` runs the
    // deterministic interestingness sweep once and exits, so it can be driven
    // from cron/systemd-timer without the service running.
    match std::env::args().nth(1).as_deref() {
        Some("sweep") => run_sweep().await,
        Some(other) => {
            anyhow::bail!("unknown mode {other:?}; expected `sweep` or no argument")
        }
        None => {
            let config = config::load()?;
            server::run(config).await
        }
    }
}

/// Run one sweep and print the digest.
///
/// Output format is chosen by `ANNOTATION_AGENT_SWEEP_FORMAT` (`markdown`, the
/// default, or `json`).
async fn run_sweep() -> Result<()> {
    let config = sweep::SweepConfig::from_env()?;
    let report = sweep::run(&config).await?;
    let format =
        std::env::var("ANNOTATION_AGENT_SWEEP_FORMAT").unwrap_or_else(|_| "markdown".into());
    let rendered = match format.as_str() {
        "json" => sweep::digest::to_json(&report)?,
        _ => sweep::digest::to_markdown(&report),
    };
    println!("{rendered}");
    Ok(())
}
