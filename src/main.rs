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

    let config = config::load()?;
    server::run(config).await
}
