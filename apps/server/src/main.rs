mod app;
mod config;
mod error;
mod models;

use std::process::ExitCode;

use crate::{app::build_router, config::Config, error::AppError};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error!(%error, "server stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), AppError> {
    dotenvy::dotenv().ok();

    let config = Config::from_env()?;
    let address = config.socket_address();
    let listener = TcpListener::bind(address).await?;

    info!(%address, "66MSG server is listening");

    axum::serve(
        listener,
        build_router(&config)?.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("msg_server=info,tower_http=info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        error!(%error, "failed to listen for shutdown signal");
    }
}
