//! Internal command handling for secure-llm.
//!
//! This module handles lightweight subcommands like the internal shim and TUI.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::sync::watch;
use tracing::error;

use crate::cli::Commands;
use crate::control::ControlSocketClient;
use crate::shim;
use crate::tui::{TuiApp, TuiRunner};

/// Handle subcommands (internal shim, internal TUI, etc.).
pub fn handle_command(command: Commands) -> Result<()> {
    match command {
        Commands::InternalShim { socket_path } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime")?;

            rt.block_on(async {
                shim::run(&socket_path)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            })
        }
        Commands::InternalTui { socket_path } => run_tui_subprocess(&socket_path),
        Commands::InternalReverseShim {
            bridge_dir,
            max_slots,
        } => run_reverse_shim(&bridge_dir, max_slots),
    }
}

/// Run the reverse shim daemon inside the sandbox.
fn run_reverse_shim(bridge_dir: &Path, max_slots: u8) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    rt.block_on(async {
        shim::run_reverse(bridge_dir, max_slots)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    })
}

/// Run the TUI as a subprocess.
fn run_tui_subprocess(socket_path: &PathBuf) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    rt.block_on(async {
        let client = ControlSocketClient::connect(socket_path)
            .await
            .context("Failed to connect to control socket")?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut app = TuiApp::new_with_socket(client, shutdown_rx);

        match TuiRunner::new() {
            Ok(mut runner) => {
                if let Err(e) = runner.run(&mut app).await {
                    error!("TUI error: {}", e);
                    return Err(anyhow::anyhow!("TUI error: {}", e));
                }
            }
            Err(e) => {
                error!("Failed to initialize TUI: {}", e);
                return Err(anyhow::anyhow!("Failed to initialize TUI: {}", e));
            }
        }

        let _ = shutdown_tx.send(true);
        Ok(())
    })
}
