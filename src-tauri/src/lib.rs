//! Turnet Console — Tauri v2 backend.
//!
//! Wires the core daemon crates to a desktop UI. Responsibilities:
//! - register the type-safe [`commands`] invoke handlers;
//! - manage shared [`state::AppState`];
//! - push a throttled (~60fps) telemetry event stream to the frontend without
//!   blocking the core event loop.

pub mod commands;
pub mod state;

use std::time::Duration;

use tauri::Emitter;

use p2p_engine::telemetry::{TelemetrySampler, TelemetrySnapshot};
use state::AppState;

/// Event name the frontend subscribes to for live telemetry.
pub const TELEMETRY_EVENT: &str = "turnet://telemetry";

/// Target frame interval for the telemetry push (~60fps).
const FRAME_INTERVAL: Duration = Duration::from_millis(16);

/// Build and run the Tauri application.
pub fn run() {
    // Best-effort tracing init; ignore if a subscriber is already set.
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_proxy_status,
            commands::set_proxy_running,
            commands::classify_domain,
            commands::get_credit_balance,
            commands::get_node_state,
            commands::set_node_state,
            commands::get_audit_policy,
            commands::set_audit_policy,
            commands::get_honeypot_flags,
            commands::export_compliance_report,
        ])
        .setup(|app| {
            spawn_telemetry_loop(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Turnet Console");
}

/// Spawn the background telemetry emitter.
///
/// Runs on the async runtime, sampling [`TelemetrySampler`] and emitting a
/// [`TelemetrySnapshot`] every [`FRAME_INTERVAL`]. Sampling and emitting are
/// cheap and happen off the UI thread, so the presentation layer never
/// blocks the relay/core work.
fn spawn_telemetry_loop(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let sampler = TelemetrySampler;
        let mut ticker = tokio::time::interval(FRAME_INTERVAL);
        loop {
            ticker.tick().await;
            let snapshot: TelemetrySnapshot = sampler.sample();
            if app.emit(TELEMETRY_EVENT, &snapshot).is_err() {
                // No listeners / app shutting down: stop the loop.
                break;
            }
        }
    });
}
