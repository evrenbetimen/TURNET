//! Shared application state managed by Tauri and borrowed by commands.

use std::sync::Mutex;

use incentive_ledger::Ledger;
use proxy_core::ProxyConfig;

/// Process-wide state. Commands access it via `tauri::State`.
pub struct AppState {
    /// Whether the local proxy front end is (nominally) running.
    pub proxy_running: Mutex<bool>,
    /// The proxy configuration shown in the UI.
    pub proxy_config: ProxyConfig,
    /// The credit ledger (scaffold: in-memory).
    pub ledger: Mutex<Ledger>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            proxy_running: Mutex::new(false),
            proxy_config: ProxyConfig::default(),
            ledger: Mutex::new(Ledger::new()),
        }
    }
}
