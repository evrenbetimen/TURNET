//! Shared application state managed by Tauri and borrowed by commands.

use std::path::PathBuf;
use std::sync::Mutex;

use compliance_reporting::exporter::{generate_signing_key, SigningKey};
use compliance_reporting::honeypot::Honeypot;
use compliance_reporting::node_control::LocalNodeControl;
use incentive_ledger::Ledger;
use p2p_engine::audit_hook::AuditPolicy;
use proxy_core::ProxyConfig;

/// Process-wide state. Commands access it via `tauri::State`.
pub struct AppState {
    /// Whether the local proxy front end is (nominally) running.
    pub proxy_running: Mutex<bool>,
    /// The proxy configuration shown in the UI.
    pub proxy_config: ProxyConfig,
    /// The credit ledger (scaffold: in-memory).
    pub ledger: Mutex<Ledger>,
    /// Local node run-state control (this node only).
    pub node_control: Mutex<LocalNodeControl>,
    /// Operator audit-logging policy (off by default, disclosure-gated).
    pub audit_policy: Mutex<AuditPolicy>,
    /// Defensive honeypot sensor for this node.
    pub honeypot: Mutex<Honeypot>,
    /// Operator signing key for compliance exports (generated at startup;
    /// a real deployment loads a persisted key from secure storage).
    pub signing_key: SigningKey,
    /// Directory the audit store and exports live in.
    pub data_dir: PathBuf,
}

impl Default for AppState {
    fn default() -> Self {
        let data_dir = std::env::temp_dir().join("turnet");
        Self {
            proxy_running: Mutex::new(false),
            proxy_config: ProxyConfig::default(),
            ledger: Mutex::new(Ledger::new()),
            node_control: Mutex::new(LocalNodeControl::default()),
            audit_policy: Mutex::new(AuditPolicy::default()),
            honeypot: Mutex::new(Honeypot::new(5)),
            signing_key: generate_signing_key(),
            data_dir,
        }
    }
}
