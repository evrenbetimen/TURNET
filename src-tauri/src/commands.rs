//! Type-safe `#[tauri::command]` invoke handlers.
//!
//! Every command takes and returns `serde`-typed values so the TypeScript
//! `invoke` wrapper in the frontend stays type-safe end to end. Commands are
//! thin: they read/update [`crate::state::AppState`] and call into the core
//! crates. Heavy work belongs on background tasks, never inline here, so the
//! UI event loop is never blocked.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;
use compliance_reporting::exporter::{self, SigningKey};
use compliance_reporting::store::AuditStore;
use proxy_core::{classify_host, Route};

/// Proxy status surfaced to the UI status panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatusDto {
    pub running: bool,
    pub bind: String,
    pub block_public_dns_for_turnet: bool,
}

/// Result of a routing classification (demonstrates the split router).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDto {
    pub host: String,
    pub route: String,
}

/// Summary of a generated compliance export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSummaryDto {
    pub format: String,
    pub record_count: u64,
    pub signature_prefix: String,
    pub note: String,
}

/// Read the current proxy status.
#[tauri::command]
pub fn get_proxy_status(state: State<'_, AppState>) -> ProxyStatusDto {
    let running = *state.proxy_running.lock().expect("proxy_running lock");
    ProxyStatusDto {
        running,
        bind: state.proxy_config.bind.to_string(),
        block_public_dns_for_turnet: state.proxy_config.block_public_dns_for_turnet,
    }
}

/// Start/stop the local proxy front end (scaffold: flips state only).
#[tauri::command]
pub fn set_proxy_running(
    running: bool,
    state: State<'_, AppState>,
) -> Result<ProxyStatusDto, String> {
    *state.proxy_running.lock().map_err(|e| e.to_string())? = running;
    Ok(get_proxy_status(state))
}

/// Classify a destination host via the split router. Lets the UI preview
/// whether a name routes to the clear web or into Turnet.
#[tauri::command]
pub fn classify_domain(host: String) -> RouteDto {
    let route = match classify_host(&host) {
        Route::ClearWeb => "clear-web",
        Route::Turnet => "turnet",
    };
    RouteDto { host, route: route.to_string() }
}

/// Read a node's current credit balance.
#[tauri::command]
pub fn get_credit_balance(node_id: u64, state: State<'_, AppState>) -> u64 {
    let ledger = state.ledger.lock().expect("ledger lock");
    ledger.balance(dht_resolver::NodeId(node_id))
}

/// Generate a signed compliance export from this node's local audit store.
///
/// Scaffold: builds an in-memory store so the export path is exercised
/// end-to-end. In a real build the store is the operator's on-disk WAL
/// database. The export is operator-local and signed for integrity.
#[tauri::command]
pub fn export_compliance_report(format: String) -> Result<ExportSummaryDto, String> {
    let fmt = match format.as_str() {
        "json" => exporter::Format::Json,
        "csv" => exporter::Format::Csv,
        other => return Err(format!("unknown format: {other}")),
    };

    // Operator-local store. Empty in the scaffold (no records captured).
    let store = AuditStore::open_in_memory().map_err(|e| e.to_string())?;
    let records = store.all().map_err(|e| e.to_string())?;

    // A real build loads the operator's signing key from secure storage.
    let key = SigningKey::from_bytes(&[0u8; 32]);
    let signed = exporter::export_signed(&records, fmt, &key).map_err(|e| e.to_string())?;

    Ok(ExportSummaryDto {
        format: signed.format.to_string(),
        record_count: records.len() as u64,
        signature_prefix: signed.signature_hex.chars().take(16).collect(),
        note: "Operator-local audit export, produced on this node under the \
               operator's own authority. Not a network-wide collection."
            .to_string(),
    })
}
