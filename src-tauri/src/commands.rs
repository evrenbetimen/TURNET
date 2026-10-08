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
use compliance_reporting::node_control::NodeState;
use compliance_reporting::store::AuditStore;
use p2p_engine::audit_hook::AuditPolicy;
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
    pub verified: bool,
    pub output_path: String,
    pub note: String,
}

/// Audit-policy view for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicyDto {
    pub recording: bool,
    pub disclosure: Option<String>,
}

/// Node run-state for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStateDto {
    pub state: String,
}

fn node_state_str(s: NodeState) -> String {
    match s {
        NodeState::Running => "running",
        NodeState::Paused => "paused",
        NodeState::Stopped => "stopped",
    }
    .to_string()
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

/// Classify a destination host via the split router.
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

// --- node control (local, this node only) ---

/// Read the local node's run state.
#[tauri::command]
pub fn get_node_state(state: State<'_, AppState>) -> NodeStateDto {
    let nc = state.node_control.lock().expect("node_control lock");
    NodeStateDto { state: node_state_str(nc.state()) }
}

/// Pause / resume / stop the local node. `action` is one of
/// `"pause" | "resume" | "stop"`.
#[tauri::command]
pub fn set_node_state(action: String, state: State<'_, AppState>) -> Result<NodeStateDto, String> {
    let mut nc = state.node_control.lock().map_err(|e| e.to_string())?;
    let new = match action.as_str() {
        "pause" => nc.pause(),
        "resume" => nc.resume(),
        "stop" => nc.stop(),
        other => return Err(format!("unknown action: {other}")),
    }
    .map_err(|e| e.to_string())?;
    Ok(NodeStateDto { state: node_state_str(new) })
}

// --- audit policy (operator-local, disclosure-gated) ---

/// Read the current audit-logging policy.
#[tauri::command]
pub fn get_audit_policy(state: State<'_, AppState>) -> AuditPolicyDto {
    let p = state.audit_policy.lock().expect("audit_policy lock");
    AuditPolicyDto {
        recording: p.is_recording(),
        disclosure: p.operator_disclosure.clone(),
    }
}

/// Enable or disable operator audit logging. Enabling **requires** a non-empty
/// disclosure string — there is no way to turn on silent logging.
#[tauri::command]
pub fn set_audit_policy(
    enabled: bool,
    disclosure: Option<String>,
    state: State<'_, AppState>,
) -> Result<AuditPolicyDto, String> {
    let mut p = state.audit_policy.lock().map_err(|e| e.to_string())?;
    if enabled {
        match disclosure {
            Some(d) if !d.trim().is_empty() => *p = AuditPolicy::enabled(d),
            _ => return Err("enabling audit logging requires a disclosure statement".into()),
        }
    } else {
        *p = AuditPolicy::default();
    }
    Ok(AuditPolicyDto {
        recording: p.is_recording(),
        disclosure: p.operator_disclosure.clone(),
    })
}

/// Current honeypot flags (defensive: probes against this node).
#[tauri::command]
pub fn get_honeypot_flags(state: State<'_, AppState>) -> u64 {
    let h = state.honeypot.lock().expect("honeypot lock");
    h.flags().len() as u64
}

/// Generate a signed compliance export from this node's local audit store and
/// write it to the data directory. Returns a summary including the output path
/// and whether the signature re-verifies.
///
/// Operator-local: the store holds only what this node observed, and logging
/// is off unless the operator explicitly enabled it with a disclosure.
#[tauri::command]
pub fn export_compliance_report(
    format: String,
    state: State<'_, AppState>,
) -> Result<ExportSummaryDto, String> {
    let fmt = match format.as_str() {
        "json" => exporter::Format::Json,
        "csv" => exporter::Format::Csv,
        other => return Err(format!("unknown format: {other}")),
    };

    let store_path = state.data_dir.join("audit.sqlite3");
    let store = AuditStore::open(&store_path).map_err(|e| e.to_string())?;
    let records = store.all().map_err(|e| e.to_string())?;

    let key: &SigningKey = &state.signing_key;
    let signed = exporter::export_signed(&records, fmt, key).map_err(|e| e.to_string())?;
    let verified = exporter::verify(&signed, &key.verifying_key());

    let out_dir = state.data_dir.join("exports");
    let path = exporter::write_to_dir(&signed, &out_dir, "turnet-compliance")
        .map_err(|e| e.to_string())?;

    Ok(ExportSummaryDto {
        format: signed.format.to_string(),
        record_count: records.len() as u64,
        signature_prefix: signed.signature_hex.chars().take(16).collect(),
        verified,
        output_path: path.display().to_string(),
        note: "Operator-local audit export, produced on this node under the \
               operator's own authority. Not a network-wide collection."
            .to_string(),
    })
}
