//! Live per-session telemetry for the operator dashboard.
//!
//! These are the metrics surfaced to the local UI (upload/download rates,
//! active hops, handshake state). They describe the operator's *own* node
//! and are what the Tauri backend samples for its 60fps event stream.

use serde::{Deserialize, Serialize};

/// A point-in-time snapshot of this node's activity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Current upload throughput, bytes/sec.
    pub up_bps: u64,
    /// Current download throughput, bytes/sec.
    pub down_bps: u64,
    /// Number of active relay sessions.
    pub active_sessions: u32,
    /// Number of hops in the current circuit, if any.
    pub relay_hops: u32,
}

/// Sampler that produces [`TelemetrySnapshot`]s for the UI.
pub struct TelemetrySampler;

impl TelemetrySampler {
    /// Produce the current snapshot.
    ///
    /// Scaffold: returns a zeroed snapshot until the metrics counters are
    /// wired into the relay loop.
    pub fn sample(&self) -> TelemetrySnapshot {
        TelemetrySnapshot::default()
    }
}
