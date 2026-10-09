//! # p2p_engine — relay transport, UDP handshake, and session telemetry
//!
//! This crate owns the node-to-node relay transport: the UDP handshake that
//! establishes an encrypted session (keys from [`quantum_crypto`]), peer
//! discovery (over [`dht_resolver`]), and the telemetry that feeds the local
//! operator dashboard and the operator's audit log.
//!
//! ## Modules
//! - [`handshake`] — UDP session establishment and the hybrid key exchange.
//! - [`telemetry`] — live per-session metrics for the operator UI.
//! - [`audit_hook`] — **consent-gated** hook that records a connection into
//!   the operator's local audit log ([`compliance_reporting`]).
//!
//! ## On the connection-record hook
//! A relay operator may be legally required to keep records of the
//! connections *their own node* handled. The [`audit_hook`] exists for that
//! purpose and is governed by [`audit_hook::AuditPolicy`], which is
//! **off by default**. When enabled by the operator, it records only what
//! that one node observed, into that node's local store. It is deliberately
//! *not* a network-wide tap: there is no mechanism here to collect or
//! centralize other nodes' connection data, and users on the network can be
//! informed that an entry relay they choose keeps such logs. See the
//! [`compliance_reporting`] crate docs for the full design rationale.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use thiserror::Error;

pub mod audit_hook;
pub mod handshake;
pub mod telemetry;

/// Errors from the relay engine.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("handshake rejected")]
    HandshakeRejected,
    /// A handshake message had the wrong length or shape.
    #[error("malformed handshake message")]
    MalformedHandshake,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// UDP address the relay listens on.
    pub listen: SocketAddr,
    /// Audit-log policy for this node (off by default).
    pub audit: audit_hook::AuditPolicy,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:0".parse().expect("valid default listen addr"),
            audit: audit_hook::AuditPolicy::default(),
        }
    }
}

/// The relay engine: owns the UDP listener and session table.
pub struct RelayEngine {
    config: EngineConfig,
}

impl RelayEngine {
    /// Build an engine from config.
    pub fn new(config: EngineConfig) -> Self {
        Self { config }
    }

    /// Borrow the config.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Bind the UDP socket and run the relay loop.
    ///
    /// Stub: accept loop, handshake dispatch, and session multiplexing are a
    /// later milestone.
    pub async fn run(&self) -> Result<(), EngineError> {
        tracing::info!(listen = %self.config.listen, "p2p_engine: run() not yet implemented");
        Err(EngineError::NotImplemented("relay run loop"))
    }
}
