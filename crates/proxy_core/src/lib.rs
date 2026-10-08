//! # proxy_core — local proxy front end and split router
//!
//! Native applications (browsers, FTP/SSH clients) are pointed at a local
//! SOCKS5 + HTTP proxy on `127.0.0.1:8888`. Every request is classified by
//! its destination and routed down one of two paths:
//!
//! - **Clear-web** (`.com`, `.net`, …) — forwarded straight to the public
//!   Internet so native performance is preserved.
//! - **Turnet** (`.tur`, and internal `.vps` / `.cpt`) — handed to the
//!   decentralized P2P pipeline. These names are resolved via the in-network
//!   DHT ([`dht_resolver`]) and must **not** leak to public DNS resolvers.
//!
//! This crate contains the listener and the classifier. The actual byte
//! pumping, SOCKS5 state machine, and HTTP CONNECT handling are stubbed; the
//! split-router decision logic below is real so the routing contract is
//! testable from day one.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use thiserror::Error;

pub mod http;
pub mod socks5;

/// Default localhost bind address for the universal proxy trap.
pub const DEFAULT_BIND: &str = "127.0.0.1:8888";

/// Errors from the proxy front end.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed request")]
    Malformed,
}

/// Where a classified request should go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Forward to the public Internet unchanged.
    ClearWeb,
    /// Trap and divert into the Turnet P2P pipeline; block public DNS.
    Turnet,
}

/// Internal pseudo-TLDs that belong to the Turnet ecosystem.
pub const TURNET_TLDS: [&str; 3] = ["tur", "vps", "cpt"];

/// Classify a destination host into a [`Route`].
///
/// A trailing-dot FQDN is tolerated. Matching is case-insensitive and looks
/// only at the final label, so `shop.example.tur` routes to Turnet while
/// `tur.example.com` does not.
pub fn classify_host(host: &str) -> Route {
    let host = host.trim_end_matches('.');
    match host.rsplit('.').next() {
        Some(tld) if TURNET_TLDS.iter().any(|t| t.eq_ignore_ascii_case(tld)) => Route::Turnet,
        _ => Route::ClearWeb,
    }
}

/// Configuration for the local proxy front end.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the SOCKS5 + HTTP listener binds to.
    pub bind: SocketAddr,
    /// When true, `.tur`/`.vps`/`.cpt` lookups are kept entirely inside the
    /// DHT and are never sent to a public DNS resolver.
    pub block_public_dns_for_turnet: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.parse().expect("valid default bind"),
            block_public_dns_for_turnet: true,
        }
    }
}

/// The local proxy front end: one listener multiplexing SOCKS5 and HTTP.
pub struct ProxyFrontend {
    config: ProxyConfig,
}

impl ProxyFrontend {
    /// Build a front end from config.
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Borrow the active configuration.
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    /// Bind the listener and serve until shutdown.
    ///
    /// Stub: the accept loop, protocol sniffing (SOCKS5 greeting vs. HTTP
    /// verb), and per-connection routing via [`classify_host`] land in a
    /// later milestone.
    pub async fn serve(&self) -> Result<(), ProxyError> {
        tracing::info!(bind = %self.config.bind, "proxy_core: serve() not yet implemented");
        Err(ProxyError::NotImplemented("proxy accept loop"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_web_routes_direct() {
        assert_eq!(classify_host("example.com"), Route::ClearWeb);
        assert_eq!(classify_host("a.b.net."), Route::ClearWeb);
        assert_eq!(classify_host("tur.example.com"), Route::ClearWeb);
    }

    #[test]
    fn turnet_tlds_are_trapped() {
        assert_eq!(classify_host("myhandle.tur"), Route::Turnet);
        assert_eq!(classify_host("node.VPS"), Route::Turnet);
        assert_eq!(classify_host("shop.example.cpt."), Route::Turnet);
    }

    #[test]
    fn default_blocks_public_dns() {
        assert!(ProxyConfig::default().block_public_dns_for_turnet);
    }
}
