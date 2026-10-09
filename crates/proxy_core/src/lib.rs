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
//! This crate contains the listener, the protocol sniffer, the split-router
//! classifier, and the SOCKS5 / HTTP handlers. Clear-web targets are relayed
//! to the public Internet; Turnet targets are refused with the protocol's own
//! error until the P2P pipeline ([`dht_resolver`] + relay) is wired, so a
//! reserved-namespace name is never sent to a public DNS resolver.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};

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
    /// The client spoke a protocol version this proxy does not implement.
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    /// A SOCKS command other than CONNECT (e.g. BIND, UDP ASSOCIATE).
    #[error("unsupported command")]
    UnsupportedCommand,
    /// A SOCKS address type this proxy does not handle.
    #[error("unsupported address type")]
    UnsupportedAddressType,
    /// The target routes to the Turnet pipeline, which is not wired yet. The
    /// name is deliberately not resolved via public DNS.
    #[error("turnet pipeline not available yet")]
    TurnetPipelineUnavailable,
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

    /// Bind the listener and accept connections until the task is dropped.
    ///
    /// Each connection is sniffed (SOCKS5 greeting vs. HTTP verb) and handed to
    /// the matching handler on its own task. A per-connection error is logged
    /// and does not bring the listener down.
    pub async fn serve(&self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.config.bind).await?;
        tracing::info!(bind = %self.config.bind, "proxy_core: listening");
        loop {
            let (stream, peer) = listener.accept().await?;
            tokio::spawn(async move {
                if let Err(e) = dispatch(stream).await {
                    tracing::warn!(?peer, error = %e, "proxy_core: connection ended with error");
                }
            });
        }
    }
}

/// Which front-end protocol a connection is speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// A SOCKS5 greeting (first byte `0x05`).
    Socks5,
    /// Anything else is treated as HTTP (a printable request-line verb).
    Http,
}

/// Decide the protocol from the first byte of the connection. SOCKS5 always
/// opens with version `0x05`; every HTTP method starts with an uppercase ASCII
/// letter, so the two never collide.
pub fn sniff(first_byte: u8) -> Protocol {
    if first_byte == 0x05 {
        Protocol::Socks5
    } else {
        Protocol::Http
    }
}

/// Peek the first byte of `stream` and route it to the right handler.
async fn dispatch(stream: TcpStream) -> Result<(), ProxyError> {
    let mut first = [0u8; 1];
    let n = stream.peek(&mut first).await?;
    if n == 0 {
        return Err(ProxyError::Malformed);
    }
    match sniff(first[0]) {
        Protocol::Socks5 => socks5::handle_connection(stream).await,
        Protocol::Http => http::handle_connection(stream).await,
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

    #[test]
    fn sniff_distinguishes_socks5_from_http() {
        assert_eq!(sniff(0x05), Protocol::Socks5);
        assert_eq!(sniff(b'G'), Protocol::Http); // GET
        assert_eq!(sniff(b'C'), Protocol::Http); // CONNECT
    }
}
