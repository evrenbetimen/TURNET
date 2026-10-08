//! SOCKS5 server state machine (RFC 1928). **Stub.**
//!
//! Handles the greeting/auth negotiation and the CONNECT request, then hands
//! the resolved target host to [`crate::classify_host`] to pick a route.

use crate::ProxyError;
use tokio::net::TcpStream;

/// Drive one SOCKS5 client connection through negotiation and connect.
///
/// Stub: returns [`ProxyError::NotImplemented`] until the state machine is
/// built.
pub async fn handle_connection(_stream: TcpStream) -> Result<(), ProxyError> {
    Err(ProxyError::NotImplemented("socks5 state machine"))
}
