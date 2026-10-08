//! HTTP proxy front end, including the `CONNECT` tunnel. **Stub.**
//!
//! Parses the request line / `Host` header, classifies the target with
//! [`crate::classify_host`], and either forwards to the clear web or diverts
//! into the Turnet pipeline.

use crate::ProxyError;
use tokio::net::TcpStream;

/// Serve one HTTP proxy connection.
///
/// Stub: returns [`ProxyError::NotImplemented`] until request parsing and the
/// CONNECT tunnel are implemented on top of `hyper`.
pub async fn handle_connection(_stream: TcpStream) -> Result<(), ProxyError> {
    Err(ProxyError::NotImplemented("http proxy handler"))
}
