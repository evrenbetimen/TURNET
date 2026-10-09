//! HTTP proxy front end: `CONNECT` tunnels and plain forward proxying.
//!
//! The request head is read, the target host extracted (from the `CONNECT`
//! authority, the absolute-form request URI, or the `Host` header), and the
//! target classified by [`crate::classify_host`]:
//!
//! - **Clear-web** `CONNECT` targets are dialed and the sockets spliced; plain
//!   (non-`CONNECT`) requests are forwarded to the origin with the request
//!   line rewritten to origin-form.
//! - **Turnet** targets are refused with `502` and
//!   [`ProxyError::TurnetPipelineUnavailable`] until the P2P pipeline is wired,
//!   so a `.tur` name never reaches a public resolver.

use crate::{classify_host, ProxyError, Route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum header size we buffer before giving up (64 KiB).
const MAX_HEAD: usize = 64 * 1024;

/// A parsed HTTP proxy target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpTarget {
    /// Target host (no port).
    pub host: String,
    /// Target port (defaults: 443 for `CONNECT`, 80 for plain HTTP).
    pub port: u16,
    /// Whether the request was a `CONNECT` tunnel request.
    pub connect: bool,
}

impl HttpTarget {
    /// Which pipeline this target routes to.
    pub fn route(&self) -> Route {
        classify_host(&self.host)
    }
}

/// Split a `host[:port]` authority into its host and optional port, coping with
/// bracketed IPv6 literals (`[::1]:8080`).
fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), ProxyError> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(ProxyError::Malformed);
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [addr] or [addr]:port
        let (addr, tail) = rest.split_once(']').ok_or(ProxyError::Malformed)?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| ProxyError::Malformed)?,
            None => default_port,
        };
        return Ok((addr.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            Ok((h.to_string(), p.parse().map_err(|_| ProxyError::Malformed)?))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

/// Parse the target from an HTTP request head (everything up to the blank
/// line, CRLFs intact).
pub fn parse_target(head: &str) -> Result<HttpTarget, ProxyError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ProxyError::Malformed)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ProxyError::Malformed)?;
    let target = parts.next().ok_or(ProxyError::Malformed)?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(target, 443)?;
        return Ok(HttpTarget {
            host,
            port,
            connect: true,
        });
    }

    // Absolute-form request URI: scheme://authority/path
    if let Some(after) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let authority = after.split('/').next().unwrap_or(after);
        let (host, port) = split_authority(authority, 80)?;
        return Ok(HttpTarget {
            host,
            port,
            connect: false,
        });
    }

    // Origin-form: rely on the Host header.
    for line in lines {
        if let Some(value) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let (host, port) = split_authority(value, 80)?;
            return Ok(HttpTarget {
                host,
                port,
                connect: false,
            });
        }
    }
    Err(ProxyError::Malformed)
}

/// Rewrite an absolute-form request line to origin-form for forwarding to an
/// origin server (`GET http://h/p HTTP/1.1` → `GET /p HTTP/1.1`). Other lines
/// pass through unchanged. A request already in origin-form is returned as-is.
pub fn rewrite_to_origin_form(head: &str) -> String {
    let Some((request_line, rest)) = head.split_once("\r\n") else {
        return head.to_string();
    };
    let mut parts = request_line.splitn(3, ' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return head.to_string();
    };
    let origin = match target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        Some(after) => match after.find('/') {
            Some(slash) => &after[slash..],
            None => "/",
        },
        None => target,
    };
    format!("{method} {origin} {version}\r\n{rest}")
}

/// Read the request head through the blank line (`\r\n\r\n`). Any request body
/// stays buffered on the socket and is relayed by the later splice.
async fn read_head(client: &mut TcpStream) -> Result<String, ProxyError> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Err(ProxyError::Malformed);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD {
            return Err(ProxyError::Malformed);
        }
    }
    String::from_utf8(buf).map_err(|_| ProxyError::Malformed)
}

/// Serve one HTTP proxy connection.
pub async fn handle_connection(mut client: TcpStream) -> Result<(), ProxyError> {
    let head = read_head(&mut client).await?;
    let target = parse_target(&head)?;

    if target.route() == Route::Turnet {
        client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Err(ProxyError::TurnetPipelineUnavailable);
    }

    let mut upstream = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(s) => s,
        Err(e) => {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Err(ProxyError::Io(e));
        }
    };

    if target.connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        // Forward the (rewritten) request head to the origin, then splice.
        let rewritten = rewrite_to_origin_form(&head);
        upstream.write_all(rewritten.as_bytes()).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority() {
        let t =
            parse_target("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert!(t.connect);
        assert_eq!(t.route(), Route::ClearWeb);
    }

    #[test]
    fn parses_absolute_form_and_defaults_port() {
        let t =
            parse_target("GET http://shop.tur/index HTTP/1.1\r\nHost: shop.tur\r\n\r\n").unwrap();
        assert_eq!(t.host, "shop.tur");
        assert_eq!(t.port, 80);
        assert!(!t.connect);
        assert_eq!(t.route(), Route::Turnet);
    }

    #[test]
    fn parses_origin_form_via_host_header() {
        let t = parse_target("GET /path HTTP/1.1\r\nHost: node.vps:8443\r\n\r\n").unwrap();
        assert_eq!(t.host, "node.vps");
        assert_eq!(t.port, 8443);
        assert_eq!(t.route(), Route::Turnet);
    }

    #[test]
    fn rewrites_absolute_to_origin_form() {
        let head = "GET http://example.com/a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let out = rewrite_to_origin_form(head);
        assert!(out.starts_with("GET /a?b=c HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com"));
    }

    #[test]
    fn rewrite_leaves_origin_form_untouched() {
        let head = "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(rewrite_to_origin_form(head), head);
    }

    #[tokio::test]
    async fn connect_clearweb_tunnels() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 2];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = server.accept().await.unwrap();
            handle_connection(sock).await
        });
        let mut c = TcpStream::connect(srv_addr).await.unwrap();
        let req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", up_addr.port());
        c.write_all(req.as_bytes()).await.unwrap();
        // Read the 200 response line.
        let mut byte = [0u8; 1];
        let mut resp = Vec::new();
        loop {
            c.read_exact(&mut byte).await.unwrap();
            resp.push(byte[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&resp).contains("200"));
        c.write_all(b"hi").await.unwrap();
        let mut echo = [0u8; 2];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hi");
        // Close the client so the tunnel sees EOF and the handler task finishes.
        drop(c);
        handle.await.unwrap().unwrap();
    }
}
