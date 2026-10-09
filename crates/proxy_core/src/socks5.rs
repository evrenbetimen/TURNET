//! SOCKS5 server (RFC 1928): greeting, CONNECT, and split routing.
//!
//! A client negotiates the no-authentication method, then issues a `CONNECT`
//! request naming a target host. The target is classified by
//! [`crate::classify_host`]:
//!
//! - **Clear-web** targets are dialed directly and the two sockets are spliced,
//!   so native throughput is preserved.
//! - **Turnet** targets (`.tur`/`.vps`/`.cpt`) belong to the P2P pipeline. That
//!   pipeline (DHT resolve + relay transport) is not wired yet, so such a
//!   request is refused with a SOCKS "network unreachable" reply and
//!   [`ProxyError::TurnetPipelineUnavailable`] rather than leaking the name to
//!   a public resolver. Wiring it to [`dht_resolver`] + the relay is the next
//!   milestone.
//!
//! Only `CONNECT` is supported (the command browsers and tunneling clients
//! use); `BIND` and `UDP ASSOCIATE` are refused with the standard reply.

use crate::{classify_host, ProxyError, Route};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes (RFC 1928 §6).
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NET_UNREACHABLE: u8 = 0x03;
const REP_CONN_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// A parsed SOCKS5 `CONNECT` request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    /// Target host: a domain name, or the string form of an IPv4/IPv6 address.
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl Socks5Request {
    /// Which pipeline this request routes to.
    pub fn route(&self) -> Route {
        classify_host(&self.host)
    }
}

/// Parse a complete SOCKS5 request packet (the bytes after the method
/// negotiation): `VER CMD RSV ATYP ADDR PORT`.
///
/// Returns [`ProxyError::UnsupportedVersion`], [`ProxyError::UnsupportedCommand`],
/// or [`ProxyError::UnsupportedAddressType`] for the specific fields a reply
/// code maps to, and [`ProxyError::Malformed`] for a truncated packet.
pub fn parse_request(buf: &[u8]) -> Result<Socks5Request, ProxyError> {
    if buf.len() < 4 {
        return Err(ProxyError::Malformed);
    }
    if buf[0] != VERSION {
        return Err(ProxyError::UnsupportedVersion);
    }
    if buf[1] != CMD_CONNECT {
        return Err(ProxyError::UnsupportedCommand);
    }
    let atyp = buf[3];
    let mut i = 4;
    let host = match atyp {
        ATYP_IPV4 => {
            let end = i + 4;
            let o = buf.get(i..end).ok_or(ProxyError::Malformed)?;
            i = end;
            Ipv4Addr::new(o[0], o[1], o[2], o[3]).to_string()
        }
        ATYP_DOMAIN => {
            let len = *buf.get(i).ok_or(ProxyError::Malformed)? as usize;
            i += 1;
            let end = i + len;
            let name = buf.get(i..end).ok_or(ProxyError::Malformed)?;
            i = end;
            std::str::from_utf8(name)
                .map_err(|_| ProxyError::Malformed)?
                .to_string()
        }
        ATYP_IPV6 => {
            let end = i + 16;
            let o: [u8; 16] = buf
                .get(i..end)
                .ok_or(ProxyError::Malformed)?
                .try_into()
                .map_err(|_| ProxyError::Malformed)?;
            i = end;
            Ipv6Addr::from(o).to_string()
        }
        _ => return Err(ProxyError::UnsupportedAddressType),
    };
    let port_bytes: [u8; 2] = buf
        .get(i..i + 2)
        .ok_or(ProxyError::Malformed)?
        .try_into()
        .map_err(|_| ProxyError::Malformed)?;
    Ok(Socks5Request {
        host,
        port: u16::from_be_bytes(port_bytes),
    })
}

/// A 10-byte SOCKS5 reply with an all-zero IPv4 bound address.
fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Drive one SOCKS5 client connection through negotiation, CONNECT, and
/// (for clear-web targets) bidirectional relay to the upstream server.
pub async fn handle_connection(mut client: TcpStream) -> Result<(), ProxyError> {
    // --- Method negotiation: VER, NMETHODS, METHODS... ---
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != VERSION {
        return Err(ProxyError::UnsupportedVersion);
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    client.read_exact(&mut methods).await?;
    // Select "no authentication required".
    client.write_all(&[VERSION, 0x00]).await?;

    // --- Request: VER, CMD, RSV, ATYP, ADDR, PORT ---
    let mut rh = [0u8; 4];
    client.read_exact(&mut rh).await?;
    // Reassemble the full request packet so the pure parser validates it.
    let mut packet = rh.to_vec();
    match rh[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4 + 2];
            client.read_exact(&mut a).await?;
            packet.extend_from_slice(&a);
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16 + 2];
            client.read_exact(&mut a).await?;
            packet.extend_from_slice(&a);
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut a = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut a).await?;
            packet.push(len[0]);
            packet.extend_from_slice(&a);
        }
        _ => {
            client.write_all(&reply(REP_ATYP_NOT_SUPPORTED)).await?;
            return Err(ProxyError::UnsupportedAddressType);
        }
    }

    let req = match parse_request(&packet) {
        Ok(r) => r,
        Err(e) => {
            let code = match e {
                ProxyError::UnsupportedCommand => REP_CMD_NOT_SUPPORTED,
                ProxyError::UnsupportedAddressType => REP_ATYP_NOT_SUPPORTED,
                _ => REP_GENERAL_FAILURE,
            };
            client.write_all(&reply(code)).await?;
            return Err(e);
        }
    };

    match req.route() {
        Route::Turnet => {
            // The P2P pipeline is not wired yet; refuse rather than leak the
            // name to public DNS.
            client.write_all(&reply(REP_NET_UNREACHABLE)).await?;
            Err(ProxyError::TurnetPipelineUnavailable)
        }
        Route::ClearWeb => match TcpStream::connect((req.host.as_str(), req.port)).await {
            Ok(mut upstream) => {
                client.write_all(&reply(REP_SUCCESS)).await?;
                tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                Ok(())
            }
            Err(e) => {
                client.write_all(&reply(REP_CONN_REFUSED)).await?;
                Err(ProxyError::Io(e))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_request() {
        // VER CMD RSV ATYP LEN "a.tur" PORT(443)
        let mut p = vec![0x05, 0x01, 0x00, ATYP_DOMAIN, 5];
        p.extend_from_slice(b"a.tur");
        p.extend_from_slice(&443u16.to_be_bytes());
        let req = parse_request(&p).unwrap();
        assert_eq!(req.host, "a.tur");
        assert_eq!(req.port, 443);
        assert_eq!(req.route(), Route::Turnet);
    }

    #[test]
    fn parses_ipv4_request() {
        let mut p = vec![0x05, 0x01, 0x00, ATYP_IPV4, 93, 184, 216, 34];
        p.extend_from_slice(&80u16.to_be_bytes());
        let req = parse_request(&p).unwrap();
        assert_eq!(req.host, "93.184.216.34");
        assert_eq!(req.port, 80);
        assert_eq!(req.route(), Route::ClearWeb);
    }

    #[test]
    fn rejects_non_connect_and_bad_version() {
        let p = vec![0x05, 0x02, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
        assert!(matches!(
            parse_request(&p),
            Err(ProxyError::UnsupportedCommand)
        ));
        let p = vec![0x04, 0x01, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80];
        assert!(matches!(
            parse_request(&p),
            Err(ProxyError::UnsupportedVersion)
        ));
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(parse_request(&[0x05]), Err(ProxyError::Malformed)));
    }

    #[tokio::test]
    async fn connect_clearweb_relays_to_upstream() {
        // Upstream echo server.
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        // Our SOCKS5 server on another port.
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = server.accept().await.unwrap();
            handle_connection(sock).await
        });

        // Client speaks SOCKS5 to our server, asking to CONNECT to upstream.
        let mut c = TcpStream::connect(srv_addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // greeting, no-auth
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        assert_eq!(m, [0x05, 0x00]);
        // CONNECT 127.0.0.1:up_port
        let mut req = vec![0x05, 0x01, 0x00, ATYP_IPV4, 127, 0, 0, 1];
        req.extend_from_slice(&up_addr.port().to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_SUCCESS);
        // Tunnel carries bytes to the echo server and back.
        c.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        c.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        // Close the client so the relay sees EOF and the handler task finishes.
        drop(c);
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_turnet_is_refused_without_leaking() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (sock, _) = server.accept().await.unwrap();
            handle_connection(sock).await
        });
        let mut c = TcpStream::connect(srv_addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut m = [0u8; 2];
        c.read_exact(&mut m).await.unwrap();
        let mut req = vec![0x05, 0x01, 0x00, ATYP_DOMAIN, 5];
        req.extend_from_slice(b"a.tur");
        req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_NET_UNREACHABLE);
        assert!(matches!(
            handle.await.unwrap(),
            Err(ProxyError::TurnetPipelineUnavailable)
        ));
    }
}
