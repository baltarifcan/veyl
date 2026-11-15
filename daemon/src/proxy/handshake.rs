//! SOCKS5, SOCKS4/4a and HTTP CONNECT, sniffed from the first byte.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Host {
    fn from_str(s: &str) -> Host {
        let t = s.trim_start_matches('[').trim_end_matches(']');
        match t.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(s.trim_end_matches('.').to_ascii_lowercase()),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Host::Name(n) => n.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Proto {
    Socks5,
    Socks4,
    Http,
}

pub struct Request {
    pub host: Host,
    pub port: u16,
    pub proto: Proto,
    /// Client bytes that arrived after the request, before our reply.
    pub early: Vec<u8>,
}

pub enum Incoming {
    Tunnel(Request),
    /// A plain HTTP request to the proxy itself.
    Status,
    Reject,
}

#[derive(Clone, Copy, Debug)]
pub enum Failure {
    General,
    NetUnreachable,
    HostUnreachable,
    Refused,
    TimedOut,
}

impl Failure {
    pub fn from_io(e: &io::Error) -> Failure {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => Failure::Refused,
            io::ErrorKind::TimedOut => Failure::TimedOut,
            io::ErrorKind::HostUnreachable => Failure::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => Failure::NetUnreachable,
            io::ErrorKind::NotFound => Failure::HostUnreachable,
            _ => Failure::General,
        }
    }
}

pub async fn read(s: &mut TcpStream) -> io::Result<Incoming> {
    let b0 = s.read_u8().await?;
    match b0 {
        0x05 => socks5(s).await,
        0x04 => socks4(s).await,
        b'A'..=b'Z' => http(s, b0).await,
        _ => Ok(Incoming::Reject),
    }
}

async fn socks5(s: &mut TcpStream) -> io::Result<Incoming> {
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xFF]).await?;
        return Ok(Incoming::Reject);
    }
    s.write_all(&[5, 0]).await?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Ok(Incoming::Reject);
    }
    let host = match hdr[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(a)))
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            Host::from_str(&String::from_utf8_lossy(&name))
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Ok(Incoming::Reject);
        }
    };
    let port = s.read_u16().await?;
    if hdr[1] != 1 {
        // CONNECT only; clients fall back on "command not supported".
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(Incoming::Reject);
    }
    Ok(Incoming::Tunnel(Request { host, port, proto: Proto::Socks5, early: Vec::new() }))
}

async fn socks4(s: &mut TcpStream) -> io::Result<Incoming> {
    let cmd = s.read_u8().await?;
    let port = s.read_u16().await?;
    let mut ip = [0u8; 4];
    s.read_exact(&mut ip).await?;
    read_cstr(s).await?; // user id
    let host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        Host::from_str(&read_cstr(s).await?) // 4a
    } else {
        Host::Ip(IpAddr::V4(Ipv4Addr::from(ip)))
    };
    if cmd != 1 {
        s.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(Incoming::Reject);
    }
    Ok(Incoming::Tunnel(Request { host, port, proto: Proto::Socks4, early: Vec::new() }))
}

async fn read_cstr(s: &mut TcpStream) -> io::Result<String> {
    let mut v = Vec::new();
    loop {
        let c = s.read_u8().await?;
        if c == 0 {
            break;
        }
        v.push(c);
        if v.len() > 255 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SOCKS4 field too long"));
        }
    }
    Ok(String::from_utf8_lossy(&v).into_owned())
}

async fn http(s: &mut TcpStream, b0: u8) -> io::Result<Incoming> {
    let mut buf = vec![b0];
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 16 * 1024 {
            return Ok(Incoming::Reject);
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(Incoming::Reject);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let early = buf[end..].to_vec();
    let line = head.split("\r\n").next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(target) else {
            s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(Incoming::Reject);
        };
        if host.is_empty() {
            s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(Incoming::Reject);
        }
        return Ok(Incoming::Tunnel(Request { host: Host::from_str(host), port, proto: Proto::Http, early }));
    }
    if target.starts_with('/') && (method == "GET" || method == "HEAD") {
        return Ok(Incoming::Status);
    }
    s.write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
    Ok(Incoming::Reject)
}

/// `host:port`, `[v6]:port`, or either without a port (443).
fn split_authority(a: &str) -> Option<(&str, u16)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => 443,
            None => return None,
        };
        return Some((h, port));
    }
    match a.matches(':').count() {
        0 => Some((a, 443)),
        1 => {
            let (h, p) = a.split_once(':')?;
            Some((h, p.parse().ok()?))
        }
        _ => Some((a, 443)), // a bare IPv6 literal
    }
}

#[cfg(test)]
mod tests {
    use super::split_authority;

    #[test]
    fn authorities() {
        assert_eq!(split_authority("example.com:8443"), Some(("example.com", 8443)));
        assert_eq!(split_authority("example.com"), Some(("example.com", 443)));
        assert_eq!(split_authority("[::1]:443"), Some(("::1", 443)));
        assert_eq!(split_authority("[::1]"), Some(("::1", 443)));
        assert_eq!(split_authority("example.com:x"), None);
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub async fn reply_ok(s: &mut TcpStream, proto: Proto) -> io::Result<()> {
    match proto {
        Proto::Socks5 => s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await,
        Proto::Socks4 => s.write_all(&[0, 0x5A, 0, 0, 0, 0, 0, 0]).await,
        Proto::Http => s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await,
    }
}

pub async fn reply_err(s: &mut TcpStream, proto: Proto, f: Failure) -> io::Result<()> {
    match proto {
        Proto::Socks5 => {
            let code = match f {
                Failure::General => 1,
                Failure::NetUnreachable => 3,
                Failure::HostUnreachable | Failure::TimedOut => 4,
                Failure::Refused => 5,
            };
            s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
        }
        Proto::Socks4 => s.write_all(&[0, 0x5B, 0, 0, 0, 0, 0, 0]).await,
        Proto::Http => {
            let line = match f {
                Failure::TimedOut => "504 Gateway Timeout",
                _ => "502 Bad Gateway",
            };
            s.write_all(format!("HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", line).as_bytes()).await
        }
    }
}
