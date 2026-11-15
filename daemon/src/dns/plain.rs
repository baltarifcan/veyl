//! Plain DNS over UDP, retried over TCP on truncation. For local names and
//! as a fallback while DoH is unreachable (captive portals).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

use super::msg;

fn random_id() -> u16 {
    unsafe { libc::arc4random() as u16 }
}

/// Query `server`; the returned message carries transaction ID 0.
pub async fn query(server: SocketAddr, wire: &[u8], q: &msg::Question, limit: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + limit;
    let id = random_id();
    let mut req = wire.to_vec();
    req[0..2].copy_from_slice(&id.to_be_bytes());

    let bind: SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(server).await.map_err(|e| e.to_string())?;
    sock.send(&req).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65_535];
    loop {
        let n = match timeout(deadline - Instant::now(), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.to_string()),
            Err(_) => return Err("timed out".into()),
        };
        let resp = &buf[..n];
        // Wrong ID or question: spoofed or stray, keep waiting.
        if n < 12 || resp[0..2] != id.to_be_bytes() || msg::parse_response(resp, q).is_err() {
            continue;
        }
        if resp[2] & 0x02 != 0 {
            return query_tcp(server, &req, id, q, deadline).await;
        }
        let mut out = resp.to_vec();
        out[0] = 0;
        out[1] = 0;
        return Ok(out);
    }
}

async fn query_tcp(server: SocketAddr, req: &[u8], id: u16, q: &msg::Question, deadline: Instant) -> Result<Vec<u8>, String> {
    let work = async {
        let mut s = TcpStream::connect(server).await.map_err(|e| e.to_string())?;
        let _ = s.set_nodelay(true);
        let mut out = Vec::with_capacity(req.len() + 2);
        out.extend_from_slice(&(req.len() as u16).to_be_bytes());
        out.extend_from_slice(req);
        s.write_all(&out).await.map_err(|e| e.to_string())?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.map_err(|e| e.to_string())?;
        let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
        if resp.len() < 12 || resp[0..2] != id.to_be_bytes() || msg::parse_response(&resp, q).is_err() {
            return Err("bad TCP response".to_string());
        }
        resp[0] = 0;
        resp[1] = 0;
        Ok(resp)
    };
    match timeout(deadline.saturating_duration_since(Instant::now()), work).await {
        Ok(r) => r,
        Err(_) => Err("timed out".into()),
    }
}
