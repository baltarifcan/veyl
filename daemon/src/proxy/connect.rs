//! Resolving (system getaddrinfo, so /etc/hosts and VPN split DNS work) and
//! dialling with Happy Eyeballs (RFC 8305).

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

pub struct Connected {
    pub stream: TcpStream,
    pub addr: SocketAddr,
    pub rtt: Duration,
}

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let host = host.to_string();
    let lookup = tokio::task::spawn_blocking(move || getaddrinfo(&host, port));
    match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
        Ok(r) => r.map_err(|e| io::Error::other(e.to_string()))?,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "name lookup timed out")),
    }
}

fn getaddrinfo(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let c = CString::new(host).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad host name"))?;
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_protocol = libc::IPPROTO_TCP;
    hints.ai_flags = libc::AI_ADDRCONFIG;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        let msg = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(rc)) }.to_string_lossy().into_owned();
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{}: {}", host, msg)));
    }
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut p = res;
    while !p.is_null() {
        let ai = unsafe { &*p };
        if !ai.ai_addr.is_null() {
            let a = match ai.ai_family {
                libc::AF_INET => {
                    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
                    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))), port))
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in6) };
                    Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                        port,
                        0,
                        sin6.sin6_scope_id,
                    )))
                }
                _ => None,
            };
            if let Some(a) = a {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        p = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    if out.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{}: no addresses", host)));
    }
    Ok(out)
}

/// First address as the resolver sorted it, then alternate families.
fn interleave(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_v6 = addrs.first().is_some_and(|a| a.is_ipv6());
    let (mut a, mut b): (Vec<&SocketAddr>, Vec<&SocketAddr>) = addrs.iter().partition(|x| x.is_ipv6() == first_v6);
    a.reverse();
    b.reverse();
    let mut out = Vec::with_capacity(addrs.len());
    while !a.is_empty() || !b.is_empty() {
        if let Some(x) = a.pop() {
            out.push(*x);
        }
        if let Some(x) = b.pop() {
            out.push(*x);
        }
    }
    out
}

pub async fn connect_any(addrs: &[SocketAddr], limit: Duration) -> io::Result<Connected> {
    let order = interleave(addrs);
    if order.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
    }
    let deadline = Instant::now() + limit;
    let (tx, mut rx) = mpsc::channel::<io::Result<Connected>>(order.len());
    let mut tasks = Vec::new();
    let mut next = 0usize;
    let mut pending = 0usize;
    let mut next_at = Instant::now();
    let mut last_err = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");

    let result = loop {
        if next < order.len() && Instant::now() >= next_at {
            let addr = order[next];
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                let t0 = Instant::now();
                let r = TcpStream::connect(addr).await.map(|stream| {
                    let _ = stream.set_nodelay(true);
                    set_keepalive(&stream);
                    Connected { stream, addr, rtt: t0.elapsed() }
                });
                let _ = tx.send(r).await;
            }));
            next += 1;
            pending += 1;
            next_at = Instant::now() + ATTEMPT_DELAY;
        }
        let wake = if next < order.len() { next_at.min(deadline) } else { deadline };
        tokio::select! {
            r = rx.recv() => {
                pending -= 1;
                match r {
                    Some(Ok(c)) => break Ok(c),
                    Some(Err(e)) => {
                        last_err = e;
                        if pending == 0 {
                            if next < order.len() { next_at = Instant::now(); } else { break Err(last_err); }
                        }
                    }
                    None => break Err(last_err),
                }
            }
            _ = tokio::time::sleep_until(wake) => {
                if Instant::now() >= deadline {
                    break Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
            }
        }
    };
    for t in tasks {
        t.abort();
    }
    result
}

/// Detect a vanished peer in ~3 minutes instead of never.
fn set_keepalive(s: &TcpStream) {
    use std::os::fd::AsRawFd;
    let fd = s.as_raw_fd();
    let set = |level: libc::c_int, opt: libc::c_int, v: libc::c_int| unsafe {
        libc::setsockopt(fd, level, opt, &v as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPALIVE, 120); // idle seconds before probing
    set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 15);
    set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 4);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_families() {
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let v6b: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let v4b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        assert_eq!(interleave(&[v6, v6b, v4, v4b]), vec![v6, v4, v6b, v4b]);
        assert_eq!(interleave(&[v4, v4b]), vec![v4, v4b]);
    }
}
