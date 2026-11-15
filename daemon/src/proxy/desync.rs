//! Sending the first flight so the DPI cannot read it. The server gets the
//! same bytes; only their framing changes:
//!   split:N      first N bytes in their own TCP segment
//!   oob:N        plus one urgent byte that the server's stack strips
//!   disorder:N   first N bytes sent with TTL 1, retransmitted after the rest
//!   tlsrec:POS   ClientHello split into two TLS records at POS
//! POS is an offset, `sni`, or `sni+N` / `sni-N`.

use std::io;
use std::os::fd::AsRawFd;

use tokio::io::Interest;
use tokio::net::TcpStream;

use super::inspect::{self, FirstFlight};

#[derive(Clone, Debug, PartialEq)]
pub enum Pos {
    At(usize),
    Sni(isize),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    Split(Pos),
    Oob(Pos),
    Disorder(Pos),
}

#[derive(Clone, Debug)]
pub struct Strategy {
    pub name: String,
    pub tlsrec: Option<Pos>,
    pub steps: Vec<Step>,
}

fn parse_pos(s: &str) -> Result<Pos, String> {
    if let Some(rest) = s.strip_prefix("sni") {
        if rest.is_empty() {
            return Ok(Pos::Sni(0));
        }
        let n: isize = rest.trim_start_matches('+').parse().map_err(|_| format!("bad position {:?}", s))?;
        return Ok(Pos::Sni(n));
    }
    s.parse::<usize>().map(Pos::At).map_err(|_| format!("bad position {:?}", s))
}

impl Strategy {
    pub fn parse(spec: &str) -> Result<Strategy, String> {
        let spec = spec.trim();
        let mut s = Strategy { name: spec.to_string(), tlsrec: None, steps: Vec::new() };
        if spec == "none" {
            return Ok(s);
        }
        for tok in spec.split(',') {
            let (op, arg) = tok.split_once(':').ok_or_else(|| format!("bad strategy step {:?}", tok))?;
            let pos = parse_pos(arg)?;
            match op {
                "split" => s.steps.push(Step::Split(pos)),
                "oob" => s.steps.push(Step::Oob(pos)),
                "disorder" => s.steps.push(Step::Disorder(pos)),
                "tlsrec" => s.tlsrec = Some(pos),
                _ => return Err(format!("unknown strategy step {:?}", op)),
            }
        }
        Ok(s)
    }

    pub fn is_none(&self) -> bool {
        self.tlsrec.is_none() && self.steps.is_empty()
    }
}

fn resolve(pos: &Pos, sni: Option<usize>, len: usize) -> Option<usize> {
    let p = match *pos {
        Pos::At(n) => n as isize,
        Pos::Sni(d) => sni? as isize + d,
    };
    if p <= 0 {
        return None;
    }
    Some((p as usize).min(len))
}

pub async fn send_first(stream: &TcpStream, payload: &[u8], info: &FirstFlight, s: &Strategy) -> io::Result<()> {
    let buf: Vec<u8>;
    let mut data: &[u8] = payload;
    let mut sni = info.sni_offset;

    if let (Some(rp), inspect::Kind::Tls) = (&s.tlsrec, info.kind) {
        // POS counts from the start of the payload.
        if let Some(at) = resolve(rp, sni, payload.len()) {
            if at > 5 {
                if let Some(v) = inspect::split_record(payload, at - 5) {
                    buf = v;
                    data = &buf;
                    sni = sni.map(|o| if o >= at { o + 5 } else { o });
                }
            }
        }
    }

    let mut lp = 0usize;
    for step in &s.steps {
        let (Step::Split(p) | Step::Oob(p) | Step::Disorder(p)) = step;
        let Some(pos) = resolve(p, sni, data.len()) else { continue };
        if pos < lp || (pos == lp && !matches!(step, Step::Oob(_))) {
            continue;
        }
        match step {
            Step::Split(_) => send_all(stream, &data[lp..pos], 0).await?,
            Step::Oob(_) => {
                let mut seg = data[lp..pos].to_vec();
                seg.push(b'a');
                send_all(stream, &seg, libc::MSG_OOB).await?;
            }
            Step::Disorder(_) => {
                let old = get_ttl(stream);
                set_ttl(stream, 1)?;
                let r = send_all(stream, &data[lp..pos], 0).await;
                set_ttl(stream, old.unwrap_or(64))?;
                r?;
            }
        }
        lp = pos;
    }
    send_all(stream, &data[lp..], 0).await
}

/// One send() per call, so segment boundaries hold under TCP_NODELAY.
pub async fn send_all(stream: &TcpStream, data: &[u8], flags: libc::c_int) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let mut off = 0;
    while off < data.len() {
        stream.writable().await?;
        let rest = &data[off..];
        let r = stream.try_io(Interest::WRITABLE, || {
            let n = unsafe { libc::send(fd, rest.as_ptr() as *const libc::c_void, rest.len(), flags) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        });
        match r {
            // Partial: the urgent mark would land on a real byte.
            Ok(n) if flags & libc::MSG_OOB != 0 && n < rest.len() => {
                return Err(io::Error::other("partial urgent send"));
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn ttl_opt(stream: &TcpStream) -> (libc::c_int, libc::c_int) {
    match stream.peer_addr() {
        Ok(a) if a.is_ipv6() => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        _ => (libc::IPPROTO_IP, libc::IP_TTL),
    }
}

fn get_ttl(stream: &TcpStream) -> Option<libc::c_int> {
    let (level, opt) = ttl_opt(stream);
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(stream.as_raw_fd(), level, opt, &mut v as *mut _ as *mut libc::c_void, &mut len) };
    (r == 0 && v > 0).then_some(v)
}

fn set_ttl(stream: &TcpStream, ttl: libc::c_int) -> io::Result<()> {
    let (level, opt) = ttl_opt(stream);
    let r = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            level,
            opt,
            &ttl as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert!(Strategy::parse("none").unwrap().is_none());
        let s = Strategy::parse("tlsrec:sni+1,split:1").unwrap();
        assert_eq!(s.tlsrec, Some(Pos::Sni(1)));
        assert_eq!(s.steps, vec![Step::Split(Pos::At(1))]);
        assert_eq!(Strategy::parse("oob:sni-2").unwrap().steps, vec![Step::Oob(Pos::Sni(-2))]);
        assert!(Strategy::parse("bogus:1").is_err());
        assert!(Strategy::parse("split").is_err());
    }
}
