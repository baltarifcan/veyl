//! Recognising the first flight of a connection, and judging the reply.

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Tls,
    Http,
    Other,
}

#[derive(Clone, Debug)]
pub struct FirstFlight {
    pub kind: Kind,
    /// SNI, or the HTTP Host header, lowercased.
    pub host: Option<String>,
    /// Offset of the SNI name within the payload.
    pub sni_offset: Option<usize>,
    /// Safe to resend on a fresh connection.
    pub replayable: bool,
}

fn u16_at(b: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]) as usize)
}

/// Total size of the TLS record starting at 0, if this looks like one.
pub fn tls_record_len(b: &[u8]) -> Option<usize> {
    if b.len() >= 5 && b[0] == 0x16 && b[1] == 0x03 {
        Some(5 + u16_at(b, 3)?)
    } else {
        None
    }
}

pub fn is_client_hello(b: &[u8]) -> bool {
    b.len() >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

/// (SNI, offset of the name) from a ClientHello.
pub fn parse_sni(b: &[u8]) -> Option<(String, usize)> {
    if !is_client_hello(b) {
        return None;
    }
    let mut o = 5 + 4 + 2 + 32;
    let sid = *b.get(o)? as usize;
    o += 1 + sid;
    o += 2 + u16_at(b, o)?;
    o += 1 + *b.get(o)? as usize;
    let ext_total = u16_at(b, o)?;
    o += 2;
    let end = (o + ext_total).min(b.len());
    while o + 4 <= end {
        let etype = u16_at(b, o)?;
        let elen = u16_at(b, o + 2)?;
        o += 4;
        if etype == 0 {
            // server_name_list: u16 len, u8 type (0 = host_name), u16 len, name
            if *b.get(o + 2)? != 0 {
                return None;
            }
            let nlen = u16_at(b, o + 3)?;
            let name = b.get(o + 5..o + 5 + nlen)?;
            let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            return Some((name, o + 5));
        }
        o += elen;
    }
    None
}

const HTTP_METHODS: &[(&str, bool)] = &[
    ("GET ", true),
    ("HEAD ", true),
    ("OPTIONS ", true),
    ("POST ", false),
    ("PUT ", false),
    ("DELETE ", false),
    ("PATCH ", false),
];

pub fn inspect(b: &[u8]) -> FirstFlight {
    if is_client_hello(b) {
        let sni = parse_sni(b);
        return FirstFlight {
            kind: Kind::Tls,
            host: sni.as_ref().map(|s| s.0.clone()),
            sni_offset: sni.map(|s| s.1),
            replayable: true,
        };
    }
    for &(m, idem) in HTTP_METHODS {
        if b.starts_with(m.as_bytes()) {
            return FirstFlight { kind: Kind::Http, host: http_host(b), sni_offset: None, replayable: idem };
        }
    }
    FirstFlight { kind: Kind::Other, host: None, sni_offset: None, replayable: false }
}

fn http_host(b: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(&b[..b.len().min(8192)]).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("host") {
            let v = v.trim();
            let host = if let Some(rest) = v.strip_prefix('[') {
                rest.split(']').next()?
            } else {
                v.rsplit_once(':').map_or(v, |(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h } else { v })
            };
            return Some(host.to_ascii_lowercase());
        }
    }
    None
}

/// Is this a real ServerHello (and, for TLS 1.3, does it echo our session ID)?
pub fn tls_reply_ok(ch: &[u8], resp: &[u8]) -> bool {
    if resp.is_empty() || resp[0] != 0x16 {
        return false;
    }
    if resp.len() < 6 {
        return resp.len() < 2 || resp[1] == 0x03;
    }
    if resp[1] != 0x03 || resp[5] != 0x02 {
        return false;
    }
    if let (Some(&csl), Some(&ssl)) = (ch.get(43), resp.get(43)) {
        let (csl, ssl) = (csl as usize, ssl as usize);
        if let Some(true) = server_hello_has_ext(resp, 0x2b) {
            let c = ch.get(44..44 + csl);
            let s = resp.get(44..44 + ssl);
            if let (Some(c), Some(s)) = (c, s) {
                if c != s {
                    return false;
                }
            }
        }
    }
    true
}

fn server_hello_has_ext(b: &[u8], want: usize) -> Option<bool> {
    let mut o = 43;
    o += 1 + *b.get(o)? as usize;
    o += 2 + 1; // cipher suite, compression
    let total = u16_at(b, o)?;
    o += 2;
    let end = o + total;
    if end > b.len() {
        return None;
    }
    while o + 4 <= end {
        if u16_at(b, o)? == want {
            return Some(true);
        }
        o += 4 + u16_at(b, o + 2)?;
    }
    Some(false)
}

/// A redirect to a bare IP: the classic block page.
pub fn http_reply_blocked(resp: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&resp[..resp.len().min(4096)]) else { return false };
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code: u16 = status.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    if !(300..400).contains(&code) {
        return false;
    }
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("location") {
                let v = v.trim();
                let rest = v.strip_prefix("http://").or_else(|| v.strip_prefix("https://")).unwrap_or("");
                let host = rest.split(['/', ':', '?']).next().unwrap_or("");
                return host.parse::<std::net::Ipv4Addr>().is_ok();
            }
        }
    }
    false
}

/// Split one TLS record into two at `k` bytes into its body.
pub fn split_record(b: &[u8], k: usize) -> Option<Vec<u8>> {
    let total = tls_record_len(b)?;
    let body_len = total - 5;
    if total > b.len() || k == 0 || k >= body_len {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() + 5);
    out.extend_from_slice(&b[..3]);
    out.extend_from_slice(&(k as u16).to_be_bytes());
    out.extend_from_slice(&b[5..5 + k]);
    out.extend_from_slice(&b[..3]);
    out.extend_from_slice(&((body_len - k) as u16).to_be_bytes());
    out.extend_from_slice(&b[5 + k..]);
    Some(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal but well-formed ClientHello for `host`.
    pub fn client_hello(host: &str) -> Vec<u8> {
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[7u8; 32]);
        hs.push(32);
        hs.extend_from_slice(&[9u8; 32]);
        hs.extend_from_slice(&[0, 2, 0x13, 0x01]);
        hs.extend_from_slice(&[1, 0]);
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut exts = vec![0, 0];
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let mut msg = vec![1, 0];
        msg.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&hs);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    fn server_hello(sid: &[u8], tls13: bool) -> Vec<u8> {
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[1u8; 32]);
        hs.push(sid.len() as u8);
        hs.extend_from_slice(sid);
        hs.extend_from_slice(&[0x13, 0x01, 0]);
        let exts: Vec<u8> = if tls13 { vec![0, 0x2b, 0, 2, 3, 4] } else { vec![] };
        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);
        let mut msg = vec![2, 0];
        msg.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        msg.extend_from_slice(&hs);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        rec.extend_from_slice(&msg);
        rec
    }

    #[test]
    fn sni_is_found() {
        let ch = client_hello("Discord.com");
        let f = inspect(&ch);
        assert_eq!(f.kind, Kind::Tls);
        assert_eq!(f.host.as_deref(), Some("discord.com"));
        let off = f.sni_offset.unwrap();
        assert_eq!(&ch[off..off + 11], b"Discord.com");
    }

    #[test]
    fn server_hello_checks() {
        let ch = client_hello("a.example");
        assert!(tls_reply_ok(&ch, &server_hello(&[9u8; 32], true)));
        assert!(!tls_reply_ok(&ch, &server_hello(&[5u8; 32], true)));
        assert!(tls_reply_ok(&ch, &server_hello(&[5u8; 32], false)));
        assert!(!tls_reply_ok(&ch, &[0x15, 0x03, 0x03, 0, 2, 2, 40]));
        assert!(!tls_reply_ok(&ch, b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(tls_reply_ok(&ch, &[0x16, 0x03]));
    }

    #[test]
    fn record_split_roundtrip() {
        let ch = client_hello("example.com");
        let s = split_record(&ch, 10).unwrap();
        assert_eq!(s.len(), ch.len() + 5);
        assert_eq!(u16_at(&s, 3), Some(10));
        let mut body = s[5..15].to_vec();
        body.extend_from_slice(&s[20..]);
        assert_eq!(body, ch[5..]);
    }

    #[test]
    fn http_detection() {
        let req = b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n";
        let f = inspect(req);
        assert_eq!(f.kind, Kind::Http);
        assert_eq!(f.host.as_deref(), Some("example.com"));
        assert!(f.replayable);
        assert!(!inspect(b"POST / HTTP/1.1\r\n\r\n").replayable);
        assert!(http_reply_blocked(b"HTTP/1.1 302 Found\r\nLocation: http://195.175.254.2/block\r\n\r\n"));
        assert!(!http_reply_blocked(b"HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n"));
    }
}
