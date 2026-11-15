//! Just enough DNS wire format to cache answers and replay them with the
//! client's ID, question spelling, and decremented TTLs.

pub const TYPE_OPT: u16 = 41;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

#[derive(Debug)]
pub struct BadMessage;

#[derive(Debug, Clone)]
pub struct Question {
    /// Lowercased wire name + qtype + qclass + flags byte.
    pub key: Vec<u8>,
    /// Lowercased, dotted, no trailing dot; "" for the root.
    pub name: String,
    pub qtype: u16,
    /// Offset just past the question section.
    pub end: usize,
    /// Largest UDP response the client accepts.
    pub udp_size: usize,
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, BadMessage> {
    b.get(off..off + 2).map(|s| u16::from_be_bytes([s[0], s[1]])).ok_or(BadMessage)
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, BadMessage> {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(BadMessage)
}

/// Offset just past a possibly-compressed name (pointers not followed).
pub fn skip_name(b: &[u8], mut off: usize) -> Result<usize, BadMessage> {
    for _ in 0..128 {
        let len = *b.get(off).ok_or(BadMessage)? as usize;
        if len == 0 {
            return Ok(off + 1);
        }
        match len & 0xC0 {
            0xC0 => {
                if off + 2 > b.len() {
                    return Err(BadMessage);
                }
                return Ok(off + 2);
            }
            0x00 => off += 1 + len,
            _ => return Err(BadMessage),
        }
    }
    Err(BadMessage)
}

/// Single-question standard queries only.
pub fn parse_query(b: &[u8]) -> Result<Question, BadMessage> {
    if b.len() < 12 {
        return Err(BadMessage);
    }
    let qr = b[2] & 0x80 != 0;
    let opcode = (b[2] >> 3) & 0x0F;
    if qr || opcode != 0 || u16_at(b, 4)? != 1 {
        return Err(BadMessage);
    }
    let (key_name, name, off) = read_question_name(b, 12)?;
    let qtype = u16_at(b, off)?;
    let qclass = u16_at(b, off + 2)?;
    let end = off + 4;

    let ancount = u16_at(b, 6)? as usize;
    let nscount = u16_at(b, 8)? as usize;
    let arcount = u16_at(b, 10)? as usize;
    let mut p = end;
    for _ in 0..ancount + nscount {
        p = skip_rr(b, p)?.0;
    }
    let mut udp_size = 512usize;
    let mut has_edns = false;
    let mut do_bit = false;
    for _ in 0..arcount {
        let name_end = skip_name(b, p)?;
        let rtype = u16_at(b, name_end)?;
        if rtype == TYPE_OPT {
            has_edns = true;
            udp_size = (u16_at(b, name_end + 2)? as usize).max(512);
            let ttl = u32_at(b, name_end + 4)?;
            do_bit = ttl & 0x8000 != 0;
        }
        p = skip_rr(b, p)?.0;
    }

    let cd_bit = b[3] & 0x10 != 0;
    let mut key = key_name;
    key.extend_from_slice(&qtype.to_be_bytes());
    key.extend_from_slice(&qclass.to_be_bytes());
    // EDNS, DO and CD change the answer, so they are part of the key.
    key.push((has_edns as u8) | (do_bit as u8) << 1 | (cd_bit as u8) << 2);
    Ok(Question { key, name, qtype, end, udp_size })
}

/// (lowercased wire, dotted, end offset) of an uncompressed name.
fn read_question_name(b: &[u8], mut off: usize) -> Result<(Vec<u8>, String, usize), BadMessage> {
    let mut wire = Vec::with_capacity(64);
    let mut dotted = String::with_capacity(64);
    loop {
        let len = *b.get(off).ok_or(BadMessage)? as usize;
        if len == 0 {
            wire.push(0);
            off += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return Err(BadMessage);
        }
        let label = b.get(off + 1..off + 1 + len).ok_or(BadMessage)?;
        wire.push(len as u8);
        if !dotted.is_empty() {
            dotted.push('.');
        }
        for &c in label {
            let c = c.to_ascii_lowercase();
            wire.push(c);
            dotted.push(if c.is_ascii_graphic() { c as char } else { '?' });
        }
        off += 1 + len;
        if wire.len() > 255 {
            return Err(BadMessage);
        }
    }
    Ok((wire, dotted, off))
}

/// (offset past the RR, offset of its TTL, its type, its TTL)
fn skip_rr(b: &[u8], off: usize) -> Result<(usize, usize, u16, u32), BadMessage> {
    let n = skip_name(b, off)?;
    let rtype = u16_at(b, n)?;
    let ttl = u32_at(b, n + 4)?;
    let rdlen = u16_at(b, n + 8)? as usize;
    let end = n + 10 + rdlen;
    if end > b.len() {
        return Err(BadMessage);
    }
    Ok((end, n + 4, rtype, ttl))
}

#[derive(Debug, Clone)]
pub struct Response {
    pub rcode: u8,
    pub truncated: bool,
    /// (offset of the TTL field, original TTL) for every RR except OPT.
    pub ttls: Vec<(u16, u32)>,
    pub min_ttl: Option<u32>,
    pub answers: u16,
}

/// Validate that `b` answers `q` and index its TTLs.
pub fn parse_response(b: &[u8], q: &Question) -> Result<Response, BadMessage> {
    if b.len() < 12 || b[2] & 0x80 == 0 || u16_at(b, 4)? != 1 {
        return Err(BadMessage);
    }
    let (key_name, _, off) = read_question_name(b, 12)?;
    // Must be our question, modulo case.
    let qlen = key_name.len() + 4;
    if off + 4 > b.len() || q.key.len() != qlen + 1 {
        return Err(BadMessage);
    }
    if key_name[..] != q.key[..key_name.len()] || b[off..off + 4] != q.key[key_name.len()..qlen] {
        return Err(BadMessage);
    }
    let rcode = b[3] & 0x0F;
    let truncated = b[2] & 0x02 != 0;
    let an = u16_at(b, 6)?;
    let total = an as usize + u16_at(b, 8)? as usize + u16_at(b, 10)? as usize;
    let mut p = off + 4;
    let mut ttls = Vec::with_capacity(total);
    let mut min_ttl: Option<u32> = None;
    for _ in 0..total {
        let (next, ttl_off, rtype, ttl) = skip_rr(b, p)?;
        if rtype != TYPE_OPT {
            if ttl_off > u16::MAX as usize {
                return Err(BadMessage);
            }
            ttls.push((ttl_off as u16, ttl));
            min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
        }
        p = next;
    }
    Ok(Response { rcode, truncated, ttls, min_ttl, answers: an })
}

pub fn render(cached: &[u8], ttls: &[(u16, u32)], age: u32, ttl_override: Option<u32>, query: &[u8], q: &Question) -> Vec<u8> {
    let mut out = cached.to_vec();
    out[0] = query[0];
    out[1] = query[1];
    out[2] = (out[2] & !0x01) | (query[2] & 0x01);
    // Echo the client's spelling (0x20).
    if q.end <= out.len() && q.end <= query.len() {
        out[12..q.end].copy_from_slice(&query[12..q.end]);
    }
    for &(off, ttl) in ttls {
        let v = match ttl_override {
            Some(t) => t.min(ttl.max(1)),
            None => ttl.saturating_sub(age),
        };
        let off = off as usize;
        if off + 4 <= out.len() {
            out[off..off + 4].copy_from_slice(&v.to_be_bytes());
        }
    }
    out
}

/// Drop the options (cookies, padding, ...) from a trailing OPT record: they
/// are per-client and must not be forwarded or replayed.
pub fn strip_edns_options(b: &[u8]) -> Vec<u8> {
    let walk = || -> Result<Option<usize>, BadMessage> {
        let qd = u16_at(b, 4)? as usize;
        let total = u16_at(b, 6)? as usize + u16_at(b, 8)? as usize + u16_at(b, 10)? as usize;
        let mut p = 12;
        for _ in 0..qd {
            p = skip_name(b, p)? + 4;
        }
        let mut opt_rdlen_at = None;
        for _ in 0..total {
            let (next, ttl_off, rtype, _) = skip_rr(b, p)?;
            opt_rdlen_at = if rtype == TYPE_OPT && next == b.len() { Some(ttl_off + 4) } else { None };
            p = next;
        }
        Ok(opt_rdlen_at)
    };
    match walk() {
        Ok(Some(at)) if at + 2 <= b.len() && b.len() > at + 2 => {
            let mut out = b[..at].to_vec();
            out.extend_from_slice(&[0, 0]);
            out
        }
        _ => b.to_vec(),
    }
}

pub fn error_reply(query: &[u8], q_end: Option<usize>, rcode: u8) -> Vec<u8> {
    let end = q_end.unwrap_or(12).min(query.len());
    let mut out = query[..end].to_vec();
    if out.len() < 12 {
        out.resize(12, 0);
    }
    out[2] = 0x80 | (query.get(2).copied().unwrap_or(0) & 0x79); // QR, opcode, RD
    out[3] = 0x80 | (rcode & 0x0F); // RA
    let qd: u16 = if q_end.is_some() { 1 } else { 0 };
    out[4..6].copy_from_slice(&qd.to_be_bytes());
    out[6..12].fill(0);
    out
}

pub fn truncated_reply(query: &[u8], q: &Question) -> Vec<u8> {
    let mut out = error_reply(query, Some(q.end), RCODE_NOERROR);
    out[2] |= 0x02;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(name: &str, qtype: u16, edns: bool) -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if edns { 1 } else { 0 }];
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        if edns {
            b.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
        }
        b
    }

    fn build_answer(query: &[u8], q: &Question, ttl: u32) -> Vec<u8> {
        let mut b = query[..q.end].to_vec();
        b[2] = 0x81;
        b[3] = 0x80;
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b[10..12].copy_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        b.extend_from_slice(&ttl.to_be_bytes());
        b.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
        b
    }

    #[test]
    fn query_key_ignores_case_and_id() {
        let a = build_query("Example.COM", 1, false);
        let mut b = build_query("example.com", 1, false);
        b[0] = 9;
        let qa = parse_query(&a).unwrap();
        let qb = parse_query(&b).unwrap();
        assert_eq!(qa.key, qb.key);
        assert_eq!(qa.name, "example.com");
        assert_eq!(qa.udp_size, 512);
    }

    #[test]
    fn edns_is_part_of_the_key() {
        let a = parse_query(&build_query("example.com", 1, false)).unwrap();
        let b = parse_query(&build_query("example.com", 1, true)).unwrap();
        assert_ne!(a.key, b.key);
        assert_eq!(b.udp_size, 1232);
    }

    #[test]
    fn response_roundtrip_and_ttl_decrement() {
        let query = build_query("example.com", 1, false);
        let q = parse_query(&query).unwrap();
        let ans = build_answer(&query, &q, 300);
        let r = parse_response(&ans, &q).unwrap();
        assert_eq!(r.min_ttl, Some(300));
        assert_eq!(r.answers, 1);

        let mut q2raw = build_query("EXAMPLE.com", 1, false);
        q2raw[0] = 0xAB;
        q2raw[1] = 0xCD;
        let q2 = parse_query(&q2raw).unwrap();
        let out = render(&ans, &r.ttls, 100, None, &q2raw, &q2);
        assert_eq!(&out[0..2], &[0xAB, 0xCD]);
        assert_eq!(&out[12..q2.end], &q2raw[12..q2.end]);
        let off = r.ttls[0].0 as usize;
        assert_eq!(u32::from_be_bytes(out[off..off + 4].try_into().unwrap()), 200);
    }

    #[test]
    fn mismatched_question_is_rejected() {
        let query = build_query("example.com", 1, false);
        let q = parse_query(&query).unwrap();
        let other = build_query("example.org", 1, false);
        let qo = parse_query(&other).unwrap();
        let ans = build_answer(&other, &qo, 60);
        assert!(parse_response(&ans, &q).is_err());
    }

    #[test]
    fn longer_or_shorter_question_in_reply_is_rejected_not_panicking() {
        let short = build_query("a", 1, false);
        let qs = parse_query(&short).unwrap();
        let long = build_query("a-much-longer-name.example", 1, false);
        let ql = parse_query(&long).unwrap();
        assert!(parse_response(&build_answer(&long, &ql, 60), &qs).is_err());
        assert!(parse_response(&build_answer(&short, &qs, 60), &ql).is_err());
    }

    #[test]
    fn edns_options_are_stripped() {
        let mut q = build_query("example.com", 1, true);
        // Give the OPT record a COOKIE option (code 10, 8 bytes).
        let n = q.len();
        q[n - 2..].copy_from_slice(&12u16.to_be_bytes());
        q.extend_from_slice(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let s = strip_edns_options(&q);
        assert_eq!(s, build_query("example.com", 1, true));
        assert!(parse_query(&s).is_ok());
        // No OPT: unchanged.
        let plain = build_query("example.com", 1, false);
        assert_eq!(strip_edns_options(&plain), plain);
    }

    #[test]
    fn garbage_does_not_panic() {
        for len in 0..64 {
            let b: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = parse_query(&b);
            if let Ok(q) = parse_query(&build_query("a.b", 1, false)) {
                let _ = parse_response(&b, &q);
            }
        }
    }
}
