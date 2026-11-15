//! One proxied connection: send the first flight with a strategy, judge the
//! first reply, retry with the next strategy on interference, then relay.
//! A TLS attempt that stays silent is kept open and raced against the next
//! strategy, so a merely slow server costs nothing.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::Instant;

use super::connect::{self, Connected};
use super::desync;
use super::inspect::{self, FirstFlight, Kind};
use super::Proxy;

const RELAY_BUF: usize = 64 * 1024;
/// Wait for the rest of a ClientHello that arrived in pieces.
const FIRST_FLIGHT_WAIT: Duration = Duration::from_millis(300);
/// Client bytes kept for replay while the first reply is being judged.
const MAX_REPLAY: usize = 64 * 1024;
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const JUDGE_CEILING: Duration = Duration::from_secs(30);

struct Attempt {
    c: Connected,
    si: usize,
}

enum Event {
    /// `true` if from the slow attempt.
    Reply(bool, Vec<u8>),
    Failed(bool, String),
    ClientData(usize),
    ClientGone,
    Timeout,
}

pub async fn run(px: Arc<Proxy>, client: TcpStream, remote: Connected, addrs: Vec<SocketAddr>, target_host: String, early: Vec<u8>) {
    // A server-first protocol (SSH, SMTP) has nothing to desync.
    let mut first = early;
    if first.is_empty() {
        tokio::select! {
            r = client.readable() => { if r.is_err() { return; } }
            r = remote.stream.readable() => {
                if r.is_err() { return; }
                return relay(client, remote.stream).await;
            }
        }
        match read_some(&client, &mut first).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
    if let Some(need) = inspect::tls_record_len(&first) {
        let deadline = Instant::now() + FIRST_FLIGHT_WAIT;
        while first.len() < need && first.len() < MAX_REPLAY {
            match tokio::time::timeout_at(deadline, read_some(&client, &mut first)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => break,
            }
        }
    }

    let info = inspect::inspect(&first);
    if info.kind == Kind::Other {
        if desync::send_all(&remote.stream, &first, 0).await.is_ok() {
            relay(client, remote.stream).await;
        }
        return;
    }

    let host = info.host.clone().unwrap_or(target_host);
    let plan = px.book.plan(&host, info.replayable);
    let started = Instant::now();
    let mut extra: Vec<u8> = Vec::new();
    let mut fresh = Some(remote);
    let mut addr = fresh.as_ref().map(|c| c.addr).unwrap();
    let mut failures: Vec<String> = Vec::new();
    let mut slow: Option<Attempt> = None;
    let mut cbuf = vec![0u8; 16 * 1024];

    for (n, &si) in plan.iter().enumerate() {
        let strategy = &px.book.strategies[si];
        let last = n + 1 == plan.len();
        let c = match fresh.take() {
            Some(c) => c,
            None => {
                let mut order = vec![addr];
                order.extend(addrs.iter().filter(|a| **a != addr));
                match connect::connect_any(&order, RECONNECT_TIMEOUT).await {
                    Ok(c) => c,
                    Err(e) => {
                        failures.push(format!("reconnect: {}", e));
                        break;
                    }
                }
            }
        };
        addr = c.addr;
        if !strategy.is_none() {
            px.stats.desynced.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(e) = desync::send_first(&c.stream, &first, &info, strategy).await {
            failures.push(format!("{}: send: {}", strategy.name, e));
            continue;
        }
        if !extra.is_empty() && desync::send_all(&c.stream, &extra, 0).await.is_err() {
            failures.push(format!("{}: send", strategy.name));
            continue;
        }
        if last && slow.is_none() {
            // Out of alternatives: relay whatever this one gets.
            if n > 0 {
                note(&px, &host, &failures, &strategy.name, false);
                // Every strategy drew a non-ServerHello: the server, not the DPI.
                if failures.iter().all(|f| f.contains("unexpected reply")) {
                    px.book.give_up(&host);
                }
            }
            return relay(client, c.stream).await;
        }

        let cur = Attempt { c, si };
        let limit = if last { JUDGE_CEILING } else { judge_timeout(cur.c.rtt, info.kind) };
        let deadline = Instant::now() + limit;
        loop {
            let ev = next_event(&client, &cur, slow.as_ref(), &info, &first, &mut cbuf, deadline).await;
            match ev {
                Event::Reply(from_slow, reply) => {
                    let won = if from_slow { slow.take().unwrap() } else { cur };
                    px.book.success(&host, won.si);
                    let won_strategy = &px.book.strategies[won.si];
                    if won_strategy.is_none() && from_slow {
                        vlog!("proxy: {} was slow to answer; kept the plain connection", host);
                    } else if n > 0 || from_slow {
                        note(&px, &host, &failures, &won_strategy.name, true);
                    } else {
                        vlog!("proxy: {} via {}", host, won_strategy.name);
                    }
                    if desync::send_all(&client, &reply, 0).await.is_ok() {
                        relay(client, won.c.stream).await;
                    }
                    return;
                }
                Event::Failed(true, why) => {
                    let s = slow.take().unwrap();
                    px.stats.interfered.fetch_add(1, Ordering::Relaxed);
                    failures.push(format!("{}: {}", px.book.strategies[s.si].name, why));
                }
                Event::Failed(false, why) => {
                    px.stats.interfered.fetch_add(1, Ordering::Relaxed);
                    failures.push(format!("{}: {}", strategy.name, why));
                    break;
                }
                Event::ClientData(len) => {
                    // Rare (0-RTT, pipelining): keep for replay, forward to all.
                    let data = cbuf[..len].to_vec();
                    extra.extend_from_slice(&data);
                    let _ = tokio::time::timeout_at(deadline, desync::send_all(&cur.c.stream, &data, 0)).await;
                    if let Some(s) = &slow {
                        let _ = tokio::time::timeout_at(deadline, desync::send_all(&s.c.stream, &data, 0)).await;
                    }
                    if extra.len() > MAX_REPLAY {
                        return relay(client, cur.c.stream).await;
                    }
                }
                Event::ClientGone => {
                    // Half-close: some servers answer only after EOF.
                    let keep = slow.take().map_or(cur.c.stream, |s| s.c.stream);
                    return relay(client, keep).await;
                }
                Event::Timeout => {
                    if info.kind != Kind::Tls || last || started.elapsed() > JUDGE_CEILING {
                        let keep = slow.take().map_or(cur.c.stream, |s| s.c.stream);
                        return relay(client, keep).await;
                    }
                    failures.push(format!("{}: no reply in {:.1}s", strategy.name, limit.as_secs_f64()));
                    // Race the next strategy against it; keep only the oldest.
                    if slow.is_none() {
                        slow = Some(cur);
                    }
                    break;
                }
            }
        }
    }
    if let Some(s) = slow {
        return relay(client, s.c.stream).await;
    }
    px.stats.failed.fetch_add(1, Ordering::Relaxed);
    log!("proxy: {} unreachable after {} attempt(s): {}", host, failures.len(), failures.join("; "));
}

#[allow(clippy::too_many_arguments)]
async fn next_event(
    client: &TcpStream,
    cur: &Attempt,
    slow: Option<&Attempt>,
    info: &FirstFlight,
    first: &[u8],
    cbuf: &mut [u8],
    deadline: Instant,
) -> Event {
    // Cancel-safe: bytes are consumed only by the winning branch's try_read.
    tokio::select! {
        r = judge(&cur.c.stream, info, first) => match r {
            Ok(reply) => Event::Reply(false, reply),
            Err(why) => Event::Failed(false, why),
        },
        r = judge_opt(slow.map(|s| &s.c.stream), info, first) => match r {
            Ok(reply) => Event::Reply(true, reply),
            Err(why) => Event::Failed(true, why),
        },
        r = read_client(client, cbuf) => match r {
            Ok(0) | Err(_) => Event::ClientGone,
            Ok(n) => Event::ClientData(n),
        },
        _ = tokio::time::sleep_until(deadline) => Event::Timeout,
    }
}

async fn judge(remote: &TcpStream, info: &FirstFlight, first: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        remote.readable().await.map_err(|e| short_err(&e))?;
        match remote.try_read(&mut buf) {
            Ok(0) => return Err("closed without replying".into()),
            Ok(n) => {
                let reply = &buf[..n];
                let ok = match info.kind {
                    Kind::Tls => inspect::tls_reply_ok(first, reply),
                    Kind::Http => !inspect::http_reply_blocked(reply),
                    Kind::Other => true,
                };
                return if ok {
                    Ok(reply.to_vec())
                } else {
                    Err(format!("unexpected reply ({:02x?})", &reply[..reply.len().min(6)]))
                };
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(short_err(&e)),
        }
    }
}

/// Pending forever for None (select! evaluates disabled branches too).
async fn judge_opt(remote: Option<&TcpStream>, info: &FirstFlight, first: &[u8]) -> Result<Vec<u8>, String> {
    match remote {
        Some(r) => judge(r, info, first).await,
        None => std::future::pending().await,
    }
}

async fn read_client(client: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        client.readable().await?;
        match client.try_read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            r => return r,
        }
    }
}

fn note(px: &Proxy, host: &str, failures: &[String], winner: &str, ok: bool) {
    if ok {
        px.stats.rescued.fetch_add(1, Ordering::Relaxed);
        log!("proxy: {} needs {} ({})", host, winner, failures.join("; "));
    } else {
        log!("proxy: {} giving up on detection, relaying {} as-is ({})", host, winner, failures.join("; "));
    }
}

fn judge_timeout(rtt: Duration, kind: Kind) -> Duration {
    match kind {
        Kind::Tls => (rtt * 8 + Duration::from_millis(1000)).clamp(Duration::from_secs(2), Duration::from_secs(6)),
        _ => Duration::from_secs(10),
    }
}

fn short_err(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::ConnectionReset => "reset".into(),
        io::ErrorKind::ConnectionRefused => "refused".into(),
        io::ErrorKind::TimedOut => "timed out".into(),
        _ => e.to_string(),
    }
}

async fn read_some(s: &TcpStream, into: &mut Vec<u8>) -> io::Result<usize> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        s.readable().await?;
        match s.try_read(&mut buf) {
            Ok(n) => {
                into.extend_from_slice(&buf[..n]);
                return Ok(n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

async fn relay(mut client: TcpStream, mut remote: TcpStream) {
    let _ = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut remote, RELAY_BUF, RELAY_BUF).await;
}
