//! Cache, single-flight, and a hedged race: a miss goes to the best DoH
//! upstream, and to the next provider too if it is slower than usual. Plain
//! and network resolvers are asked only once DoH looks broken.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::cache::{self, Cache, Entry, Lookup};
use super::local::LocalDns;
use super::msg::{self, Question};
use super::plain;
use super::upstream::DohPool;
use crate::{log_every, netwatch, vlog};

const MAX_PARALLEL: usize = 3;
const PLAIN_AFTER: Duration = Duration::from_millis(1000);
const LOCAL_AFTER: Duration = Duration::from_millis(1400);
const DEADLINE: Duration = Duration::from_millis(3500);
const LOCAL_TIMEOUT: Duration = Duration::from_millis(1500);
/// TTL handed out with an answer that came over plaintext.
const PLAIN_TTL: u32 = 5;

#[derive(Default)]
pub struct DnsStats {
    pub queries: AtomicU64,
    pub hits: AtomicU64,
    pub stale: AtomicU64,
    pub misses: AtomicU64,
    pub prefetches: AtomicU64,
    pub hedges: AtomicU64,
    pub plain: AtomicU64,
    pub local: AtomicU64,
    pub failures: AtomicU64,
}

fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub struct Reply {
    pub wire: Vec<u8>,
    pub question: Option<Question>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Source {
    Doh,
    Plain,
    Local,
}

type Waiters = Vec<oneshot::Sender<Option<Arc<Entry>>>>;

pub struct Resolver {
    pub cache: Cache,
    pub doh: DohPool,
    pub local: LocalDns,
    plain: Vec<SocketAddr>,
    inflight: Mutex<HashMap<Vec<u8>, Waiters>>,
    pub stats: DnsStats,
}

struct Leader<'a> {
    r: &'a Resolver,
    key: Vec<u8>,
    result: Option<Arc<Entry>>,
}

impl Drop for Leader<'_> {
    // Also runs on cancellation, so followers are always woken.
    fn drop(&mut self) {
        let waiters = self.r.inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.key);
        for w in waiters.unwrap_or_default() {
            let _ = w.send(self.result.clone());
        }
    }
}

enum Msg {
    Doh(usize, Result<Vec<u8>, String>),
    Plain(Source, Result<Vec<u8>, String>),
}

impl Resolver {
    pub fn new(doh: DohPool, plain: Vec<SocketAddr>, local: LocalDns) -> Resolver {
        Resolver {
            cache: Cache::new(),
            doh,
            local,
            plain,
            inflight: Mutex::new(HashMap::new()),
            stats: DnsStats::default(),
        }
    }

    pub async fn answer(self: &Arc<Self>, query: &[u8]) -> Reply {
        inc(&self.stats.queries);
        if query.len() < 12 || query[2] & 0x80 != 0 {
            return Reply { wire: Vec::new(), question: None };
        }
        let q = match msg::parse_query(query) {
            Ok(q) => q,
            Err(_) => {
                let opcode = (query[2] >> 3) & 0x0F;
                let rcode = if opcode != 0 { 4 } else { 1 }; // NOTIMP / FORMERR
                return Reply { wire: msg::error_reply(query, None, rcode), question: None };
            }
        };
        let now = std::time::Instant::now();
        match self.cache.get(&q.key) {
            Lookup::Fresh { entry, prefetch } => {
                inc(&self.stats.hits);
                if prefetch {
                    inc(&self.stats.prefetches);
                    self.refresh(&q, query);
                }
                let wire = render(&entry, now, query, &q, false);
                return Reply { wire, question: Some(q) };
            }
            Lookup::Stale(entry) => {
                inc(&self.stats.stale);
                self.refresh(&q, query);
                let wire = render(&entry, now, query, &q, true);
                return Reply { wire, question: Some(q) };
            }
            Lookup::Miss => {}
        }
        inc(&self.stats.misses);
        let wire = match self.resolve_shared(&q, query).await {
            // Expired: the stale fallback after a failed refresh.
            Some(e) => {
                let now = std::time::Instant::now();
                let stale = e.age(now) >= e.ttl;
                render(&e, now, query, &q, stale)
            }
            None => msg::error_reply(query, Some(q.end), msg::RCODE_SERVFAIL),
        };
        Reply { wire, question: Some(q) }
    }

    fn refresh(self: &Arc<Self>, q: &Question, query: &[u8]) {
        let r = self.clone();
        let q = q.clone();
        let query = query.to_vec();
        tokio::spawn(async move {
            r.resolve_shared(&q, &query).await;
        });
    }

    async fn resolve_shared(&self, q: &Question, query: &[u8]) -> Option<Arc<Entry>> {
        let rx = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            match map.get_mut(&q.key) {
                Some(w) => {
                    let (tx, rx) = oneshot::channel();
                    w.push(tx);
                    Some(rx)
                }
                None => {
                    map.insert(q.key.clone(), Vec::new());
                    None
                }
            }
        };
        if let Some(rx) = rx {
            return rx.await.ok().flatten();
        }
        let mut leader = Leader { r: self, key: q.key.clone(), result: None };
        let result = self.fetch(q, query).await;
        leader.result = result.clone();
        drop(leader);
        result
    }

    async fn fetch(&self, q: &Question, query: &[u8]) -> Option<Arc<Entry>> {
        let mut wire = msg::strip_edns_options(query);
        wire[0] = 0;
        wire[1] = 0;

        if let Some(nd) = self.local.servers_for(&q.name) {
            if let Some(resp) = race_plain(&nd.servers, &wire, q, LOCAL_TIMEOUT).await {
                inc(&self.stats.local);
                vlog!("dns: {} answered by the network resolver", q.name);
                return Some(self.store(q, resp, Source::Local));
            }
        }

        match self.race(q, Bytes::from(wire)).await {
            Some((resp, src)) => Some(self.store(q, resp, src)),
            None => {
                inc(&self.stats.failures);
                log_every!("dns-fail", "dns: no upstream answered for {} (type {})", q.name, q.qtype);
                let fail = Arc::new(Entry {
                    wire: msg::error_reply(query, Some(q.end), msg::RCODE_SERVFAIL),
                    ttls: Vec::new(),
                    stored: std::time::Instant::now(),
                    ttl: cache::FAIL_TTL,
                    negative: false,
                    failure: true,
                });
                self.cache.put(q.key.clone(), fail);
                self.cache.get_any_positive(&q.key)
            }
        }
    }

    fn store(&self, q: &Question, resp: Vec<u8>, src: Source) -> Arc<Entry> {
        let now = std::time::Instant::now();
        let resp = msg::strip_edns_options(&resp);
        let Ok(r) = msg::parse_response(&resp, q) else {
            return Arc::new(Entry { wire: resp, ttls: Vec::new(), stored: now, ttl: 1, negative: false, failure: true });
        };
        let good_rcode = r.rcode == msg::RCODE_NOERROR || r.rcode == msg::RCODE_NXDOMAIN;
        let negative = r.rcode == msg::RCODE_NXDOMAIN || (r.rcode == msg::RCODE_NOERROR && r.answers == 0);
        if src == Source::Plain || !good_rcode || r.truncated {
            // Provisional: a plaintext answer may be poisoned.
            let ttls = if src == Source::Plain {
                r.ttls.iter().map(|&(o, t)| (o, t.min(PLAIN_TTL))).collect()
            } else {
                r.ttls
            };
            let e = Arc::new(Entry { wire: resp, ttls, stored: now, ttl: cache::FAIL_TTL, negative: false, failure: true });
            self.cache.put(q.key.clone(), e.clone());
            return e;
        }
        let ttl = cache::cache_ttl(r.min_ttl, negative);
        let e = Arc::new(Entry { wire: resp, ttls: r.ttls, stored: now, ttl, negative, failure: false });
        self.cache.put(q.key.clone(), e.clone());
        e
    }

    async fn race(&self, q: &Question, wire: Bytes) -> Option<(Vec<u8>, Source)> {
        let v6 = netwatch::have_global_v6();
        let ups = self.doh.ranked(v6);
        let all_parked = ups.is_empty()
            || (ups.len() == 1 && ups[0].stats().down_until.is_some_and(|t| t > std::time::Instant::now()));
        // DoH is still tried first, so recovery is noticed.
        let degraded = all_parked || self.doh.degraded(v6);
        let cap = ups.len().min(MAX_PARALLEL);
        let start = Instant::now();
        let deadline = start + DEADLINE;
        let (mut plain_at, mut local_at) = if degraded {
            (start + Duration::from_millis(150), start + Duration::from_millis(450))
        } else {
            (start + PLAIN_AFTER, start + LOCAL_AFTER)
        };
        let (tx, mut rx) = mpsc::channel::<Msg>(16);

        let mut launched = 0usize;
        let mut pending = 0usize;
        let mut doh_pending = 0usize;
        let mut next_hedge = start;
        let mut plain_launched = false;
        let mut local_launched = false;
        let mut soft: Option<(Vec<u8>, Source)> = None;

        let launch_doh = |i: usize, tx: &mpsc::Sender<Msg>| {
            let u = ups[i].clone();
            let tls = self.doh.tls().clone();
            let wire = wire.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let r = u.query(&tls, wire).await.map_err(|e| e.to_string());
                let _ = tx.send(Msg::Doh(i, r)).await;
            });
        };
        let launch_plain = |servers: Vec<SocketAddr>, src: Source, tx: &mpsc::Sender<Msg>| {
            let tx = tx.clone();
            let wire = wire.to_vec();
            let q = q.clone();
            let limit = deadline.saturating_duration_since(Instant::now());
            tokio::spawn(async move {
                let r = race_plain(&servers, &wire, &q, limit).await.ok_or_else(|| "no answer".to_string());
                let _ = tx.send(Msg::Plain(src, r)).await;
            });
        };

        loop {
            if launched < cap && Instant::now() >= next_hedge {
                if launched > 0 {
                    inc(&self.stats.hedges);
                }
                launch_doh(launched, &tx);
                launched += 1;
                pending += 1;
                doh_pending += 1;
                next_hedge = Instant::now() + ups[launched - 1].hedge_delay();
            }
            // Fallbacks are for DoH being broken, not busy.
            let doh_alive = !degraded && doh_pending > 0 && ups[..launched].iter().any(|u| u.is_connected());
            if !plain_launched && Instant::now() >= plain_at && !self.plain.is_empty() && !doh_alive {
                plain_launched = true;
                pending += 1;
                launch_plain(self.plain.clone(), Source::Plain, &tx);
            }
            if !local_launched && Instant::now() >= local_at && !doh_alive {
                local_launched = true;
                let servers = self.local.get().servers.clone();
                if !servers.is_empty() {
                    pending += 1;
                    launch_plain(servers, Source::Local, &tx);
                }
            }

            let more = launched < cap || (!plain_launched && !self.plain.is_empty()) || !local_launched;
            if pending == 0 && !more {
                break;
            }

            // A fallback held back by a live DoH attempt is re-checked shortly.
            let now = Instant::now();
            let due = |t: Instant| if t > now { t } else { now + Duration::from_millis(100) };
            let mut wake = deadline;
            if launched < cap {
                wake = wake.min(next_hedge);
            }
            if !plain_launched && !self.plain.is_empty() {
                wake = wake.min(due(plain_at));
            }
            if !local_launched {
                wake = wake.min(due(local_at));
            }

            tokio::select! {
                m = rx.recv() => {
                    let Some(m) = m else { break };
                    pending = pending.saturating_sub(1);
                    if matches!(m, Msg::Doh(..)) {
                        doh_pending = doh_pending.saturating_sub(1);
                    }
                    let (body, src, from) = match m {
                        Msg::Doh(i, r) => (r, Source::Doh, ups[i].label.clone()),
                        Msg::Plain(s, r) => (r, s, format!("{:?}", s)),
                    };
                    if let Ok(b) = body { match msg::parse_response(&b, q) {
                        Ok(r) if r.rcode == msg::RCODE_SERVFAIL || r.rcode == 5 => {
                            // SERVFAIL/REFUSED: keep in case nobody does better.
                            if soft.is_none() { soft = Some((b, src)); }
                        }
                        Ok(_) => {
                            if src != Source::Doh {
                                inc(&self.stats.plain);
                                log_every!("dns-plain", "dns: DoH unreachable; {} answered by {} resolver", q.name,
                                    if src == Source::Plain { "plaintext" } else { "the network" });
                            } else if launched > 1 {
                                vlog!("dns: {} won by {}", q.name, from);
                            }
                            return Some((b, src));
                        }
                        Err(_) => {}
                    } }
                    // Everything so far failed: start the next path now.
                    if pending == 0 {
                        if launched < cap {
                            next_hedge = Instant::now();
                        } else if !plain_launched {
                            plain_at = Instant::now();
                        } else if !local_launched {
                            local_at = Instant::now();
                        } else {
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep_until(wake) => {
                    if Instant::now() >= deadline { break; }
                }
            }
        }
        soft
    }
}

/// Ask several plain resolvers at once; first valid answer wins.
async fn race_plain(servers: &[SocketAddr], wire: &[u8], q: &Question, limit: Duration) -> Option<Vec<u8>> {
    if servers.is_empty() {
        return None;
    }
    let (tx, mut rx) = mpsc::channel(servers.len());
    for &s in servers {
        let tx = tx.clone();
        let wire = wire.to_vec();
        let q = q.clone();
        tokio::spawn(async move {
            let _ = tx.send(plain::query(s, &wire, &q, limit).await).await;
        });
    }
    drop(tx);
    let mut soft = None;
    while let Some(r) = rx.recv().await {
        if let Ok(b) = r {
            match msg::parse_response(&b, q) {
                Ok(p) if p.rcode == msg::RCODE_SERVFAIL || p.rcode == 5 => soft = soft.or(Some(b)),
                Ok(_) => return Some(b),
                Err(_) => {}
            }
        }
    }
    soft
}

fn render(e: &Entry, now: std::time::Instant, query: &[u8], q: &Question, stale: bool) -> Vec<u8> {
    let ttl_override = if stale { Some(cache::STALE_TTL) } else { None };
    msg::render(&e.wire, &e.ttls, e.age(now), ttl_override, query, q)
}
