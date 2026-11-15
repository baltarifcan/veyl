//! DoH upstreams: one persistent HTTP/2 connection each, pinged when idle,
//! rechecked on network change, dropped on error.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{watch, Notify};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::{log, log_every, vlog};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
const TLS_TIMEOUT: Duration = Duration::from_millis(2500);
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(3000);
const KEEPALIVE: Duration = Duration::from_secs(15);
const PING_TIMEOUT: Duration = Duration::from_millis(2000);
const IDLE_CLOSE: Duration = Duration::from_secs(1800);
const INITIAL_SRTT_MS: f64 = 120.0;

fn clock() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

#[derive(Clone, Debug)]
pub struct DohSpec {
    pub addr: SocketAddr,
    /// TLS name and :authority; an IP literal sends no SNI.
    pub name: String,
    pub path: String,
}

impl DohSpec {
    /// `IP[#NAME[/PATH]]`, IP being `1.2.3.4`, `1.2.3.4:443`, `[::1]` or `[::1]:443`.
    pub fn parse(s: &str) -> Result<DohSpec, String> {
        let (addr_s, rest) = match s.split_once('#') {
            Some((a, r)) => (a, Some(r)),
            None => (s, None),
        };
        let addr: SocketAddr = if let Ok(a) = addr_s.parse::<SocketAddr>() {
            a
        } else if let Ok(ip) = addr_s.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() {
            SocketAddr::new(ip, 443)
        } else {
            return Err(format!("bad DoH upstream address in {:?}", s));
        };
        let (name, path) = match rest {
            Some(r) => match r.find('/') {
                Some(i) => (r[..i].to_string(), r[i..].to_string()),
                None => (r.to_string(), "/dns-query".to_string()),
            },
            None => (addr.ip().to_string(), "/dns-query".to_string()),
        };
        if name.is_empty() {
            return Err(format!("empty DoH name in {:?}", s));
        }
        Ok(DohSpec { addr, name, path })
    }
}

#[derive(Clone)]
struct Conn {
    send: SendRequest<Bytes>,
    alive: Arc<AtomicBool>,
    /// So one connection dying under many queries counts as one failure.
    failed: Arc<AtomicBool>,
    local_ip: IpAddr,
    check: Arc<Notify>,
}

type ConnectResult = Option<Result<Conn, String>>;

enum Slot {
    Idle,
    /// A connect in its own task, shared by every waiting query.
    Connecting(watch::Receiver<ConnectResult>),
    Ready(Conn),
}

#[derive(Clone, Copy)]
pub struct Stats {
    pub srtt_ms: f64,
    pub fails: u32,
    pub down_until: Option<Instant>,
    pub queries: u64,
    pub errors: u64,
}

pub struct Upstream {
    pub label: String,
    pub provider: String,
    tls_name: ServerName<'static>,
    uri: http::Uri,
    addr: SocketAddr,
    slot: StdMutex<Slot>,
    last_used: Arc<AtomicU64>,
    stats: StdMutex<Stats>,
}

#[derive(Debug)]
pub enum QueryError {
    Connect(String),
    Exchange { msg: String, conn_dead: bool },
    Status(u16),
    Timeout,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryError::Connect(e) => write!(f, "connect: {}", e),
            QueryError::Exchange { msg, .. } => write!(f, "{}", msg),
            QueryError::Status(s) => write!(f, "HTTP {}", s),
            QueryError::Timeout => write!(f, "timed out"),
        }
    }
}

impl Upstream {
    fn new(spec: &DohSpec) -> Result<Upstream, String> {
        let tls_name = match spec.name.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => ServerName::try_from(spec.name.clone()).map_err(|e| format!("{}: {}", spec.name, e))?,
        };
        let host = if spec.name.contains(':') { format!("[{}]", spec.name) } else { spec.name.clone() };
        let uri: http::Uri = format!("https://{}{}", host, spec.path).parse().map_err(|e| format!("{}", e))?;
        let provider = {
            let labels: Vec<&str> = spec.name.split('.').collect();
            if spec.name.parse::<IpAddr>().is_ok() || labels.len() < 2 {
                spec.name.clone()
            } else {
                labels[labels.len() - 2..].join(".")
            }
        };
        Ok(Upstream {
            label: format!("{}({})", spec.addr.ip(), spec.name),
            provider,
            tls_name,
            uri,
            addr: spec.addr,
            slot: StdMutex::new(Slot::Idle),
            last_used: Arc::new(AtomicU64::new(0)),
            stats: StdMutex::new(Stats {
                srtt_ms: INITIAL_SRTT_MS,
                fails: 0,
                down_until: None,
                queries: 0,
                errors: 0,
            }),
        })
    }

    pub fn stats(&self) -> Stats {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_connected(&self) -> bool {
        matches!(&*self.slot(), Slot::Ready(c) if c.alive.load(Ordering::Relaxed))
    }

    pub fn is_v6(&self) -> bool {
        self.addr.is_ipv6()
    }

    fn usable(&self, now: Instant) -> bool {
        self.stats().down_until.is_none_or(|t| now >= t)
    }

    fn score(&self) -> f64 {
        let s = self.stats();
        let mut score = s.srtt_ms + s.fails as f64 * 150.0;
        if !self.is_connected() {
            score += s.srtt_ms * 2.0;
        }
        score
    }

    fn record_ok(&self, rtt: Duration) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let sample = rtt.as_secs_f64() * 1000.0;
        s.srtt_ms = s.srtt_ms * 0.75 + sample * 0.25;
        s.fails = 0;
        s.down_until = None;
        s.queries += 1;
    }

    fn record_fail(&self) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        s.queries += 1;
        s.errors += 1;
        s.fails = s.fails.saturating_add(1);
        // Park after two in a row, backing off up to a minute.
        if s.fails >= 2 {
            let secs = (2u64 << (s.fails - 2).min(5)).min(60);
            s.down_until = Some(Instant::now() + Duration::from_secs(secs));
        }
        s.srtt_ms = (s.srtt_ms * 1.5).min(3000.0);
    }

    /// An error already counted for this connection.
    fn count_error(&self) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        s.queries += 1;
        s.errors += 1;
    }

    fn reset_failures(&self) {
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        s.fails = 0;
        s.down_until = None;
    }

    pub fn hedge_delay(&self) -> Duration {
        if !self.is_connected() {
            return Duration::ZERO;
        }
        let ms = (self.stats().srtt_ms * 1.3 + 25.0).clamp(60.0, 400.0);
        Duration::from_millis(ms as u64)
    }

    async fn get_conn(self: &Arc<Self>, tls: &TlsConnector) -> Result<Conn, QueryError> {
        let mut rx = {
            let mut slot = self.slot();
            match &*slot {
                Slot::Ready(c) if c.alive.load(Ordering::Relaxed) => return Ok(c.clone()),
                // Errs only if the connect task died without reporting.
                Slot::Connecting(rx) if rx.has_changed().is_ok() => rx.clone(),
                _ => {
                    let (tx, rx) = watch::channel(None);
                    *slot = Slot::Connecting(rx.clone());
                    let me = self.clone();
                    let tls = tls.clone();
                    tokio::spawn(async move { me.connect_task(tls, tx).await });
                    rx
                }
            }
        };
        let r = rx
            .wait_for(|v| v.is_some())
            .await
            .map_err(|_| QueryError::Connect("connect task vanished".into()))?;
        match r.as_ref() {
            Some(Ok(c)) => Ok(c.clone()),
            Some(Err(e)) => Err(QueryError::Connect(e.clone())),
            None => Err(QueryError::Connect("no result".into())),
        }
    }

    /// Not tied to any query, so one giving up cancels nothing.
    async fn connect_task(self: Arc<Self>, tls: TlsConnector, tx: watch::Sender<ConnectResult>) {
        let r = self.connect(&tls).await;
        *self.slot() = match &r {
            Ok(c) => Slot::Ready(c.clone()),
            Err(_) => Slot::Idle,
        };
        if let Err(e) = &r {
            self.record_fail();
            log_every!("doh-connect", "dns: cannot connect to {}: {}", self.label, e);
        }
        let _ = tx.send(Some(r));
    }

    async fn connect(&self, tls: &TlsConnector) -> Result<Conn, String> {
        let t0 = Instant::now();
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| "tcp connect timed out".to_string())?
            .map_err(|e| e.to_string())?;
        let _ = tcp.set_nodelay(true);
        let local_ip = tcp.local_addr().map_err(|e| e.to_string())?.ip();
        let stream = timeout(TLS_TIMEOUT, tls.connect(self.tls_name.clone(), tcp))
            .await
            .map_err(|_| "TLS handshake timed out".to_string())?
            .map_err(|e| format!("TLS: {}", e))?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("server did not negotiate HTTP/2".into());
        }
        let (send, mut connection) = timeout(
            TLS_TIMEOUT,
            h2::client::Builder::new()
                .enable_push(false)
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(1024 * 1024)
                .handshake::<_, Bytes>(stream),
        )
        .await
        .map_err(|_| "h2 handshake timed out".to_string())?
        .map_err(|e| format!("h2 handshake: {}", e))?;
        let ping = connection.ping_pong().ok_or("no h2 ping handle")?;
        let alive = Arc::new(AtomicBool::new(true));
        let check = Arc::new(Notify::new());

        let a = alive.clone();
        let label = self.label.clone();
        let driver = tokio::spawn(async move {
            if let Err(e) = connection.await {
                vlog!("dns: {} connection closed: {}", label, e);
            }
            a.store(false, Ordering::Relaxed);
        });
        tokio::spawn(keepalive(
            ping,
            alive.clone(),
            check.clone(),
            self.last_used.clone(),
            driver.abort_handle(),
            self.label.clone(),
        ));
        vlog!("dns: connected to {} in {}ms", self.label, t0.elapsed().as_millis());
        Ok(Conn { send, alive, failed: Arc::new(AtomicBool::new(false)), local_ip, check })
    }

    /// Retire `c` only; the slot may already hold a newer connection.
    fn kill(&self, c: &Conn) {
        c.alive.store(false, Ordering::Relaxed);
        c.check.notify_one(); // wakes the keepalive so it aborts the driver
        let mut slot = self.slot();
        if let Slot::Ready(cur) = &*slot {
            if Arc::ptr_eq(&cur.alive, &c.alive) {
                *slot = Slot::Idle;
            }
        }
    }

    /// One DoH exchange. `wire` must carry transaction ID 0 (RFC 8484).
    pub async fn query(self: &Arc<Self>, tls: &TlsConnector, wire: Bytes) -> Result<Vec<u8>, QueryError> {
        self.last_used.store(clock(), Ordering::Relaxed);
        let deadline = tokio::time::Instant::now() + ATTEMPT_TIMEOUT;
        let c = match tokio::time::timeout_at(deadline, self.get_conn(tls)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(QueryError::Timeout),
        };
        match tokio::time::timeout_at(deadline, exchange(c.send.clone(), self.uri.clone(), wire)).await {
            Ok(Ok((body, rtt))) => {
                c.failed.store(false, Ordering::Relaxed);
                self.record_ok(rtt);
                Ok(body)
            }
            Ok(Err(e)) => {
                // A 4xx is about the query, not the upstream.
                let health = !matches!(e, QueryError::Status(s) if s < 500);
                if health && !c.failed.swap(true, Ordering::Relaxed) {
                    self.record_fail();
                } else {
                    self.count_error();
                }
                if matches!(e, QueryError::Exchange { conn_dead: true, .. }) {
                    self.kill(&c);
                }
                log_every!("doh-fail", "dns: {} failed: {}", self.label, e);
                Err(e)
            }
            Err(_) => {
                if !c.failed.swap(true, Ordering::Relaxed) {
                    self.record_fail();
                } else {
                    self.count_error();
                }
                // Maybe it died silently; ping it.
                c.check.notify_one();
                log_every!("doh-timeout", "dns: {} timed out", self.label);
                Err(QueryError::Timeout)
            }
        }
    }

    /// Drop the connection if its source address is gone, else ping it.
    fn revalidate(&self, local: &[IpAddr]) {
        self.reset_failures();
        let mut slot = self.slot();
        if let Slot::Ready(c) = &*slot {
            c.check.notify_one();
            if !local.contains(&c.local_ip) {
                vlog!("dns: {} source address is gone; reconnecting", self.label);
                c.alive.store(false, Ordering::Relaxed);
                *slot = Slot::Idle;
            }
        }
    }
}

/// The round trip is timed from sending, excluding local stream queueing.
async fn exchange(send: SendRequest<Bytes>, uri: http::Uri, wire: Bytes) -> Result<(Vec<u8>, Duration), QueryError> {
    // Only a stream reset leaves the connection usable.
    let ex = |e: h2::Error| QueryError::Exchange { conn_dead: !(e.is_reset() && !e.is_go_away()), msg: e.to_string() };
    let mut send = send.ready().await.map_err(ex)?;
    let req = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", wire.len())
        .body(())
        .map_err(|e| QueryError::Exchange { msg: e.to_string(), conn_dead: false })?;
    let sent = Instant::now();
    let (resp, mut body_tx) = send.send_request(req, false).map_err(ex)?;
    body_tx.send_data(wire, true).map_err(ex)?;
    let resp = resp.await.map_err(ex)?;
    if resp.status() != http::StatusCode::OK {
        return Err(QueryError::Status(resp.status().as_u16()));
    }
    let mut body = resp.into_body();
    let mut out = Vec::with_capacity(512);
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(ex)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        if out.len() > 65_535 {
            return Err(QueryError::Exchange { msg: "oversized response".into(), conn_dead: false });
        }
    }
    Ok((out, sent.elapsed()))
}

async fn keepalive(
    mut ping: h2::PingPong,
    alive: Arc<AtomicBool>,
    check: Arc<Notify>,
    last_used: Arc<AtomicU64>,
    driver: tokio::task::AbortHandle,
    label: String,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(KEEPALIVE) => {
                let idle = clock().saturating_sub(last_used.load(Ordering::Relaxed));
                if idle > IDLE_CLOSE.as_millis() as u64 {
                    vlog!("dns: closing idle connection to {}", label);
                    break;
                }
            }
            _ = check.notified() => {}
        }
        if !alive.load(Ordering::Relaxed) {
            break;
        }
        match timeout(PING_TIMEOUT, ping.ping(h2::Ping::opaque())).await {
            Ok(Ok(_)) => {}
            _ => {
                log_every!("doh-ping", "dns: {} stopped answering pings; dropping the connection", label);
                break;
            }
        }
    }
    alive.store(false, Ordering::Relaxed);
    driver.abort();
}

pub struct DohPool {
    pub upstreams: Vec<Arc<Upstream>>,
    tls: TlsConnector,
}

impl DohPool {
    pub fn new(specs: &[DohSpec]) -> Result<DohPool, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Not the system verifier: it may fetch OCSP, which needs DNS (us).
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let mut upstreams = Vec::new();
        for s in specs {
            upstreams.push(Arc::new(Upstream::new(s)?));
        }
        Ok(DohPool { upstreams, tls: TlsConnector::from(Arc::new(cfg)) })
    }

    pub fn tls(&self) -> &TlsConnector {
        &self.tls
    }

    /// Best first, then the best of another provider, then the rest.
    pub fn ranked(&self, v6_ok: bool) -> Vec<Arc<Upstream>> {
        let now = Instant::now();
        let mut usable: Vec<(f64, usize, &Arc<Upstream>)> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, u)| u.usable(now) && (v6_ok || !u.is_v6()))
            .map(|(i, u)| (u.score(), i, u))
            .collect();
        if usable.is_empty() {
            // All parked: probe whichever leaves cooldown first.
            return self
                .upstreams
                .iter()
                .filter(|u| v6_ok || !u.is_v6())
                .min_by_key(|u| u.stats().down_until)
                .cloned()
                .into_iter()
                .collect();
        }
        usable.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
        let mut out: Vec<Arc<Upstream>> = usable.iter().map(|x| x.2.clone()).collect();
        if out.len() > 2 && out[1].provider == out[0].provider {
            if let Some(j) = (2..out.len()).find(|&j| out[j].provider != out[0].provider) {
                let u = out.remove(j);
                out.insert(1, u);
            }
        }
        out
    }

    /// Nothing connected and the best candidates failing: DoH is out.
    pub fn degraded(&self, v6_ok: bool) -> bool {
        let ranked = self.ranked(v6_ok);
        !ranked.iter().any(|u| u.is_connected()) && ranked.iter().take(2).all(|u| u.stats().fails > 0)
    }

    pub fn on_network_change(&self, local: &[IpAddr]) {
        for u in &self.upstreams {
            u.revalidate(local);
        }
    }

    pub async fn warm(&self, v6_ok: bool) {
        for u in self.ranked(v6_ok).into_iter().take(2) {
            let tls = self.tls.clone();
            tokio::spawn(async move {
                let _ = u.get_conn(&tls).await; // failures are logged by the connect task
            });
        }
    }

    pub fn describe(&self) -> String {
        let mut s = String::new();
        for u in &self.upstreams {
            let st = u.stats();
            let down = st.down_until.map_or(String::new(), |t| {
                let now = Instant::now();
                if t > now { format!(" parked {}s", (t - now).as_secs() + 1) } else { String::new() }
            });
            s.push_str(&format!(
                "  {:<40} {} srtt={:.0}ms queries={} errors={}{}\n",
                u.label,
                if u.is_connected() { "connected" } else { "idle     " },
                st.srtt_ms,
                st.queries,
                st.errors,
                down
            ));
        }
        s
    }
}

pub fn log_startup(pool: &DohPool) {
    let names: Vec<&str> = pool.upstreams.iter().map(|u| u.label.as_str()).collect();
    log!("dns: DoH upstreams: {}", names.join(", "));
}
