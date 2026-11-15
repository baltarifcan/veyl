pub mod book;
pub mod connect;
pub mod desync;
pub mod handshake;
pub mod inspect;
pub mod session;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::dns::resolver::Resolver;
use book::Book;
use handshake::{Failure, Host, Incoming};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct ProxyStats {
    pub total: AtomicU64,
    pub active: AtomicU64,
    pub desynced: AtomicU64,
    pub interfered: AtomicU64,
    pub rescued: AtomicU64,
    pub failed: AtomicU64,
    pub connect_errors: AtomicU64,
}

pub struct Proxy {
    pub book: Book,
    pub stats: ProxyStats,
    pub started: Instant,
    pub resolver: Arc<Resolver>,
}

struct Active<'a>(&'a AtomicU64);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn serve(listener: TcpListener, px: Arc<Proxy>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let px = px.clone();
                tokio::spawn(async move { handle(px, stream).await });
            }
            Err(e) => {
                log_every!("proxy-accept", "proxy: accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle(px: Arc<Proxy>, mut client: TcpStream) {
    px.stats.total.fetch_add(1, Ordering::Relaxed);
    px.stats.active.fetch_add(1, Ordering::Relaxed);
    let _active = Active(&px.stats.active);
    let _ = client.set_nodelay(true);

    let req = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake::read(&mut client)).await {
        Ok(Ok(Incoming::Tunnel(r))) => r,
        Ok(Ok(Incoming::Status)) => {
            let body = status(&px);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = client.write_all(resp.as_bytes()).await;
            return;
        }
        _ => return,
    };

    let addrs = match &req.host {
        Host::Ip(ip) => vec![std::net::SocketAddr::new(*ip, req.port)],
        Host::Name(n) => match connect::resolve(n, req.port).await {
            Ok(a) => a,
            Err(e) => {
                vlog!("proxy: resolve {}: {}", n, e);
                px.stats.connect_errors.fetch_add(1, Ordering::Relaxed);
                let _ = handshake::reply_err(&mut client, req.proto, Failure::HostUnreachable).await;
                return;
            }
        },
    };
    let remote = match connect::connect_any(&addrs, CONNECT_TIMEOUT).await {
        Ok(c) => c,
        Err(e) => {
            vlog!("proxy: connect {}:{}: {}", req.host.display(), req.port, e);
            px.stats.connect_errors.fetch_add(1, Ordering::Relaxed);
            let _ = handshake::reply_err(&mut client, req.proto, Failure::from_io(&e)).await;
            return;
        }
    };
    if handshake::reply_ok(&mut client, req.proto).await.is_err() {
        return;
    }
    session::run(px.clone(), client, remote, addrs, req.host.display(), req.early).await;
}

fn status(px: &Proxy) -> String {
    let r = &px.resolver;
    let d = &r.stats;
    let p = &px.stats;
    let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let up = px.started.elapsed().as_secs();
    let mut s = format!(
        "veyld {}  up {}h{:02}m\n\n\
         dns   queries={} hits={} stale={} misses={} prefetches={} hedges={} plaintext={} local={} failures={} cached={} dropped={}\n",
        env!("CARGO_PKG_VERSION"),
        up / 3600,
        (up / 60) % 60,
        g(&d.queries),
        g(&d.hits),
        g(&d.stale),
        g(&d.misses),
        g(&d.prefetches),
        g(&d.hedges),
        g(&d.plain),
        g(&d.local),
        g(&d.failures),
        r.cache.len(),
        crate::dns::UDP_DROPPED.load(Ordering::Relaxed),
    );
    s.push_str(&r.doh.describe());
    let nd = r.local.get();
    s.push_str(&format!("  network resolvers: {:?}  domains: {:?}\n", nd.servers, nd.domains));
    s.push_str(&format!(
        "\nproxy connections={} active={} desynced={} interfered={} rescued={} failed={} connect_errors={}\n",
        g(&p.total),
        g(&p.active),
        g(&p.desynced),
        g(&p.interfered),
        g(&p.rescued),
        g(&p.failed),
        g(&p.connect_errors),
    ));
    let entries = px.book.entries();
    if entries.is_empty() {
        s.push_str("  no host has needed a desync yet\n");
    }
    for (h, st) in entries {
        s.push_str(&format!("  {:<40} {}\n", h, st));
    }
    s
}
