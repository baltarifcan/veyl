//! veyld: DoH resolver and auto-desync proxy.

mod config;
mod dns;
mod envagent;
mod launchd;
#[macro_use]
mod log;
mod netwatch;
mod proxy;

use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use config::Config;
use launchd::Activation;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve(&args[2..]),
        Some("env-agent") => envagent::run(&args[2..]),
        Some("version") | Some("--version") => println!("veyld {}", env!("CARGO_PKG_VERSION")),
        _ => config::usage(),
    }
}

/// Returns the soft limit in effect afterwards.
fn raise_nofile() -> u64 {
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            return 0;
        }
        // The kernel's per-process ceiling varies, so step down until one fits.
        for want in [65_536u64, 24_576, 10_240] {
            let target = want.min(rl.rlim_max as u64);
            if target <= rl.rlim_cur as u64 {
                break;
            }
            let new = libc::rlimit { rlim_cur: target as libc::rlim_t, rlim_max: rl.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &new) == 0 {
                break;
            }
        }
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        rl.rlim_cur as u64
    }
}

fn serve(args: &[String]) {
    let cfg = Config::parse(args).unwrap_or_else(|e| {
        eprintln!("veyld: {}", e);
        std::process::exit(2)
    });
    let nofile = raise_nofile();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.workers)
        .max_blocking_threads(256)
        .thread_name("veyld")
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(e) = rt.block_on(run(cfg, nofile)) {
        log!("fatal: {}", e);
        std::process::exit(1);
    }
}

/// Off the blocking pool, so it never queues behind proxy lookups.
fn refresh_local(r: &Arc<dns::resolver::Resolver>) {
    let r = r.clone();
    let _ = std::thread::Builder::new().name("netdns".into()).spawn(move || r.local.refresh());
}

fn std_udp(fd: i32) -> std::io::Result<tokio::net::UdpSocket> {
    let s = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    s.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(s)
}

fn std_tcp(fd: i32) -> std::io::Result<tokio::net::TcpListener> {
    let s = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    s.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(s)
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let s = if addr.is_ipv6() { tokio::net::TcpSocket::new_v6()? } else { tokio::net::TcpSocket::new_v4()? };
    s.set_reuseaddr(true)?;
    s.set_nodelay(true)?;
    s.bind(addr)?;
    s.listen(4096)
}

async fn run(cfg: Config, nofile: u64) -> Result<(), String> {
    let e = |what: &str| { let what = what.to_string(); move |err: std::io::Error| format!("{}: {}", what, err) };

    // From launchd when it manages us, otherwise bound here.
    let mut udp = Vec::new();
    let mut dns_tcp = Vec::new();
    let mut proxy_l = Vec::new();
    let mut managed = false;
    if let Activation::Fds(fds) = launchd::activate("dns-udp").map_err(e("launchd dns-udp"))? {
        managed = true;
        for fd in fds {
            udp.push(std_udp(fd).map_err(e("dns-udp socket"))?);
        }
    }
    if let Activation::Fds(fds) = launchd::activate("dns-tcp").map_err(e("launchd dns-tcp"))? {
        managed = true;
        for fd in fds {
            dns_tcp.push(std_tcp(fd).map_err(e("dns-tcp socket"))?);
        }
    }
    if let Activation::Fds(fds) = launchd::activate("proxy").map_err(e("launchd proxy"))? {
        managed = true;
        for fd in fds {
            proxy_l.push(std_tcp(fd).map_err(e("proxy socket"))?);
        }
    }
    if !managed {
        for &a in &cfg.dns_listen {
            udp.push(tokio::net::UdpSocket::bind(a).await.map_err(e(&format!("bind udp {}", a)))?);
            dns_tcp.push(bind_tcp(a).map_err(e(&format!("bind tcp {}", a)))?);
        }
        for &a in &cfg.proxy_listen {
            proxy_l.push(bind_tcp(a).map_err(e(&format!("bind tcp {}", a)))?);
        }
    }

    let pool = dns::upstream::DohPool::new(&cfg.doh)?;
    let local = dns::local::LocalDns::new(cfg.local_forward);
    let resolver = Arc::new(dns::resolver::Resolver::new(pool, cfg.plain_fallback.clone(), local));
    let px = Arc::new(proxy::Proxy {
        book: proxy::book::Book::new(cfg.strategies.clone(), cfg.direct.clone()),
        stats: Default::default(),
        started: Instant::now(),
        resolver: resolver.clone(),
    });

    refresh_local(&resolver);
    let mut net = netwatch::start();
    resolver.doh.warm(netwatch::have_global_v6()).await;

    for s in udp {
        tokio::spawn(dns::serve_udp(s, resolver.clone()));
    }
    for l in dns_tcp {
        tokio::spawn(dns::serve_tcp(l, resolver.clone()));
    }
    let nproxy = proxy_l.len();
    for l in proxy_l {
        tokio::spawn(proxy::serve(l, px.clone()));
    }

    let r = resolver.clone();
    tokio::spawn(async move {
        while net.changed().await.is_ok() {
            let addrs = netwatch::local_addrs();
            r.doh.on_network_change(&addrs);
            r.cache.forget_failures();
            refresh_local(&r);
            r.doh.warm(netwatch::have_global_v6()).await;
        }
    });

    let r = resolver.clone();
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            tick += 1;
            r.cache.sweep();
            if tick.is_multiple_of(5) {
                refresh_local(&r);
            }
        }
    });

    dns::upstream::log_startup(&resolver.doh);
    let names: Vec<&str> = px.book.strategies.iter().map(|s| s.name.as_str()).collect();
    log!(
        "veyld {} ready ({}): dns {}, proxy {} listener(s), strategies [{}], {} worker threads, fd limit {}",
        env!("CARGO_PKG_VERSION"),
        if managed { "launchd sockets" } else { "self-bound" },
        if managed { "launchd".to_string() } else { format!("{:?}", cfg.dns_listen) },
        nproxy,
        names.join(" | "),
        cfg.workers,
        nofile
    );

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    log!("stopping");
    Ok(())
}
