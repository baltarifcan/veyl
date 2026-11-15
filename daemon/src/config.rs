//! Command-line configuration for `veyld serve`.

use std::net::SocketAddr;

use crate::dns::upstream::DohSpec;
use crate::proxy::desync::Strategy;

pub struct Config {
    /// Used only when not started by launchd.
    pub dns_listen: Vec<SocketAddr>,
    pub proxy_listen: Vec<SocketAddr>,
    pub doh: Vec<DohSpec>,
    pub plain_fallback: Vec<SocketAddr>,
    pub strategies: Vec<Strategy>,
    /// Hosts (and their subdomains) that are never desynced.
    pub direct: Vec<String>,
    /// Send local names to the network's own resolver.
    pub local_forward: bool,
    pub workers: usize,
}

/// Literal IPs, providers interleaved so hedges take independent paths.
pub const DEFAULT_DOH: &[&str] = &[
    "1.1.1.1#cloudflare-dns.com",
    "8.8.8.8#dns.google",
    "1.0.0.1#cloudflare-dns.com",
    "8.8.4.4#dns.google",
    "[2606:4700:4700::1111]#cloudflare-dns.com",
    "[2001:4860:4860::8888]#dns.google",
];

/// Used only while DoH is unreachable; their answers are not cached.
pub const DEFAULT_PLAIN: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

/// Tried in order; "none" first so unblocked hosts are never touched.
pub const DEFAULT_STRATEGIES: &[&str] = &[
    "none",
    "split:1",
    "tlsrec:sni+1,split:1",
    "oob:2",
    "split:2,oob:2",
];

pub fn usage() -> ! {
    eprintln!(
        "usage:
  veyld serve [options]
      --dns ADDR           DNS listen address (default 127.0.0.1:53; ignored under launchd)
      --proxy ADDR         SOCKS5/4 + HTTP CONNECT listen address, repeatable
                           (default 127.0.0.1:1080 and 127.0.0.1:1085; ignored under launchd)
      --doh IP#NAME        DoH upstream, repeatable (replaces the defaults)
      --plain ADDR         plaintext emergency resolver, repeatable (replaces the defaults)
      --strategy SPEC      desync strategy, repeatable, tried in order (replaces the defaults)
      --direct HOST[,..]   never desync these hosts or their subdomains
      --no-local-forward   send local names to DoH too
      --workers N          runtime threads (default: min(4, cores))
      --verbose            log every connection and lookup
  veyld env-agent --state FILE --url URL [--no-proxy LIST] [--probe ADDR]
  veyld version"
    );
    std::process::exit(2)
}

impl Config {
    pub fn parse(args: &[String]) -> Result<Config, String> {
        let mut dns_listen = Vec::new();
        let mut proxy_listen = Vec::new();
        let mut doh = Vec::new();
        let mut plain = Vec::new();
        let mut strategies = Vec::new();
        let mut direct = Vec::new();
        let mut local_forward = true;
        let mut workers = 0usize;

        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = |name: &str| -> Result<String, String> {
                it.next().cloned().ok_or_else(|| format!("{} needs a value", name))
            };
            match a.as_str() {
                "--dns" => dns_listen.push(parse_addr(&val("--dns")?)?),
                "--proxy" => proxy_listen.push(parse_addr(&val("--proxy")?)?),
                "--doh" => doh.push(DohSpec::parse(&val("--doh")?)?),
                "--plain" => plain.push(parse_addr(&val("--plain")?)?),
                "--strategy" => strategies.push(Strategy::parse(&val("--strategy")?)?),
                "--direct" => {
                    for h in val("--direct")?.split(',') {
                        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
                        if !h.is_empty() {
                            direct.push(h);
                        }
                    }
                }
                "--no-local-forward" => local_forward = false,
                "--workers" => {
                    workers = val("--workers")?.parse().map_err(|_| "bad --workers".to_string())?
                }
                "--verbose" | "-v" => {
                    crate::log::VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed)
                }
                "-h" | "--help" => usage(),
                other => return Err(format!("unknown option {}", other)),
            }
        }

        if dns_listen.is_empty() {
            dns_listen.push("127.0.0.1:53".parse().unwrap());
        }
        if proxy_listen.is_empty() {
            proxy_listen.push("127.0.0.1:1080".parse().unwrap());
            proxy_listen.push("127.0.0.1:1085".parse().unwrap());
        }
        if doh.is_empty() {
            for s in DEFAULT_DOH {
                doh.push(DohSpec::parse(s)?);
            }
        }
        if plain.is_empty() {
            for s in DEFAULT_PLAIN {
                plain.push(parse_addr(s)?);
            }
        }
        if strategies.is_empty() {
            for s in DEFAULT_STRATEGIES {
                strategies.push(Strategy::parse(s)?);
            }
        }
        if workers == 0 {
            let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
            workers = cores.clamp(2, 4);
        }
        Ok(Config {
            dns_listen,
            proxy_listen,
            doh,
            plain_fallback: plain,
            strategies,
            direct,
            local_forward,
            workers,
        })
    }
}

pub fn parse_addr(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>().map_err(|_| format!("bad address {:?} (want IP:PORT or [IPv6]:PORT)", s))
}
