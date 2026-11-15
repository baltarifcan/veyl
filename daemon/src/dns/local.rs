//! Router-local names and private reverse zones go to the network's own
//! (DHCP) resolver; nothing else does, since that is the one that sinkholes.

use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::io::Write;
use std::sync::{Arc, RwLock};

use crate::vlog;

#[derive(Default, Debug)]
pub struct NetworkDns {
    pub servers: Vec<SocketAddr>,
    pub domains: Vec<String>,
}

const LOCAL_SUFFIXES: &[&str] = &[
    "lan",
    "home",
    "home.arpa",
    "internal",
    "localdomain",
    "intranet",
    "corp",
    "private",
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "c.f.ip6.arpa",
    "d.f.ip6.arpa",
];

pub struct LocalDns {
    current: RwLock<Arc<NetworkDns>>,
    enabled: bool,
}

impl LocalDns {
    /// Starts empty; refresh() (blocking) populates it.
    pub fn new(enabled: bool) -> LocalDns {
        LocalDns { current: RwLock::new(Arc::new(NetworkDns::default())), enabled }
    }

    pub fn get(&self) -> Arc<NetworkDns> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn refresh(&self) {
        if !self.enabled {
            return;
        }
        let nd = read_network_dns();
        vlog!("dns: network resolvers {:?}, domains {:?}", nd.servers, nd.domains);
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(nd);
    }

    pub fn servers_for(&self, name: &str) -> Option<Arc<NetworkDns>> {
        if !self.enabled || name.is_empty() {
            return None;
        }
        let nd = self.get();
        if nd.servers.is_empty() {
            return None;
        }
        let local = !name.contains('.')
            || LOCAL_SUFFIXES.iter().any(|s| has_suffix(name, s))
            || is_private_172(name)
            || nd.domains.iter().any(|d| has_suffix(name, d));
        if local { Some(nd) } else { None }
    }
}

fn has_suffix(name: &str, suffix: &str) -> bool {
    name == suffix || (name.len() > suffix.len() && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// 16.172.in-addr.arpa through 31.172.in-addr.arpa.
fn is_private_172(name: &str) -> bool {
    (16..=31).any(|n| has_suffix(name, &format!("{}.172.in-addr.arpa", n)))
}

fn scutil(cmd: &str) -> String {
    let child = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return String::new() };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(cmd.as_bytes());
    }
    // Read on a helper thread so a wedged scutil can be killed.
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        if let Some(s) = stdout.as_mut() {
            let _ = std::io::Read::read_to_string(s, &mut out);
        }
        out
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
    reader.join().unwrap_or_default()
}

fn scalar(out: &str, key: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (k, v) = l.trim().split_once(" : ")?;
        (k == key).then(|| v.trim().to_string())
    })
}

fn array(out: &str, key: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut inside = false;
    for l in out.lines() {
        let t = l.trim();
        if !inside {
            if t.starts_with(&format!("{} : <array>", key)) {
                inside = true;
            }
            continue;
        }
        if t == "}" {
            break;
        }
        if let Some((_, v)) = t.split_once(" : ") {
            items.push(v.trim().to_string());
        }
    }
    items
}

/// The primary service's State: DNS, which keeps the DHCP servers while
/// Setup: overrides them with 127.0.0.1.
pub fn read_network_dns() -> NetworkDns {
    let global = scutil("show State:/Network/Global/IPv4\n");
    let Some(service) = scalar(&global, "PrimaryService") else { return NetworkDns::default() };
    if !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return NetworkDns::default();
    }
    let dns = scutil(&format!("show State:/Network/Service/{}/DNS\n", service));
    let servers = array(&dns, "ServerAddresses")
        .iter()
        // Skip scoped link-local addresses.
        .filter(|s| !s.contains('%'))
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    let mut domains: Vec<String> = array(&dns, "SearchDomains");
    if let Some(d) = scalar(&dns, "DomainName") {
        domains.push(d);
    }
    let domains = domains
        .into_iter()
        .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    NetworkDns { servers, domains }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matching() {
        assert!(has_suffix("printer.lan", "lan"));
        assert!(has_suffix("lan", "lan"));
        assert!(!has_suffix("plan", "lan"));
        assert!(is_private_172("1.0.20.172.in-addr.arpa"));
        assert!(!is_private_172("1.0.15.172.in-addr.arpa"));
    }

    #[test]
    fn scutil_parsing() {
        let out = "<dictionary> {\n  DomainName : home\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n    1 : fe80::1%en0\n  }\n}\n";
        assert_eq!(scalar(out, "DomainName").as_deref(), Some("home"));
        assert_eq!(array(out, "ServerAddresses"), vec!["192.168.1.1", "fe80::1%en0"]);
    }
}
