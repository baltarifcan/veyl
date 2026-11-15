//! `veyld env-agent`: publish HTTPS_PROXY to the user's launchd domain while
//! veyl is on and the proxy is accepting, for clients that ignore the system
//! SOCKS setting.

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

const LAUNCHCTL: &str = "/bin/launchctl";
const PROXY_VARS: &[&str] = &["HTTPS_PROXY", "https_proxy"];
const NO_PROXY_VARS: &[&str] = &["NO_PROXY", "no_proxy"];
const STATE_POLL: Duration = Duration::from_millis(500);
const PROBE_EVERY: Duration = Duration::from_secs(5);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn say(msg: &str) {
    crate::log::emit(&format!("env-agent: {}", msg));
}

fn launchctl(args: &[&str]) {
    match Command::new(LAUNCHCTL).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => say(&format!("launchctl {} exited {}", args.join(" "), s)),
        Err(e) => say(&format!("launchctl {}: {}", args.join(" "), e)),
    }
}

fn publish(url: &str, no_proxy: &str) {
    for v in PROXY_VARS {
        launchctl(&["setenv", v, url]);
    }
    if !no_proxy.is_empty() {
        for v in NO_PROXY_VARS {
            launchctl(&["setenv", v, no_proxy]);
        }
    }
}

fn withdraw() {
    for v in PROXY_VARS.iter().chain(NO_PROXY_VARS) {
        launchctl(&["unsetenv", v]);
    }
}

fn state_on(path: &str) -> bool {
    match std::fs::read_to_string(path) {
        Ok(s) => matches!(s.trim(), "1" | "on" | "true" | "yes"),
        Err(_) => false,
    }
}

fn mtime(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn listening(addr: SocketAddr) -> bool {
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

pub fn run(args: &[String]) -> ! {
    let mut state = String::new();
    let mut url = String::new();
    let mut no_proxy = String::new();
    let mut probe: Option<SocketAddr> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().cloned().unwrap_or_else(|| crate::config::usage());
        match a.as_str() {
            "--state" => state = v,
            "--url" => url = v,
            "--no-proxy" => no_proxy = v,
            "--probe" => probe = Some(crate::config::parse_addr(&v).unwrap_or_else(|e| {
                eprintln!("veyld: {}", e);
                std::process::exit(2)
            })),
            _ => crate::config::usage(),
        }
    }
    if state.is_empty() || url.is_empty() {
        crate::config::usage();
    }
    let probe = probe.unwrap_or_else(|| {
        let hostport = url.trim_start_matches("http://").trim_end_matches('/');
        hostport.parse().unwrap_or_else(|_| "127.0.0.1:1085".parse().unwrap())
    });

    unsafe {
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }

    let mut published: Option<bool> = None;
    let mut last_mtime = None;
    let mut last_probe = Instant::now() - PROBE_EVERY;
    let mut up = false;
    while !STOP.load(Ordering::SeqCst) {
        let m = mtime(&state);
        let changed = m != last_mtime;
        last_mtime = m;
        if changed || last_probe.elapsed() >= PROBE_EVERY {
            up = listening(probe);
            last_probe = Instant::now();
        }
        let want = up && state_on(&state);
        if published != Some(want) {
            if want {
                publish(&url, &no_proxy);
                say(&format!("published HTTPS_PROXY={}", url));
            } else {
                withdraw();
                say(if up { "veyl is off; HTTPS_PROXY withdrawn" } else { "proxy not listening; HTTPS_PROXY withdrawn" });
            }
            published = Some(want);
        }
        std::thread::sleep(STATE_POLL);
    }
    withdraw();
    say("stopping; HTTPS_PROXY withdrawn");
    std::process::exit(0)
}
