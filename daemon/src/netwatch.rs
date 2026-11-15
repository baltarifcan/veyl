//! Network change detection: PF_ROUTE interface/address messages, plus a
//! wall-clock jump against the monotonic clock for wake from sleep.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::watch;


pub static HAVE_V6: AtomicBool = AtomicBool::new(false);

pub fn have_global_v6() -> bool {
    HAVE_V6.load(Ordering::Relaxed)
}

/// All configured unicast addresses, excluding loopback and link-local.
pub fn local_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let ifa = &*p;
            if !ifa.ifa_addr.is_null() && ifa.ifa_flags & libc::IFF_UP as u32 != 0 {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::from(u32::from_be(sin.sin_addr.s_addr).to_be_bytes());
                        if !ip.is_loopback() {
                            out.push(ip);
                        }
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        let seg0 = ip.segments()[0];
                        if !ip.is_loopback() && (seg0 & 0xffc0) != 0xfe80 {
                            out.push(IpAddr::V6(ip));
                        }
                    }
                    _ => {}
                }
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

fn refresh_v6(addrs: &[IpAddr]) {
    // Global unicast (2000::/3).
    let v6 = addrs.iter().any(|a| match a {
        IpAddr::V6(v) => (v.segments()[0] & 0xe000) == 0x2000,
        _ => false,
    });
    HAVE_V6.store(v6, Ordering::Relaxed);
}

/// Interfaces that churn constantly without affecting reachability.
fn noisy_interface(index: u16) -> bool {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let name = unsafe {
        if libc::if_indextoname(index as u32, buf.as_mut_ptr()).is_null() {
            return false;
        }
        std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    };
    ["awdl", "llw", "anpi", "ap", "gif", "stf", "ipsec"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// The receiver's value is bumped, debounced, on every change.
pub fn start() -> watch::Receiver<u64> {
    refresh_v6(&local_addrs());
    let (tx, rx) = watch::channel(0u64);
    let (raw_tx, mut raw_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();

    let rtx = raw_tx.clone();
    std::thread::Builder::new()
        .name("netwatch".into())
        .spawn(move || route_socket_loop(rtx))
        .ok();

    // Instant does not advance while asleep; wall time does.
    let stx = raw_tx;
    tokio::spawn(async move {
        let mut mono = Instant::now();
        let mut wall = SystemTime::now();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let dm = mono.elapsed();
            let dw = SystemTime::now().duration_since(wall).unwrap_or_default();
            if dw > dm + Duration::from_secs(5) {
                let _ = stx.send("wake");
            }
            mono = Instant::now();
            wall = SystemTime::now();
        }
    });

    tokio::spawn(async move {
        let mut gen = 0u64;
        while let Some(why) = raw_rx.recv().await {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
            loop {
                match tokio::time::timeout_at(deadline, raw_rx.recv()).await {
                    Ok(Some(_)) => continue,
                    Ok(None) => return,
                    Err(_) => break,
                }
            }
            refresh_v6(&local_addrs());
            gen += 1;
            vlog!("netwatch: change #{} ({})", gen, why);
            if tx.send(gen).is_err() {
                return;
            }
        }
    });
    rx
}

fn route_socket_loop(tx: tokio::sync::mpsc::UnboundedSender<&'static str>) {
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if fd < 0 {
        crate::log!("netwatch: cannot open route socket: {}", std::io::Error::last_os_error());
        return;
    }
    let mut buf = vec![0u8; 8192];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            crate::log!("netwatch: route socket read failed: {}", err);
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let n = n as usize;
        if n < 14 {
            continue;
        }
        // Header: u16 len, u8 version, u8 type; if/ifa index at offset 12.
        let kind = buf[3] as i32;
        let why = match kind {
            libc::RTM_IFINFO => "link",
            libc::RTM_NEWADDR => "address added",
            libc::RTM_DELADDR => "address removed",
            _ => continue,
        };
        let index = u16::from_ne_bytes([buf[12], buf[13]]);
        if noisy_interface(index) {
            continue;
        }
        if tx.send(why).is_err() {
            return;
        }
    }
}
