//! Timestamped stderr logging, with per-key throttling for repeated failures.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub static VERBOSE: AtomicBool = AtomicBool::new(false);

const THROTTLE: Duration = Duration::from_secs(10);

pub fn timestamp() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

pub fn emit(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{} {}", timestamp(), msg);
}

static THROTTLED: Mutex<Option<HashMap<&'static str, (Instant, u64)>>> = Mutex::new(None);

/// Emit at most once per THROTTLE for `key`, reporting how many were folded.
pub fn throttled(key: &'static str, msg: String) {
    let now = Instant::now();
    let suppressed;
    {
        let mut g = THROTTLED.lock().unwrap_or_else(|e| e.into_inner());
        let map = g.get_or_insert_with(HashMap::new);
        match map.get_mut(key) {
            Some((last, count)) if now.duration_since(*last) < THROTTLE => {
                *count += 1;
                return;
            }
            Some((last, count)) => {
                suppressed = *count;
                *last = now;
                *count = 0;
            }
            None => {
                suppressed = 0;
                map.insert(key, (now, 0));
            }
        }
    }
    if suppressed > 0 {
        emit(&format!("{} (+{} similar in the last {}s)", msg, suppressed, THROTTLE.as_secs()));
    } else {
        emit(&msg);
    }
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! log {
    ($($a:tt)*) => { $crate::log::emit(&format!($($a)*)) };
}

#[macro_export]
macro_rules! log_every {
    ($key:expr, $($a:tt)*) => { $crate::log::throttled($key, format!($($a)*)) };
}

#[macro_export]
macro_rules! vlog {
    ($($a:tt)*) => { if $crate::log::verbose() { $crate::log::emit(&format!($($a)*)) } };
}
