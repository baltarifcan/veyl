//! Answer cache. Entries in the last tenth of their TTL are prefetched;
//! expired positive answers are served stale while refreshing (RFC 8767).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long past expiry a positive answer may still be served.
pub const STALE_MAX: Duration = Duration::from_secs(24 * 3600);
/// TTL handed out with a stale answer.
pub const STALE_TTL: u32 = 10;
pub const MAX_TTL: u32 = 86_400;
/// Kept at least this long even for TTL 0; the client still sees 0.
pub const MIN_CACHE_TTL: u32 = 5;
pub const FAIL_TTL: u32 = 2;
const CAPACITY: usize = 50_000;

pub struct Entry {
    pub wire: Vec<u8>,
    pub ttls: Vec<(u16, u32)>,
    pub stored: Instant,
    /// Seconds the entry is fresh for.
    pub ttl: u32,
    /// NXDOMAIN / NODATA. Not served stale.
    pub negative: bool,
    /// Synthesized failure or plaintext answer: short-lived, never stale,
    /// never displaces a real answer.
    pub failure: bool,
}

impl Entry {
    pub fn age(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.stored).as_secs().min(u32::MAX as u64) as u32
    }
}

pub enum Lookup {
    Fresh { entry: Arc<Entry>, prefetch: bool },
    Stale(Arc<Entry>),
    Miss,
}

struct Slot {
    entry: Arc<Entry>,
    last_used: Instant,
}

pub struct Cache {
    map: Mutex<HashMap<Vec<u8>, Slot>>,
}

impl Cache {
    pub fn new() -> Cache {
        Cache { map: Mutex::new(HashMap::with_capacity(4096)) }
    }

    pub fn get(&self, key: &[u8]) -> Lookup {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = map.get_mut(key) else { return Lookup::Miss };
        slot.last_used = now;
        let e = &slot.entry;
        let age = now.saturating_duration_since(e.stored);
        let ttl = Duration::from_secs(e.ttl as u64);
        if age < ttl {
            let remaining = ttl - age;
            let prefetch = !e.failure && e.ttl >= 10 && remaining * 10 < ttl;
            return Lookup::Fresh { entry: e.clone(), prefetch };
        }
        if !e.negative && !e.failure && age < ttl + STALE_MAX {
            return Lookup::Stale(e.clone());
        }
        map.remove(key);
        Lookup::Miss
    }

    /// Any positive entry still within the stale window.
    pub fn get_any_positive(&self, key: &[u8]) -> Option<Arc<Entry>> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let e = &map.get(key)?.entry;
        let age = Instant::now().saturating_duration_since(e.stored);
        if !e.negative && !e.failure && age < Duration::from_secs(e.ttl as u64) + STALE_MAX {
            Some(e.clone())
        } else {
            None
        }
    }

    pub fn put(&self, key: Vec<u8>, entry: Arc<Entry>) {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if entry.failure {
            if let Some(old) = map.get(&key) {
                if !old.entry.failure && !old.entry.negative {
                    return;
                }
            }
        }
        if map.len() >= CAPACITY && !map.contains_key(&key) {
            evict(&mut map, now);
        }
        map.insert(key, Slot { entry, last_used: now });
    }

    pub fn forget_failures(&self) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, s| !s.entry.failure);
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, s| {
            let e = &s.entry;
            let lifetime = Duration::from_secs(e.ttl as u64)
                + if e.negative || e.failure { Duration::ZERO } else { STALE_MAX };
            now.saturating_duration_since(e.stored) < lifetime
        });
    }

    pub fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Drop the expired, then the least recently used eighth.
fn evict(map: &mut HashMap<Vec<u8>, Slot>, now: Instant) {
    map.retain(|_, s| now.saturating_duration_since(s.entry.stored) < Duration::from_secs(s.entry.ttl as u64));
    if map.len() < CAPACITY {
        return;
    }
    let mut ages: Vec<Instant> = map.values().map(|s| s.last_used).collect();
    let cut = ages.len() / 8;
    ages.select_nth_unstable(cut);
    let threshold = ages[cut];
    map.retain(|_, s| s.last_used > threshold);
}

pub fn cache_ttl(min_ttl: Option<u32>, negative: bool) -> u32 {
    let t = min_ttl.unwrap_or(if negative { 60 } else { 300 });
    let t = if negative { t.min(3600) } else { t };
    t.clamp(MIN_CACHE_TTL, MAX_TTL)
}
