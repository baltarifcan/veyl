//! Which strategy works for which host, keyed by hostname (never IP, which
//! CDNs share). Hosts without an entry inherit their parent domain's.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::desync::Strategy;

const TTL: Duration = Duration::from_secs(12 * 3600);
/// How long a host that rejects every strategy itself is left unjudged.
const GIVE_UP_TTL: Duration = Duration::from_secs(600);
const MAX_ENTRIES: usize = 8192;

pub struct Book {
    pub strategies: Vec<Strategy>,
    none: Option<usize>,
    direct: Vec<String>,
    map: Mutex<HashMap<String, (usize, Instant)>>,
    gave_up: Mutex<HashMap<String, Instant>>,
    /// The desync that last worked: the first guess for a new host.
    preferred: AtomicUsize,
}

fn matches_suffix(host: &str, d: &str) -> bool {
    host == d || (host.len() > d.len() && host.ends_with(d) && host.as_bytes()[host.len() - d.len() - 1] == b'.')
}

impl Book {
    pub fn new(strategies: Vec<Strategy>, direct: Vec<String>) -> Book {
        let none = strategies.iter().position(|s| s.is_none());
        let preferred = strategies.iter().position(|s| !s.is_none()).unwrap_or(0);
        Book {
            strategies,
            none,
            direct,
            map: Mutex::new(HashMap::new()),
            gave_up: Mutex::new(HashMap::new()),
            preferred: AtomicUsize::new(preferred),
        }
    }

    /// Strategy indices to try for `host`, in order.
    pub fn plan(&self, host: &str, replayable: bool) -> Vec<usize> {
        if self.direct.iter().any(|d| matches_suffix(host, d)) {
            return vec![self.none.unwrap_or(0)];
        }
        let now = Instant::now();
        {
            let mut g = self.gave_up.lock().unwrap_or_else(|e| e.into_inner());
            match g.get(host) {
                Some(t) if now.duration_since(*t) < GIVE_UP_TTL => return vec![self.none.unwrap_or(0)],
                Some(_) => {
                    g.remove(host);
                }
                None => {}
            }
        }
        let (exact, inherited) = {
            let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = |k: &str| map.get(k).filter(|(_, t)| now.duration_since(*t) < TTL).map(|(i, _)| *i);
            let exact = fresh(host);
            let mut inherited = None;
            if exact.is_none() {
                let mut rest = host;
                while let Some((_, parent)) = rest.split_once('.') {
                    if !parent.contains('.') {
                        break;
                    }
                    if let Some(i) = fresh(parent) {
                        inherited = Some(i);
                        break;
                    }
                    rest = parent;
                }
            }
            (exact, inherited)
        };

        let preferred = self.preferred.load(Ordering::Relaxed);
        let mut plan = Vec::with_capacity(self.strategies.len());
        let push = |i: usize, plan: &mut Vec<usize>| {
            if i < self.strategies.len() && !plan.contains(&i) {
                plan.push(i);
            }
        };
        match (exact, inherited) {
            (Some(i), _) => push(i, &mut plan),
            (None, Some(i)) => {
                push(i, &mut plan);
                if let Some(n) = self.none {
                    push(n, &mut plan);
                }
            }
            (None, None) => {
                if let Some(n) = self.none {
                    push(n, &mut plan);
                }
            }
        }
        push(preferred, &mut plan);
        for i in 0..self.strategies.len() {
            if Some(i) != self.none {
                push(i, &mut plan);
            }
        }
        if let Some(n) = self.none {
            push(n, &mut plan);
        }
        if !replayable {
            plan.truncate(1);
        }
        plan
    }

    pub fn success(&self, host: &str, idx: usize) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if self.strategies[idx].is_none() {
            map.remove(host);
            return;
        }
        if map.len() >= MAX_ENTRIES && !map.contains_key(host) {
            let now = Instant::now();
            map.retain(|_, (_, t)| now.duration_since(*t) < TTL);
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(host.to_string(), (idx, Instant::now()));
        self.preferred.store(idx, Ordering::Relaxed);
    }

    pub fn give_up(&self, host: &str) {
        let mut g = self.gave_up.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= MAX_ENTRIES {
            g.clear();
        }
        g.insert(host.to_string(), Instant::now());
    }

    pub fn entries(&self) -> Vec<(String, String)> {
        let now = Instant::now();
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = map
            .iter()
            .filter(|(_, (_, t))| now.duration_since(*t) < TTL)
            .map(|(h, (i, _))| (h.clone(), self.strategies[*i].name.clone()))
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book() -> Book {
        let s = ["none", "split:1", "oob:2"].iter().map(|s| Strategy::parse(s).unwrap()).collect();
        Book::new(s, vec!["direct.example".into()])
    }

    #[test]
    fn plans() {
        let b = book();
        assert_eq!(b.plan("example.com", true), vec![0, 1, 2]);
        assert_eq!(b.plan("x.direct.example", true), vec![0]);
        assert_eq!(b.plan("example.com", false), vec![0]);
        b.success("discord.com", 2);
        assert_eq!(b.plan("discord.com", true), vec![2, 1, 0]);
        assert_eq!(b.plan("cdn.discord.com", true), vec![2, 0, 1]);
        // Preferred moved to 2 as well.
        assert_eq!(b.plan("other.org", true), vec![0, 2, 1]);
        b.success("discord.com", 0);
        assert_eq!(b.plan("discord.com", true), vec![0, 2, 1]);
        // A bare TLD never matches as a parent.
        b.success("com", 1);
        assert_eq!(b.plan("foo.com", true)[0], 0);
    }
}
