use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const RATE_LIMIT_SHARDS: usize = 64;

pub struct RateLimiter {
    current: HashMap<IpAddr, u32>,
    previous: HashMap<IpAddr, u32>,
    limit_per_window: u32,
    max_entries: usize,
    window_start: Instant,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(
        limit_per_window: u32,
        max_entries: usize,
        window_duration: Duration,
        start_time: Instant,
    ) -> Self {
        Self {
            current: HashMap::with_capacity(max_entries.min(1024)),
            previous: HashMap::with_capacity(max_entries.min(1024)),
            limit_per_window,
            max_entries,
            window_start: start_time,
            window_duration,
        }
    }

    fn roll_windows(&mut self, now: Instant) {
        let elapsed = now
            .checked_duration_since(self.window_start)
            .unwrap_or_default();
        let two_windows = self.window_duration.checked_mul(2);
        if two_windows.is_some_and(|duration| elapsed >= duration) {
            self.current.clear();
            self.previous.clear();
            self.window_start = now;
        } else if elapsed >= self.window_duration {
            std::mem::swap(&mut self.current, &mut self.previous);
            self.current.clear();
            self.window_start = self
                .window_start
                .checked_add(self.window_duration)
                .unwrap_or(now);
        }
    }

    pub fn check_and_increment(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.roll_windows(now);
        if self.limit_per_window == 0 {
            return false;
        }

        let elapsed_in_window = now
            .checked_duration_since(self.window_start)
            .unwrap_or_default();
        let window_secs = self.window_duration.as_secs_f64();
        let weight = if window_secs > 0.0 {
            (1.0 - elapsed_in_window.as_secs_f64() / window_secs).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let previous_count = self.previous.get(&ip).copied().unwrap_or(0) as f64;
        let current_count = self.current.get(&ip).copied().unwrap_or(0) as f64;
        if previous_count * weight + current_count >= f64::from(self.limit_per_window) {
            return false;
        }
        if !self.current.contains_key(&ip) && self.current.len() >= self.max_entries {
            return false;
        }
        let count = self.current.entry(ip).or_insert(0);
        *count = count.saturating_add(1);
        true
    }

    #[cfg(test)]
    pub fn get_count(&self, ip: IpAddr) -> u32 {
        self.current.get(&ip).copied().unwrap_or(0)
    }
}

pub struct RateLimiterSet {
    shards: Vec<Mutex<RateLimiter>>,
    hash_builder: RandomState,
}

impl RateLimiterSet {
    pub fn new(
        limit_per_window: u32,
        max_entries: usize,
        window_duration: Duration,
        start_time: Instant,
    ) -> Self {
        let per_shard_capacity = max_entries.div_ceil(RATE_LIMIT_SHARDS);
        let shards = (0..RATE_LIMIT_SHARDS)
            .map(|_| {
                Mutex::new(RateLimiter::new(
                    limit_per_window,
                    per_shard_capacity,
                    window_duration,
                    start_time,
                ))
            })
            .collect();
        Self {
            shards,
            hash_builder: RandomState::new(),
        }
    }

    fn shard_index(&self, ip: IpAddr) -> usize {
        (self.hash_builder.hash_one(ip) as usize) % RATE_LIMIT_SHARDS
    }

    pub fn check_and_increment(&self, ip: IpAddr, now: Instant) -> bool {
        let mut limiter = self.shards[self.shard_index(ip)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limiter.check_and_increment(ip, now)
    }

    pub fn check_and_increment_now(&self, ip: IpAddr) -> bool {
        let mut limiter = self.shards[self.shard_index(ip)]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        limiter.check_and_increment(ip, now)
    }

    #[cfg(test)]
    pub fn total_entries(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .current
                    .len()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiting_and_window_swap() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let start = Instant::now();
        let mut limiter = RateLimiter::new(3, 100, Duration::from_secs(1), start);
        assert!(limiter.check_and_increment(ip, start));
        assert!(limiter.check_and_increment(ip, start));
        assert!(limiter.check_and_increment(ip, start));
        assert!(!limiter.check_and_increment(ip, start));

        let later = start + Duration::from_millis(1100);
        assert!(limiter.check_and_increment(ip, later));
        assert_eq!(limiter.get_count(ip), 1);
    }

    #[test]
    fn test_entry_capacity_cap() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(10, 2, Duration::from_secs(1), start);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));
        assert!(limiter.check_and_increment(ip1, start));
        assert!(limiter.check_and_increment(ip2, start));
        assert!(!limiter.check_and_increment(ip3, start));
        assert!(limiter.check_and_increment(ip1, start));
    }

    #[test]
    fn out_of_order_instants_do_not_panic() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(10, 10, Duration::from_secs(1), start);
        assert!(limiter.check_and_increment(IpAddr::V4(Ipv4Addr::LOCALHOST), start));
        assert!(limiter.check_and_increment(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            start.checked_sub(Duration::from_secs(1)).unwrap()
        ));
    }

    #[test]
    fn sharded_set_uses_full_per_ip_quota_and_bounded_capacity() {
        let start = Instant::now();
        let set = RateLimiterSet::new(2, 65, Duration::from_secs(1), start);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(set.check_and_increment(ip, start));
        assert!(set.check_and_increment(ip, start));
        assert!(!set.check_and_increment(ip, start));
        assert!(set.total_entries() <= 128);
    }
}
