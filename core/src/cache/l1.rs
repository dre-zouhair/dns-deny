use crate::cache::{CacheKey, CachedResponse};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A small weighted front cache. Both tiers own Arcs, so L1 needs its own
/// memory budget rather than relying on eviction from L2.
pub struct L1Cache {
    cache: moka::sync::Cache<CacheKey, Arc<CachedResponse>>,
    max_bytes: u64,
}

impl L1Cache {
    pub fn new(max_entries: usize) -> Self {
        // At most 1 KiB of budget per configured entry, capped at 64 MiB.
        Self::with_byte_capacity(
            max_entries,
            (max_entries as u64)
                .saturating_mul(1024)
                .min(64 * 1024 * 1024),
        )
    }

    pub fn with_byte_capacity(max_entries: usize, max_bytes: u64) -> Self {
        let capacity = if max_entries == 0 { 0 } else { max_bytes };
        let minimum = capacity
            .div_ceil(max_entries.max(1) as u64)
            .min(u32::MAX as u64) as u32;
        let cache = moka::sync::Cache::builder()
            .support_invalidation_closures()
            .max_capacity(capacity)
            .weigher(move |key, value: &Arc<CachedResponse>| {
                crate::cache::l2::cached_response_weight(key, value).max(minimum)
            })
            .expire_after(crate::cache::l2::CachedResponseExpiry)
            .build();
        Self {
            cache,
            max_bytes: capacity,
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        let value = self.cache.get(key)?;
        if value.remaining_ttl(Instant::now()).is_some() {
            Some(value)
        } else {
            self.cache.invalidate(key);
            None
        }
    }

    /// Oversized responses are rejected; capacity pressure evicts older,
    /// less frequently used entries instead of permanently rejecting new keys.
    pub fn insert(&self, key: CacheKey, value: impl Into<Arc<CachedResponse>>) -> bool {
        let value = value.into();
        if u64::from(crate::cache::l2::cached_response_weight(&key, &value)) > self.max_bytes
            || self.max_bytes == 0
        {
            return false;
        }
        self.cache.insert(key, value);
        true
    }
    pub fn remove(&self, key: &CacheKey) {
        self.cache.invalidate(key);
    }
    pub fn invalidate_by_name(&self, name: &hickory_proto::rr::Name) {
        let name = name.clone();
        self.cache
            .invalidate_entries_if(move |key, _| key.name == name)
            .expect("invalidation enabled");
    }
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
    pub fn len(&self) -> usize {
        self.cache.run_pending_tasks();
        self.live_len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn live_len(&self) -> usize {
        self.cache
            .iter()
            .filter(|(_, value)| value.remaining_ttl(Instant::now()).is_some())
            .count()
    }
    fn reap_expired(&self) {
        let now = Instant::now();
        for (key, _) in self
            .cache
            .iter()
            .filter(|(_, value)| value.remaining_ttl(now).is_none())
        {
            self.cache.invalidate(key.as_ref());
        }
        self.cache.run_pending_tasks();
    }
    pub fn start_reaper_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let cache = self.clone();
                let _ = tokio::task::spawn_blocking(move || cache.reap_expired()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{DNSClass, Name, RecordType};

    fn key(label: &str) -> CacheKey {
        CacheKey {
            name: Name::from_ascii(label).unwrap(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
        }
    }

    fn response_with_ttl(ttl_secs: u32) -> CachedResponse {
        CachedResponse {
            response_code: ResponseCode::NoError,
            authenticated_data: false,
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            created_at: Instant::now(),
            original_ttl: ttl_secs,
            payload_weight: Default::default(),
            aged_sections: Default::default(),
        }
    }

    #[test]
    fn oversized_responses_do_not_consume_the_front_cache_budget() {
        let cache = L1Cache::with_byte_capacity(10, 1024);
        let mut response = response_with_ttl(300);
        response.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::root(),
            300,
            hickory_proto::rr::RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                "x".repeat(4096),
            ])),
        ));
        assert!(!cache.insert(key("large.example."), response));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_reap_expired_removes_only_expired_entries() {
        let cache = L1Cache::new(100);
        assert!(cache.insert(key("expired.com."), response_with_ttl(0)));
        assert!(cache.insert(key("alive.com."), response_with_ttl(300)));
        assert_eq!(cache.live_len(), 1);

        std::thread::sleep(Duration::from_millis(10));
        cache.reap_expired();

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&key("alive.com.")).is_some());
        assert!(cache.get(&key("expired.com.")).is_none());
    }

    #[test]
    fn test_live_len_excludes_entries_not_yet_reaped() {
        let cache = L1Cache::new(100);
        assert!(cache.insert(key("expired.com."), response_with_ttl(0)));
        assert!(cache.insert(key("alive.com."), response_with_ttl(300)));

        std::thread::sleep(Duration::from_millis(10));

        // Expired entries must not be included in live utilisation.
        assert_eq!(cache.live_len(), 1);
        assert_eq!(cache.live_len(), 1);
    }

    #[test]
    fn test_insert_refresh_of_existing_key_not_blocked_by_capacity() {
        let cache = L1Cache::new(1);
        assert!(cache.insert(key("only.com."), response_with_ttl(300)));
        assert_eq!(cache.len(), 1);

        // Updating an existing key must remain possible at capacity.
        assert!(cache.insert(key("only.com."), response_with_ttl(600)));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&key("only.com.")).unwrap().original_ttl, 600);
    }
}
