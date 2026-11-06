use crate::cache::{CacheKey, CachedResponse};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::BinEncodable;
use moka::Expiry;
use moka::future::Cache;
use std::mem::size_of;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Add an allocation estimate without allowing a maliciously large response to
/// wrap the `u32` weight used by moka.
fn add_weight(total: &mut u32, amount: usize) {
    let amount = u32::try_from(amount).unwrap_or(u32::MAX);
    *total = total.saturating_add(amount);
}

fn record_weight(record: &Record) -> usize {
    // `Record::to_bytes` includes the owner name, type, class, TTL, and the
    // encoded RDATA.  Keep the struct itself and its owned allocations in the
    // estimate as well; moka's capacity is an accounting budget, not a wire
    // protocol limit.
    size_of::<Record>()
        .saturating_add(record.name.len())
        .saturating_add(record.data.to_bytes().map_or(0, |bytes| bytes.len()))
}

fn add_records_weight(total: &mut u32, records: &[Record], capacity: usize) {
    // A Vec's capacity is retained even when its current length is smaller.
    add_weight(total, capacity.saturating_mul(size_of::<Record>()));
    for record in records {
        add_weight(total, record_weight(record));
    }
}

pub(crate) fn cached_response_weight(key: &CacheKey, value: &CachedResponse) -> u32 {
    // Record sections are immutable outside this module. Clone resets the
    // memo, so each owned payload is measured only once across both tiers.
    let payload = *value.payload_weight.get_or_init(|| {
        let mut weight = 0;
        add_weight(&mut weight, size_of::<CachedResponse>());
        add_records_weight(&mut weight, &value.answers, value.answers.capacity());
        add_records_weight(
            &mut weight,
            &value.authorities,
            value.authorities.capacity(),
        );
        add_records_weight(
            &mut weight,
            &value.additionals,
            value.additionals.capacity(),
        );
        weight
    });
    let mut weight = payload;
    add_weight(&mut weight, size_of::<CacheKey>());
    add_weight(&mut weight, key.name.len());
    weight.saturating_mul(2)
}

/// Aligns moka's expiry with DNS TTLs so dead entries release weighted
/// capacity without waiting for a lookup or capacity pressure.
pub(crate) struct CachedResponseExpiry;

impl Expiry<CacheKey, Arc<CachedResponse>> for CachedResponseExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &Arc<CachedResponse>,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(Duration::from_secs(value.original_ttl as u64))
    }
}

#[derive(Clone)]
pub struct L2Cache {
    cache: Cache<CacheKey, Arc<CachedResponse>>,
}

impl L2Cache {
    pub fn new(max_capacity_bytes: u64) -> Self {
        let cache = Cache::builder()
            .support_invalidation_closures()
            .weigher(|key: &CacheKey, value: &Arc<CachedResponse>| {
                cached_response_weight(key, value)
            })
            .expire_after(CachedResponseExpiry)
            .max_capacity(max_capacity_bytes)
            .build();
        Self { cache }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        self.cache.get(key).await
    }

    pub async fn insert(&self, key: CacheKey, value: impl Into<Arc<CachedResponse>>) {
        self.cache.insert(key, value.into()).await;
    }

    pub async fn remove(&self, key: &CacheKey) {
        self.cache.invalidate(key).await;
    }

    pub fn invalidate_by_name(&self, name: &hickory_proto::rr::Name) {
        let name = name.clone();
        self.cache
            .invalidate_entries_if(move |k, _v| k.name == name)
            .expect("L2 cache enables invalidation closures");
    }

    /// `invalidate_all` only marks the existing entries as dead; moka drops
    /// them, and refreshes the counters, while draining its housekeeping
    /// queue. Drain it here so a caller that clears an otherwise idle cache
    /// doesn't keep reading the pre-clear `entry_count`/`weighted_size`.
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
    }

    /// Applies the queued inserts, evictions and invalidations so that
    /// `entry_count` and `weighted_size` describe the cache as it is now.
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn weighted_size(&self) -> u64 {
        self.cache.weighted_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::{A, TXT};
    use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

    fn key() -> CacheKey {
        CacheKey {
            name: Name::root(),
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

    fn record_with_rdata(rdata: RData) -> Record {
        Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 60, rdata)
    }

    fn large_txt_record() -> Record {
        record_with_rdata(RData::TXT(TXT::new(vec!["x".repeat(255); 20])))
    }

    #[tokio::test]
    async fn invalidation_by_name_removes_all_types_and_preserves_other_names() {
        let cache = L2Cache::new(1024 * 1024);
        let first = key();
        let mut second = first.clone();
        second.qtype = RecordType::AAAA;
        let mut other = first.clone();
        other.name = Name::from_ascii("other.example.").unwrap();
        for key in [&first, &second, &other] {
            cache.insert(key.clone(), response_with_ttl(300)).await;
        }
        cache.invalidate_by_name(&first.name);
        assert!(cache.get(&first).await.is_none());
        assert!(cache.get(&second).await.is_none());
        assert!(cache.get(&other).await.is_some());
    }

    #[test]
    fn weight_includes_full_record_payload_and_sections() {
        let key = key();
        let small = CachedResponse {
            answers: vec![record_with_rdata(RData::A(A::new(192, 0, 2, 1)))],
            ..response_with_ttl(60)
        };
        let large = CachedResponse {
            answers: vec![large_txt_record()],
            authorities: vec![record_with_rdata(RData::A(A::new(192, 0, 2, 2)))],
            additionals: vec![record_with_rdata(RData::A(A::new(192, 0, 2, 3)))],
            ..response_with_ttl(60)
        };

        assert!(cached_response_weight(&key, &large) > cached_response_weight(&key, &small));
        assert!(cached_response_weight(&key, &large) > 4096);
    }

    #[tokio::test]
    async fn tiers_reuse_payload_weight_and_owned_clones_recompute_it() {
        let response = Arc::new(CachedResponse::new(
            ResponseCode::NoError,
            vec![record_with_rdata(RData::A(A::new(192, 0, 2, 1)))],
            vec![],
            vec![],
            60,
        ));
        assert!(response.payload_weight.get().is_none());
        let l1 = crate::cache::l1::L1Cache::new(10);
        let l2 = L2Cache::new(1024 * 1024);
        l1.insert(key(), response.clone());
        let measured = *response.payload_weight.get().unwrap();
        l2.insert(key(), response.clone()).await;
        assert_eq!(response.payload_weight.get(), Some(&measured));
        let mut owned = response.as_ref().clone();
        assert!(owned.payload_weight.get().is_none());
        owned.answers = vec![large_txt_record()];
        assert!(cached_response_weight(&key(), &owned) > cached_response_weight(&key(), &response));
        assert_eq!(response.payload_weight.get(), Some(&measured));
    }

    #[test]
    fn weight_saturates_instead_of_wrapping() {
        let mut weight = u32::MAX - 1;
        add_weight(&mut weight, usize::MAX);
        assert_eq!(weight, u32::MAX);
    }

    #[tokio::test]
    async fn entry_larger_than_capacity_is_not_admitted() {
        let large = CachedResponse {
            answers: vec![large_txt_record()],
            ..response_with_ttl(300)
        };
        let large_weight = cached_response_weight(&key(), &large);
        let l2 = L2Cache::new(u64::from(large_weight.saturating_sub(1)));
        let cache_key = key();
        l2.insert(cache_key.clone(), large).await;
        l2.cache.run_pending_tasks().await;

        assert!(l2.get(&cache_key).await.is_none());
    }

    #[tokio::test]
    async fn test_expired_entry_is_proactively_evicted_not_just_hidden() {
        let l2 = L2Cache::new(1024 * 1024);
        l2.insert(key(), response_with_ttl(1)).await;
        l2.cache.run_pending_tasks().await;
        assert_eq!(l2.cache.entry_count(), 1);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        l2.cache.run_pending_tasks().await;

        // The entry must actually be gone from moka's internal store (not
        // merely hidden on `get`), otherwise it keeps consuming weighted
        // capacity and polluting TinyLFU's frequency sketch.
        assert_eq!(l2.cache.entry_count(), 0);
        assert!(l2.get(&key()).await.is_none());
    }

    #[tokio::test]
    async fn test_clear_updates_counters_without_further_cache_activity() {
        let l2 = L2Cache::new(1024 * 1024);
        l2.insert(key(), response_with_ttl(300)).await;
        l2.cache.run_pending_tasks().await;
        assert_eq!(l2.entry_count(), 1);

        l2.clear().await;

        // No read or write happens between the clear and the stats read, so
        // `clear` itself has to drain moka's housekeeping queue -- otherwise
        // callers keep seeing the pre-clear totals.
        assert_eq!(l2.entry_count(), 0);
        assert_eq!(l2.weighted_size(), 0);
        assert!(l2.get(&key()).await.is_none());
    }

    #[tokio::test]
    async fn test_unexpired_entry_is_still_served() {
        let l2 = L2Cache::new(1024 * 1024);
        l2.insert(key(), response_with_ttl(300)).await;
        assert!(l2.get(&key()).await.is_some());
    }
}
