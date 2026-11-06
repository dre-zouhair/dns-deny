pub mod exact;
pub mod regex_set;
pub mod snapshot;
pub mod trie;

use arc_swap::ArcSwap;
use hickory_proto::rr::Name;
use moka::sync::Cache;
use std::sync::Arc;
use std::time::Duration;

use crate::snapshot::FilterSnapshot;

const MAX_VERDICT_CACHE_ENTRIES: u64 = 100_000;
const VERDICT_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterVerdict {
    Allow,
    Block,
    Pass,
}

pub struct FilterEngine {
    snapshot: ArcSwap<FilterState>,
}

struct FilterState {
    rules: FilterSnapshot,
    verdict_cache: Cache<Name, FilterVerdict>,
}

impl FilterEngine {
    pub fn new(snapshot: FilterSnapshot) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(FilterState::new(snapshot)),
        }
    }

    /// Rules and their verdict cache are published together. Readers using an
    /// older snapshot can only populate that snapshot's private cache.
    pub fn reload(&self, new_snapshot: FilterSnapshot) {
        self.snapshot
            .store(Arc::new(FilterState::new(new_snapshot)));
    }

    /// Clears all entries in the verdict cache.
    ///
    /// Runs moka's housekeeping inline so the cleared state is visible to
    /// `cache_entry_count` immediately; that makes this call blocking, so
    /// async callers should offload it rather than run it on a worker that
    /// also serves lookups.
    pub fn clear_cache(&self) {
        let state = self.snapshot.load();
        state.verdict_cache.invalidate_all();
        state.verdict_cache.run_pending_tasks();
    }

    /// Returns the number of entries currently stored in the verdict cache.
    ///
    /// Blocking, for the same reason as [`clear_cache`](Self::clear_cache).
    pub fn cache_entry_count(&self) -> u64 {
        let state = self.snapshot.load();
        state.verdict_cache.run_pending_tasks();
        state.verdict_cache.entry_count()
    }

    /// Checks the name against the filter rules, caching results in the verdict cache.
    pub fn check(&self, name: &Name) -> FilterVerdict {
        let snapshot = self.snapshot.load();
        if let Some(cached) = snapshot.verdict_cache.get(name) {
            return cached;
        }

        let verdict = match snapshot.rules.check(name) {
            Some(true) => FilterVerdict::Allow,
            Some(false) => FilterVerdict::Block,
            None => FilterVerdict::Pass,
        };

        snapshot.verdict_cache.insert(name.clone(), verdict);

        verdict
    }
}

impl FilterState {
    fn new(rules: FilterSnapshot) -> Self {
        Self {
            rules,
            verdict_cache: Cache::builder()
                .max_capacity(MAX_VERDICT_CACHE_ENTRIES)
                .time_to_live(VERDICT_CACHE_TTL)
                .build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::ExactFilter;
    use crate::regex_set::RegexFilter;
    use crate::trie::SubdomainTrie;
    use std::str::FromStr;

    #[test]
    fn old_reader_cannot_populate_reloaded_verdict_cache() {
        let snapshot = || {
            FilterSnapshot::new(
                ExactFilter::new(),
                SubdomainTrie::new(),
                RegexFilter::new(&[], &[]).unwrap(),
            )
        };
        let engine = FilterEngine::new(snapshot());
        let old = engine.snapshot.load_full();
        let name = Name::from_ascii("blocked.example.").unwrap();
        let mut replacement = snapshot();
        replacement.exact.insert_deny(name.clone());
        engine.reload(replacement);
        // Deterministically emulate the old reader finishing after publication.
        old.verdict_cache.insert(name.clone(), FilterVerdict::Pass);
        assert_eq!(engine.check(&name), FilterVerdict::Block);
    }

    #[test]
    fn test_filter_exact_match() {
        let mut exact = ExactFilter::new();
        exact.insert_deny(Name::from_str("blocked.example.com.").unwrap());
        exact.insert_allow(Name::from_str("allowed.example.com.").unwrap());

        let trie = SubdomainTrie::new();
        let regex = RegexFilter::new(&[], &[]).unwrap();
        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = FilterEngine::new(snapshot);

        assert_eq!(
            engine.check(&Name::from_str("blocked.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("allowed.example.com.").unwrap()),
            FilterVerdict::Allow
        );
        assert_eq!(
            engine.check(&Name::from_str("other.example.com.").unwrap()),
            FilterVerdict::Pass
        );
    }

    #[test]
    fn test_filter_subdomain_trie() {
        let exact = ExactFilter::new();

        let mut trie = SubdomainTrie::new();
        trie.insert_deny(&Name::from_str("example.com.").unwrap());
        trie.insert_allow(&Name::from_str("good.example.com.").unwrap());

        let regex = RegexFilter::new(&[], &[]).unwrap();
        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = FilterEngine::new(snapshot);

        assert_eq!(
            engine.check(&Name::from_str("example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("sub.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("another.sub.example.com.").unwrap()),
            FilterVerdict::Block
        );

        assert_eq!(
            engine.check(&Name::from_str("good.example.com.").unwrap()),
            FilterVerdict::Allow
        );
        assert_eq!(
            engine.check(&Name::from_str("sub.good.example.com.").unwrap()),
            FilterVerdict::Allow
        );

        assert_eq!(
            engine.check(&Name::from_str("notexample.com.").unwrap()),
            FilterVerdict::Pass
        );
    }

    #[test]
    fn test_cross_tier_allow_precedence() {
        // A trie allow must override an exact deny from any source.
        let mut exact = ExactFilter::new();
        exact.insert_deny(Name::from_str("bad.example.com.").unwrap());

        let mut trie = SubdomainTrie::new();
        trie.insert_allow(&Name::from_str("example.com.").unwrap());

        let regex = RegexFilter::new(&[], &[]).unwrap();
        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = FilterEngine::new(snapshot);

        assert_eq!(
            engine.check(&Name::from_str("bad.example.com.").unwrap()),
            FilterVerdict::Allow
        );
    }

    #[test]
    fn test_filter_regex_tier() {
        let exact = ExactFilter::new();
        let trie = SubdomainTrie::new();

        let regex =
            RegexFilter::new(&[r"trusted".to_string()], &[r"^ads\..*".to_string()]).unwrap();

        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = FilterEngine::new(snapshot);

        assert_eq!(
            engine.check(&Name::from_str("ads.example.com.").unwrap()),
            FilterVerdict::Block
        );

        assert_eq!(
            engine.check(&Name::from_str("myads.example.com.").unwrap()),
            FilterVerdict::Pass
        );

        assert_eq!(
            engine.check(&Name::from_str("ads.trusted.com.").unwrap()),
            FilterVerdict::Allow
        );
    }

    #[test]
    fn test_engine_verdict_cache_and_reload() {
        let mut exact = ExactFilter::new();
        exact.insert_deny(Name::from_str("bad.com.").unwrap());
        let trie = SubdomainTrie::new();
        let regex = RegexFilter::new(&[], &[]).unwrap();

        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = FilterEngine::new(snapshot);

        assert_eq!(
            engine.check(&Name::from_str("bad.com.").unwrap()),
            FilterVerdict::Block
        );
        engine.snapshot.load().verdict_cache.run_pending_tasks();
        assert_eq!(engine.snapshot.load().verdict_cache.entry_count(), 1);

        let new_exact = ExactFilter::new();
        let new_trie = SubdomainTrie::new();
        let new_regex = RegexFilter::new(&[], &[]).unwrap();
        let new_snapshot = FilterSnapshot::new(new_exact, new_trie, new_regex);

        engine.reload(new_snapshot);

        engine.snapshot.load().verdict_cache.run_pending_tasks();
        assert_eq!(engine.snapshot.load().verdict_cache.entry_count(), 0);
        assert_eq!(
            engine.check(&Name::from_str("bad.com.").unwrap()),
            FilterVerdict::Pass
        );
    }
}
