use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::error;

use crate::cache::l1::L1Cache;
use crate::cache::l2::L2Cache;
use crate::config::{Config, ConfigHandle, now_epoch};
use crate::updater::BlocklistUpdater;

/// Snapshot of currently-live (non-expired) pause state, safe to render
/// directly to an admin.
#[derive(Debug, Clone)]
pub struct ProtectionStatus {
    pub default_duration_secs: u64,
    pub global_paused_until: Option<i64>,
    pub category_pauses: HashMap<String, i64>,
    pub service_pauses: HashMap<String, i64>,
    pub device_pauses: HashMap<String, i64>,
}

/// Filters out anything already expired even if the background sweeper
/// hasn't physically cleared it from `Config` yet -- callers must never
/// show a negative countdown.
pub fn live_status(config: &Config, now: i64) -> ProtectionStatus {
    ProtectionStatus {
        default_duration_secs: config.protection_pause_default_duration_secs,
        global_paused_until: config.protection_paused_until.filter(|&t| t > now),
        category_pauses: config
            .category_pauses
            .iter()
            .filter(|&(_, &t)| t > now)
            .map(|(id, &t)| (id.clone(), t))
            .collect(),
        device_pauses: config
            .device_pauses
            .iter()
            .filter(|&(_, &until)| until > now)
            .map(|(id, &until)| (crate::config::normalize_device_identifier(id), until))
            .collect(),
        service_pauses: config
            .service_pauses
            .iter()
            .filter(|&(_, &t)| t > now)
            .map(|(id, &t)| (id.clone(), t))
            .collect(),
    }
}

/// Persists expired global/category/service pauses so protection resumes automatically.
pub struct PauseSweeper {
    config: Arc<ConfigHandle>,
    updater: Arc<BlocklistUpdater>,
    l1_cache: Arc<L1Cache>,
    l2_cache: L2Cache,
}

impl PauseSweeper {
    pub fn new(
        config: Arc<ConfigHandle>,
        updater: Arc<BlocklistUpdater>,
        l1_cache: Arc<L1Cache>,
        l2_cache: L2Cache,
    ) -> Self {
        updater.attach_config(config.clone());
        Self {
            config,
            updater,
            l1_cache,
            l2_cache,
        }
    }

    pub fn start_pause_sweep_task(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick fires immediately; skip it
            loop {
                ticker.tick().await;
                self.sweep_once().await;
            }
        });
    }

    /// One sweep pass: clears any expired global/category/service pause,
    /// persists the change, and -- only if a category pause expired --
    /// resyncs the blocklist snapshot so its domains are enforced again.
    pub async fn sweep_once(&self) {
        let now = now_epoch();
        let snap = self.config.load();
        let has_expired = snap.protection_paused_until.is_some_and(|t| t <= now)
            || snap.category_pauses.values().any(|&t| t <= now)
            || snap.service_pauses.values().any(|&t| t <= now)
            || snap.device_pauses.values().any(|&t| t <= now);
        if !has_expired {
            return;
        }

        let update_res = self
            .config
            .update("protection:sweep", |cfg| {
                let now = now_epoch();
                let mut any_expired = false;

                if cfg.protection_paused_until.is_some_and(|t| t <= now) {
                    cfg.protection_paused_until = None;
                    any_expired = true;
                }

                let expired_categories: Vec<String> = cfg
                    .category_pauses
                    .iter()
                    .filter(|&(_, &t)| t <= now)
                    .map(|(id, _)| id.clone())
                    .collect();
                let category_expired = !expired_categories.is_empty();
                for id in &expired_categories {
                    cfg.category_pauses.remove(id);
                }
                any_expired |= category_expired;

                let expired_services: Vec<String> = cfg
                    .service_pauses
                    .iter()
                    .filter(|&(_, &t)| t <= now)
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in &expired_services {
                    cfg.service_pauses.remove(id);
                }
                any_expired |= !expired_services.is_empty();

                let other_expired = any_expired;
                let before = cfg.device_pauses.len();
                cfg.device_pauses.retain(|_, until| *until > now);
                any_expired |= before != cfg.device_pauses.len();

                if !any_expired {
                    return Err("nothing_expired".to_string());
                }

                Ok::<(bool, bool), String>((category_expired, other_expired))
            })
            .await;

        let (category_expired, other_expired) = match update_res {
            Ok(commit) => commit.output,
            Err(crate::config::ConfigUpdateError::Mutation(_)) => return,
            Err(crate::config::ConfigUpdateError::Validation(e)) => {
                error!("Config validation failed during pause sweep: {:?}", e);
                return;
            }
            Err(crate::config::ConfigUpdateError::Persistence(e)) => {
                error!("Failed to persist config after pause sweep: {:?}", e);
                return;
            }
        };

        if other_expired {
            self.l1_cache.clear();
            self.l2_cache.clear().await;
        }

        if category_expired && let Err(error) = self.updater.ensure_current_sources().await {
            error!("Pause sweep: failed to publish resumed categories: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::l1::L1Cache;
    use crate::cache::l2::L2Cache;
    use crate::config::ConfigHandle;
    use crate::config::tests::base_config;
    use crate::config::{BlocklistCategory, now_epoch};
    use crate::protection::{PauseSweeper, live_status};
    use crate::updater::BlocklistUpdater;
    use filter::exact::ExactFilter;
    use filter::regex_set::RegexFilter;
    use filter::snapshot::FilterSnapshot;
    use filter::{FilterEngine, FilterVerdict};
    use hickory_proto::rr::Name;
    use std::str::FromStr;
    use std::sync::Arc;

    fn empty_engine() -> Arc<FilterEngine> {
        let snapshot = FilterSnapshot::new(
            ExactFilter::new(),
            filter::trie::SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        Arc::new(FilterEngine::new(snapshot))
    }

    #[test]
    fn test_live_status_filters_expired_entries() {
        let mut cfg = base_config();
        let now = 1_000_000;
        cfg.protection_paused_until = Some(now - 10); // expired
        cfg.category_pauses.insert("gambling".to_string(), now - 5); // expired
        cfg.category_pauses.insert("social".to_string(), now + 5); // live
        cfg.service_pauses.insert("tiktok".to_string(), now + 100); // live
        cfg.device_pauses.insert("192.0.2.1".into(), now - 1);
        cfg.device_pauses
            .insert("AA-BB-CC-DD-EE-01".into(), now + 100);

        let status = live_status(&cfg, now);

        assert_eq!(status.global_paused_until, None);
        assert_eq!(
            status.device_pauses,
            std::collections::HashMap::from([("aa:bb:cc:dd:ee:01".into(), now + 100)])
        );
        assert!(!status.category_pauses.contains_key("gambling"));
        assert_eq!(status.category_pauses.get("social"), Some(&(now + 5)));
        assert_eq!(status.service_pauses.get("tiktok"), Some(&(now + 100)));
    }

    #[tokio::test]
    async fn test_sweep_once_clears_expired_category_and_reblocks_domain() {
        let base_dir =
            std::env::temp_dir().join(format!("dns-deny-protection-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();

        let blocklist_file = base_dir.join("gambling.txt");
        tokio::fs::write(&blocklist_file, b"blocked-gambling.example.com\n")
            .await
            .unwrap();
        let category_url = format!("file://{}", blocklist_file.to_str().unwrap());

        let engine = empty_engine();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![],
            base_dir.clone(),
        ));

        let mut cfg = base_config();
        cfg.blocklist_categories.push(BlocklistCategory {
            id: "gambling".to_string(),
            name: "Gambling".to_string(),
            urls: vec![category_url],
            enabled: true,
        });
        let now = now_epoch();
        cfg.category_pauses.insert("gambling".to_string(), now - 10); // already expired
        cfg.service_pauses
            .insert("tiktok".to_string(), now + 10_000); // still live

        cfg.device_pauses.insert("192.0.2.1".into(), now - 1);
        cfg.device_pauses
            .insert("aa:bb:cc:dd:ee:01".into(), now + 10000);

        let state_db = base_dir.join("state.db");
        let store = crate::config_store::ConfigStore::open(&state_db).unwrap();
        let rev = store.insert_seed(&cfg).unwrap();
        let config = Arc::new(ConfigHandle::new_persistent(store, cfg, rev).unwrap());
        let l1_cache = Arc::new(L1Cache::new(100));
        let l2_cache = L2Cache::new(1024 * 1024);

        let sweeper = PauseSweeper::new(
            config.clone(),
            updater.clone(),
            l1_cache.clone(),
            l2_cache.clone(),
        );
        sweeper.sweep_once().await;

        {
            let cfg = config.load();
            assert!(!cfg.category_pauses.contains_key("gambling"));
            assert!(!cfg.device_pauses.contains_key("192.0.2.1"));
            assert!(cfg.device_pauses.contains_key("aa:bb:cc:dd:ee:01"));
            assert!(cfg.service_pauses.contains_key("tiktok"));
        }

        assert_eq!(
            engine.check(&Name::from_str("blocked-gambling.example.com.").unwrap()),
            FilterVerdict::Block
        );

        let store = crate::config_store::ConfigStore::open(&state_db).unwrap();
        let (reloaded, _) = store.load_current().unwrap().expect("snapshot exists");
        assert!(!reloaded.category_pauses.contains_key("gambling"));
        assert!(!reloaded.device_pauses.contains_key("192.0.2.1"));
        assert!(reloaded.device_pauses.contains_key("aa:bb:cc:dd:ee:01"));
        assert!(reloaded.service_pauses.contains_key("tiktok"));

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn test_sweep_once_noop_when_nothing_expired() {
        let base_dir = std::env::temp_dir().join(format!(
            "dns-deny-protection-test-noop-{}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();

        let engine = empty_engine();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![],
            base_dir.clone(),
        ));

        let mut cfg = base_config();
        let now = now_epoch();
        cfg.protection_paused_until = Some(now + 10_000); // still live

        let state_db = base_dir.join("state.db");
        let store = crate::config_store::ConfigStore::open(&state_db).unwrap();
        let rev = store.insert_seed(&cfg).unwrap();
        let config = Arc::new(ConfigHandle::new_persistent(store, cfg, rev).unwrap());
        let l1_cache = Arc::new(L1Cache::new(100));
        let l2_cache = L2Cache::new(1024 * 1024);

        let sweeper = PauseSweeper::new(config.clone(), updater, l1_cache, l2_cache);
        sweeper.sweep_once().await;

        let cfg = config.load();
        assert!(cfg.protection_paused_until.is_some());

        let store = crate::config_store::ConfigStore::open(&state_db).unwrap();
        let (_, cur_rev) = store.load_current().unwrap().expect("snapshot exists");
        assert_eq!(cur_rev, rev);

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn test_sweep_once_failure_isolation_and_retry() {
        use std::os::unix::fs::PermissionsExt;
        let base_dir = std::env::temp_dir().join(format!(
            "dns-deny-protection-test-fail-{}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();

        let engine = empty_engine();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![],
            base_dir.clone(),
        ));

        let mut cfg = base_config();
        let now = now_epoch();
        cfg.protection_paused_until = Some(now - 10); // expired

        let state_db = base_dir.join("state.db");
        let store = crate::config_store::ConfigStore::open(&state_db).unwrap();
        let rev = store.insert_seed(&cfg).unwrap();
        let config = Arc::new(ConfigHandle::new_persistent(store, cfg, rev).unwrap());
        let l1_cache = Arc::new(L1Cache::new(100));
        let l2_cache = L2Cache::new(1024 * 1024);

        let sweeper = PauseSweeper::new(config.clone(), updater, l1_cache, l2_cache);

        for entry in std::fs::read_dir(&base_dir).unwrap().flatten() {
            let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o400));
        }
        let _ = std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o500));

        sweeper.sweep_once().await;

        let cfg = config.load();
        assert!(cfg.protection_paused_until.is_some());

        let _ = std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700));
        for entry in std::fs::read_dir(&base_dir).unwrap().flatten() {
            let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o600));
        }

        sweeper.sweep_once().await;
        let cfg = config.load();
        assert!(cfg.protection_paused_until.is_none());

        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
