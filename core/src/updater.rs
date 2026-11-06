use filter::FilterEngine;
use filter::exact::ExactFilter;
use filter::regex_set::RegexFilter;
use filter::snapshot::FilterSnapshot;
use filter::trie::SubdomainTrie;
use futures_util::{StreamExt, stream};
use hickory_proto::rr::Name;
use ingest::{FilterRule, RuleAction, RuleType};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct SourceState {
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Shared so `rebuild_snapshot` can hand every source's rules to a
    /// blocking thread without copying them.
    pub last_rules: Arc<Vec<FilterRule>>,
    pattern_bytes: usize,
    active: bool,
    loaded: bool,
    has_regex: bool,
}

/// Cached downloads keep filtering active at startup, even without network access.
const CACHE_DIR: &str = "blocklist_cache";
// At most two source buffers/parsers are live, regardless of the configured
// fetch concurrency. Retained rules have a separate aggregate ceiling.
const MAX_IMPORTS_IN_FLIGHT: usize = 2;
const MAX_RETAINED_SOURCE_RULES: usize = 2_000_000;
const MAX_AUTO_DENY_RULES: usize = 100_000;

fn retained_rules_fit(
    sources: &HashMap<String, SourceState>,
    url: &str,
    rules: usize,
    bytes: usize,
) -> bool {
    let mut count = rules;
    let mut pattern_bytes = bytes;
    for (_, source) in sources.iter().filter(|(key, _)| key.as_str() != url) {
        count = count.saturating_add(source.last_rules.len());
        pattern_bytes = pattern_bytes.saturating_add(source.pattern_bytes);
    }
    count <= MAX_RETAINED_SOURCE_RULES && pattern_bytes <= 64 * 1024 * 1024
}

async fn read_source(
    path: PathBuf,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<ImportBuffer, Box<dyn std::error::Error + Send + Sync>> {
    Ok(
        tokio::task::spawn_blocking(move || -> Result<ImportBuffer, ingest::IngestError> {
            Ok(ImportBuffer {
                bytes: ingest::read_source(&path)?,
                permit,
            })
        })
        .await??,
    )
}

async fn read_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if response
        .content_length()
        .is_some_and(|length| length > ingest::MAX_SOURCE_BYTES as u64)
    {
        return Err("blocklist source exceeds byte limit".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > ingest::MAX_SOURCE_BYTES.saturating_sub(bytes.len()) {
            return Err("blocklist source exceeds byte limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Stable cache file stem for a source URL (64-bit FNV-1a, hex). `std`'s
/// `DefaultHasher` isn't guaranteed stable across Rust releases, and a
/// changed hash would silently orphan the whole cache after an upgrade.
fn cache_key(url: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in url.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn is_remote_source(url: &str) -> bool {
    !(url.starts_with('/') || url.starts_with("file://"))
}

/// Sniffs and parses blocklist bytes on the blocking pool -- a multi-MB list
/// (or a gravity.db) takes long enough to parse that doing it inline would
/// stall a runtime worker that also serves DNS. The buffer is handed back so
/// callers can still use it (e.g. to cache it on disk).
async fn parse_blocklist<B>(
    bytes: B,
) -> Result<(B, Vec<FilterRule>, usize, bool), Box<dyn std::error::Error + Send + Sync>>
where
    B: AsRef<[u8]> + Send + 'static,
{
    let (bytes, result) = tokio::task::spawn_blocking(move || {
        let result = {
            let data = bytes.as_ref();
            let format = ingest::sniff::sniff_format(data);
            ingest::ingest_source(format, ingest::SourceData::Bytes(data)).map(|rules| {
                let bytes = rules.iter().map(|rule| rule.pattern.len()).sum();
                let has_regex = rules.iter().any(|rule| rule.rule_type == RuleType::Regex);
                (rules, bytes, has_regex)
            })
        };
        (bytes, result)
    })
    .await?;
    let (rules, pattern_bytes, has_regex) = result?;
    Ok((bytes, rules, pattern_bytes, has_regex))
}

/// Everything `rebuild_snapshot` reads, collected up front so the build can
/// run on a blocking thread without holding any of the updater's locks.
struct RuleInputs {
    sources: Vec<Arc<Vec<FilterRule>>>,
    local_allows: Vec<String>,
    local_denies: Vec<String>,
    auto_denies: Vec<String>,
    regex_allows: Vec<String>,
    regex_denies: Vec<String>,
}

/// A successfully fetched and parsed source, applied to its `SourceState`
/// only once everything (download *and* parse) has succeeded.
struct FetchedSource {
    _permit: tokio::sync::OwnedSemaphorePermit,
    body: Option<Vec<u8>>,
    pattern_bytes: usize,
    etag: Option<String>,
    last_modified: Option<String>,
    rules: Vec<FilterRule>,
    has_regex: bool,
}

struct ImportBuffer {
    bytes: Vec<u8>,
    permit: tokio::sync::OwnedSemaphorePermit,
}

impl AsRef<[u8]> for ImportBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Restore the dirty bit even if the caller is cancelled or the blocking
/// build panics. The compile permit lives in that same blocking closure.
struct SnapshotBuildGuard {
    dirty: Arc<AtomicBool>,
    published: bool,
}
impl SnapshotBuildGuard {
    fn publish(mut self) {
        self.published = true;
    }
}
impl Drop for SnapshotBuildGuard {
    fn drop(&mut self) {
        if !self.published {
            self.dirty.store(true, Ordering::Release);
        }
    }
}

pub struct BlocklistUpdater {
    filter_engine: Arc<FilterEngine>,
    client: Client,
    sources: Mutex<HashMap<String, SourceState>>,
    pub local_allows: Arc<Mutex<HashSet<String>>>,
    pub local_denies: Arc<Mutex<HashSet<String>>>,
    pub regex_allows: Arc<Mutex<HashSet<String>>>,
    pub regex_denies: Arc<Mutex<HashSet<String>>>,
    pub auto_denies: Arc<Mutex<HashSet<String>>>,
    pub malicious_ips: Arc<Mutex<HashSet<std::net::IpAddr>>>,
    malicious_ip_snapshot: Arc<arc_swap::ArcSwap<HashSet<std::net::IpAddr>>>,
    base_dir: Option<PathBuf>,
    /// Serializes `refresh()` calls (startup sync, scheduler, admin sync) so
    /// two never fetch the same sources concurrently. Never held by readers.
    refresh_lock: Mutex<()>,
    fetch_concurrency: AtomicUsize,
    /// Serializes `rebuild_snapshot()` so a rebuild that read older rule
    /// state can't finish after, and overwrite, one that read newer state.
    rebuild_lock: Mutex<()>,
    rebuild_requested: AtomicBool,
    rebuild_running: AtomicBool,
    import_slots: Arc<tokio::sync::Semaphore>,
    compile_slots: Arc<tokio::sync::Semaphore>,
    sources_dirty: Arc<AtomicBool>,
    source_config: OnceLock<Arc<crate::config::ConfigHandle>>,
    reconcile_lock: Mutex<()>,
    reconciled_revision: AtomicI64,
    next_source_transition: AtomicI64,
}

impl BlocklistUpdater {
    pub async fn total_rules_count(&self) -> usize {
        let sources = self.sources.lock().await;
        let mut count: usize = sources
            .values()
            .filter(|s| s.active)
            .map(|s| s.last_rules.len())
            .sum();
        count += self.local_denies.lock().await.len();
        count += self.local_allows.lock().await.len();
        count += self.regex_denies.lock().await.len();
        count += self.regex_allows.lock().await.len();
        count
    }

    /// Uses the live filter engine so admin probes share DNS filtering semantics.
    pub fn check_domain(&self, name: &Name) -> filter::FilterVerdict {
        self.filter_engine.check(name)
    }

    /// Clears the verdict cache of the underlying filter engine.
    ///
    /// Blocking: see [`FilterEngine::clear_cache`].
    pub fn clear_filter_cache(&self) {
        self.filter_engine.clear_cache();
    }

    /// Returns the number of cached entries in the underlying filter engine.
    ///
    /// Blocking: see [`FilterEngine::cache_entry_count`].
    pub fn filter_cache_entry_count(&self) -> u64 {
        self.filter_engine.cache_entry_count()
    }

    pub fn new(filter_engine: Arc<FilterEngine>, initial_urls: Vec<String>) -> Self {
        Self::new_with_dir_opt(filter_engine, initial_urls, None)
    }

    pub fn new_with_dir(
        filter_engine: Arc<FilterEngine>,
        initial_urls: Vec<String>,
        base_dir: PathBuf,
    ) -> Self {
        Self::new_with_dir_opt(filter_engine, initial_urls, Some(base_dir))
    }

    fn new_with_dir_opt(
        filter_engine: Arc<FilterEngine>,
        initial_urls: Vec<String>,
        base_dir: Option<PathBuf>,
    ) -> Self {
        let mut sources = HashMap::new();
        for url in initial_urls {
            sources.insert(
                url.clone(),
                SourceState {
                    url,
                    etag: None,
                    last_modified: None,
                    last_rules: Arc::default(),
                    pattern_bytes: 0,
                    active: true,
                    loaded: false,
                    has_regex: false,
                },
            );
        }

        let local_allow_path = base_dir
            .as_ref()
            .map(|d| d.join("local_allow.txt"))
            .unwrap_or_else(|| PathBuf::from("local_allow.txt"));
        let local_deny_path = base_dir
            .as_ref()
            .map(|d| d.join("local_deny.txt"))
            .unwrap_or_else(|| PathBuf::from("local_deny.txt"));
        let regex_allow_path = base_dir
            .as_ref()
            .map(|d| d.join("regex_allow.txt"))
            .unwrap_or_else(|| PathBuf::from("regex_allow.txt"));
        let regex_deny_path = base_dir
            .as_ref()
            .map(|d| d.join("regex_deny.txt"))
            .unwrap_or_else(|| PathBuf::from("regex_deny.txt"));
        let auto_denies_path = base_dir
            .as_ref()
            .map(|d| d.join("auto_blocked.txt"))
            .unwrap_or_else(|| PathBuf::from("auto_blocked.txt"));
        let malicious_ips_path = base_dir
            .as_ref()
            .map(|d| d.join("malicious_ips.txt"))
            .unwrap_or_else(|| PathBuf::from("malicious_ips.txt"));

        let initial_malicious_ips = Self::load_file_ips(&malicious_ips_path);
        Self {
            filter_engine,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            sources: Mutex::new(sources),
            import_slots: Arc::new(tokio::sync::Semaphore::new(MAX_IMPORTS_IN_FLIGHT)),
            compile_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            local_allows: Arc::new(Mutex::new(Self::load_file(&local_allow_path))),
            local_denies: Arc::new(Mutex::new(Self::load_file(&local_deny_path))),
            regex_allows: Arc::new(Mutex::new(Self::load_file(&regex_allow_path))),
            regex_denies: Arc::new(Mutex::new(Self::load_file(&regex_deny_path))),
            auto_denies: Arc::new(Mutex::new(Self::load_file(&auto_denies_path))),
            malicious_ip_snapshot: Arc::new(arc_swap::ArcSwap::from_pointee(
                initial_malicious_ips.clone(),
            )),
            malicious_ips: Arc::new(Mutex::new(initial_malicious_ips)),
            base_dir,
            refresh_lock: Mutex::new(()),
            fetch_concurrency: AtomicUsize::new(4),
            rebuild_lock: Mutex::new(()),
            sources_dirty: Arc::new(AtomicBool::new(true)),
            source_config: OnceLock::new(),
            reconcile_lock: Mutex::new(()),
            reconciled_revision: AtomicI64::new(0),
            next_source_transition: AtomicI64::new(0),
            rebuild_requested: AtomicBool::new(false),
            rebuild_running: AtomicBool::new(false),
        }
    }

    fn load_file_ips<P: AsRef<Path>>(path: P) -> HashSet<std::net::IpAddr> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let mut set = HashSet::new();
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && let Ok(ip) = trimmed.parse()
                {
                    set.insert(ip);
                }
            }
        }
        set
    }

    fn load_file<P: AsRef<Path>>(path: P) -> HashSet<String> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let mut set = HashSet::new();
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    set.insert(trimmed.to_string());
                }
            }
        }
        set
    }

    // Always acquire allow before deny so opposite edits are serialized.
    async fn change_rule(
        &self,
        pattern: String,
        action: RuleAction,
        regex: bool,
    ) -> std::io::Result<bool> {
        let (allow_lock, deny_lock, allow_file, deny_file) = if regex {
            (
                &self.regex_allows,
                &self.regex_denies,
                "regex_allow.txt",
                "regex_deny.txt",
            )
        } else {
            (
                &self.local_allows,
                &self.local_denies,
                "local_allow.txt",
                "local_deny.txt",
            )
        };
        let compile_permit = if regex {
            Some(
                self.compile_slots
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "Rule compilation is busy; retry",
                        )
                    })?,
            )
        } else {
            None
        };
        let remote: Vec<_> = if regex {
            self.sources
                .lock()
                .await
                .values()
                .filter(|s| s.active && s.has_regex)
                .map(|s| s.last_rules.clone())
                .collect()
        } else {
            Vec::new()
        };
        let mut allows = allow_lock.clone().lock_owned().await;
        let mut denies = deny_lock.clone().lock_owned().await;
        let allow_path = self.file_path(allow_file);
        let deny_path = self.file_path(deny_file);
        tokio::task::spawn_blocking(move || {
            let _permit = compile_permit;
            if regex {
                RegexFilter::new(std::slice::from_ref(&pattern), &[]).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
                })?;
                let mut next_allows: HashSet<String> = allows.iter().cloned().collect();
                let mut next_denies: HashSet<String> = denies.iter().cloned().collect();
                match action {
                    RuleAction::Allow => {
                        next_allows.insert(pattern.clone());
                        next_denies.remove(&pattern);
                    }
                    RuleAction::Deny => {
                        next_denies.insert(pattern.clone());
                        next_allows.remove(&pattern);
                    }
                }
                Self::extend_remote_regex(&remote, &mut next_allows, &mut next_denies);
                Self::build_regex_filter(
                    next_allows.into_iter().collect(),
                    next_denies.into_iter().collect(),
                )
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            }
            let (target, opposite, target_file, opposite_file) = match action {
                RuleAction::Allow => (&mut allows, &mut denies, allow_path, deny_path),
                RuleAction::Deny => (&mut denies, &mut allows, deny_path, allow_path),
            };
            let mut next_target = (**target).clone();
            let mut next_opposite = (**opposite).clone();
            let inserted = next_target.insert(pattern.clone());
            let removed = next_opposite.remove(&pattern);
            if inserted {
                Self::rewrite_file(&target_file, &next_target)?;
            }
            if removed && let Err(error) = Self::rewrite_file(&opposite_file, &next_opposite) {
                if inserted {
                    // Restore the first file if the second replacement fails.
                    if let Err(rollback) = Self::rewrite_file(&target_file, target) {
                        error!("Failed to roll back rule persistence: {}", rollback);
                    }
                }
                return Err(error);
            }
            **target = next_target;
            **opposite = next_opposite;
            Ok(inserted)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn add_local_rule(&self, pattern: String, action: RuleAction) -> std::io::Result<()> {
        self.change_rule(pattern, action, false).await.map(|_| ())
    }

    pub async fn remove_local_rule(
        &self,
        pattern: &str,
        action: RuleAction,
    ) -> std::io::Result<bool> {
        let (set, filename) = match action {
            RuleAction::Allow => (&self.local_allows, "local_allow.txt"),
            RuleAction::Deny => (&self.local_denies, "local_deny.txt"),
        };
        self.remove_rule(set, filename, pattern, false).await
    }

    fn file_path(&self, filename: &str) -> PathBuf {
        self.base_dir
            .as_ref()
            .map_or_else(|| PathBuf::from(filename), |dir| dir.join(filename))
    }

    pub async fn add_regex_rule(
        &self,
        pattern: String,
        action: RuleAction,
    ) -> std::io::Result<bool> {
        // Rules are persisted one per line. Accept escaped regex sequences
        // such as `\n`, but never literal separators that become new rules
        // when the file is loaded again.
        if pattern.len() > ingest::MAX_RULE_LINE_BYTES || pattern.contains(['\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Regex rules must fit within 16 KiB and must not contain literal line breaks",
            ));
        }
        self.change_rule(pattern, action, true).await
    }

    pub async fn remove_regex_rule(
        &self,
        pattern: &str,
        action: RuleAction,
    ) -> std::io::Result<bool> {
        let (set, filename) = match action {
            RuleAction::Allow => (&self.regex_allows, "regex_allow.txt"),
            RuleAction::Deny => (&self.regex_denies, "regex_deny.txt"),
        };
        self.remove_rule(set, filename, pattern, false).await
    }

    async fn remove_rule(
        &self,
        set: &Arc<Mutex<HashSet<String>>>,
        filename: &str,
        pattern: &str,
        normalized: bool,
    ) -> std::io::Result<bool> {
        let mut current = set.clone().lock_owned().await;
        let path = self.file_path(filename);
        let pattern = pattern.to_string();
        tokio::task::spawn_blocking(move || {
            let mut next = current.clone();
            if normalized {
                let wanted = pattern.trim_end_matches('.');
                next.retain(|entry| !entry.trim_end_matches('.').eq_ignore_ascii_case(wanted));
            } else {
                next.remove(&pattern);
            }
            let changed = next.len() != current.len();
            if changed {
                Self::rewrite_file(path, &next)?;
                *current = next;
            }
            Ok(changed)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn add_auto_deny(&self, pattern: String) -> std::io::Result<bool> {
        let mut current = self.auto_denies.clone().lock_owned().await;
        let path = self.file_path("auto_blocked.txt");
        tokio::task::spawn_blocking(move || {
            if current.contains(&pattern) || current.len() >= MAX_AUTO_DENY_RULES {
                return Ok(false);
            }
            let mut next = current.clone();
            next.insert(pattern);
            Self::rewrite_file(path, &next)?;
            *current = next;
            Ok(true)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn remove_auto_deny(&self, pattern: &str) -> std::io::Result<bool> {
        self.remove_rule(&self.auto_denies, "auto_blocked.txt", pattern, true)
            .await
    }

    fn rewrite_file<P: AsRef<Path>>(path: P, set: &HashSet<String>) -> std::io::Result<()> {
        use std::io::Write;
        let path = path.as_ref();
        let temporary = path.with_extension("tmp");
        let result = (|| {
            let mut file = std::io::BufWriter::new(std::fs::File::create(&temporary)?);
            for line in set {
                writeln!(file, "{}", line)?;
            }
            file.flush()?;
            file.get_ref().sync_all()?;
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    pub async fn add_malicious_ips(&self, ips: Vec<std::net::IpAddr>) -> std::io::Result<()> {
        let mut current = self.malicious_ips.clone().lock_owned().await;
        let path = self.file_path("malicious_ips.txt");
        let snapshot = self.malicious_ip_snapshot.clone();
        tokio::task::spawn_blocking(move || {
            let mut next = current.clone();
            next.extend(ips);
            if next != *current {
                let strings = next.iter().map(ToString::to_string).collect();
                Self::rewrite_file(path, &strings)?;
                snapshot.store(Arc::new(next.clone()));
                *current = next;
            }
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn is_malicious_ip(&self, ip: &std::net::IpAddr) -> bool {
        self.malicious_ip_snapshot.load().contains(ip)
    }

    pub async fn remove_malicious_ip(&self, ip: &std::net::IpAddr) -> std::io::Result<bool> {
        let mut current = self.malicious_ips.clone().lock_owned().await;
        let path = self.file_path("malicious_ips.txt");
        let ip = *ip;
        let snapshot = self.malicious_ip_snapshot.clone();
        tokio::task::spawn_blocking(move || {
            let mut next = current.clone();
            if !next.remove(&ip) {
                return Ok(false);
            }
            let strings = next.iter().map(ToString::to_string).collect();
            Self::rewrite_file(path, &strings)?;
            snapshot.store(Arc::new(next.clone()));
            *current = next;
            Ok(true)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub fn malicious_ips_snapshot(&self) -> Arc<HashSet<std::net::IpAddr>> {
        self.malicious_ip_snapshot.load_full()
    }

    pub async fn add_source(&self, url: String) {
        let mut sources = self.sources.lock().await;
        if !sources.contains_key(&url) {
            sources.insert(
                url.clone(),
                SourceState {
                    url,
                    etag: None,
                    last_modified: None,
                    last_rules: Arc::default(),
                    pattern_bytes: 0,
                    active: true,
                    loaded: false,
                    has_regex: false,
                },
            );
        }
    }

    pub async fn remove_source(&self, url: &str) -> bool {
        let mut sources = self.sources.lock().await;
        let removed = sources.remove(url).is_some();
        if removed {
            self.sources_dirty.store(true, Ordering::Release);
        }
        removed
    }

    async fn sync_source_states(&self, urls: &[String]) {
        let mut sources = self.sources.lock().await;
        let wanted: HashSet<&String> = urls.iter().collect();
        for source in sources.values_mut() {
            let active = wanted.contains(&source.url);
            if active != source.active {
                self.sources_dirty.store(true, Ordering::Release);
            }
            source.active = active;
        }
        for url in urls {
            if !sources.contains_key(url) {
                sources.insert(
                    url.clone(),
                    SourceState {
                        url: url.clone(),
                        etag: None,
                        last_modified: None,
                        last_rules: Arc::default(),
                        pattern_bytes: 0,
                        active: true,
                        loaded: false,
                        has_regex: false,
                    },
                );
                self.sources_dirty.store(true, Ordering::Release);
            }
        }
    }

    async fn restore_local_sources(&self) {
        let pending: Vec<String> = self
            .sources
            .lock()
            .await
            .values()
            .filter(|source| source.active && !is_remote_source(&source.url) && !source.loaded)
            .map(|source| source.url.clone())
            .collect();
        for url in pending {
            match self.fetch_source(&url, None, None).await {
                Ok(Some(fetched)) => {
                    let mut sources = self.sources.lock().await;
                    if retained_rules_fit(
                        &sources,
                        &url,
                        fetched.rules.len(),
                        fetched.pattern_bytes,
                    ) && let Some(source) = sources.get_mut(&url)
                    {
                        source.last_rules = Arc::new(fetched.rules);
                        source.pattern_bytes = fetched.pattern_bytes;
                        source.has_regex = fetched.has_regex;
                        source.loaded = true;
                        self.sources_dirty.store(true, Ordering::Release);
                    }
                }
                Err(error) => warn!("Cannot restore local source {url}: {error}"),
                _ => {}
            }
        }
    }

    pub async fn sync_sources(&self, urls: &[String]) {
        self.sync_source_states(urls).await;
        self.restore_cached_sources().await;
        self.restore_local_sources().await;
        if self.sources_dirty.load(Ordering::Acquire)
            && let Err(error) = self.rebuild_snapshot().await
        {
            error!("Failed to publish source membership: {error}");
        }
    }

    pub fn attach_config(&self, config: Arc<crate::config::ConfigHandle>) {
        let _ = self.source_config.set(config);
    }

    pub async fn bind_config(
        &self,
        config: Arc<crate::config::ConfigHandle>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.attach_config(config);
        self.ensure_current_sources().await
    }

    /// Serialize reconciliation and read the newest committed configuration
    /// inside the lock. Expiry is handled on the query path, without a download
    /// or dependence on the housekeeping sweeper's interval.
    pub async fn ensure_current_sources(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(config) = self.source_config.get() else {
            return Ok(());
        };
        let runtime = config.load_runtime();
        if self.reconciled_revision.load(Ordering::Acquire) == runtime.revision()
            && crate::config::now_epoch() < self.next_source_transition.load(Ordering::Acquire)
        {
            return Ok(());
        }
        let _guard = self.reconcile_lock.lock().await;
        loop {
            let runtime = config.load_runtime();
            let now = crate::config::now_epoch();
            let current = runtime.config();
            let active = current.active_blocklist_urls(now);
            let keep: HashSet<String> = current.configured_blocklist_urls().into_iter().collect();
            self.sync_source_states(&active).await;
            self.sources
                .lock()
                .await
                .retain(|url, _| keep.contains(url));
            self.restore_cached_sources().await;
            self.restore_local_sources().await;
            if self.sources_dirty.load(Ordering::Acquire) {
                self.rebuild_snapshot().await?;
            }
            let next = current
                .category_pauses
                .values()
                .copied()
                .filter(|&until| until > now)
                .min()
                .unwrap_or(i64::MAX);
            self.next_source_transition.store(next, Ordering::Release);
            self.reconciled_revision
                .store(runtime.revision(), Ordering::Release);
            if config.load_runtime().revision() == runtime.revision() {
                return Ok(());
            }
        }
    }

    pub async fn invalidate_source(&self, url: &str) {
        {
            let mut sources = self.sources.lock().await;
            if let Some(state) = sources.get_mut(url) {
                state.etag = None;
                state.last_modified = None;
                state.last_rules = Arc::default();
                state.pattern_bytes = 0;
                state.has_regex = false;
                state.loaded = false;
            }
        }
        self.remove_cached_source(url).await;
    }

    fn cache_paths(&self, url: &str) -> (PathBuf, PathBuf) {
        let dir = self.file_path(CACHE_DIR);
        let key = cache_key(url);
        (
            dir.join(format!("{key}.list")),
            dir.join(format!("{key}.meta")),
        )
    }

    /// Persists a freshly downloaded source body plus its conditional-request
    /// validators. Each file is written to a temp path and renamed into
    /// place, and the meta file -- which `load_cached_sources` requires --
    /// goes last, so a crash mid-write never leaves a torn cache entry.
    async fn write_cached_source(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
        body: &[u8],
    ) -> std::io::Result<()> {
        let (data_path, meta_path) = self.cache_paths(url);
        if let Some(dir) = data_path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let meta = format!(
            "{}\n{}\n{}\n",
            url,
            etag.unwrap_or_default(),
            last_modified.unwrap_or_default()
        );
        for (path, contents) in [(&data_path, body), (&meta_path, meta.as_bytes())] {
            let tmp = PathBuf::from(format!("{}.tmp", path.display()));
            tokio::fs::write(&tmp, contents).await?;
            tokio::fs::rename(&tmp, path).await?;
        }
        Ok(())
    }

    async fn remove_cached_source(&self, url: &str) {
        let (data_path, meta_path) = self.cache_paths(url);
        let _ = tokio::fs::remove_file(meta_path).await;
        let _ = tokio::fs::remove_file(data_path).await;
    }

    /// Loads the on-disk copy of every remote source that has no rules yet,
    /// restoring its rules and validators (so the next refresh is a cheap
    /// conditional request), then deletes cache files belonging to URLs not
    /// in `keep_urls` -- pass every configured URL, including paused and
    /// disabled categories, so their copies survive until they're re-enabled.
    /// Returns how many sources were restored. Does not rebuild the filter.
    pub async fn load_cached_sources(&self, keep_urls: &[String]) -> usize {
        let restored = self.restore_cached_sources().await;
        self.prune_cached_sources(keep_urls).await;
        restored
    }

    async fn restore_cached_sources(&self) -> usize {
        let pending: Vec<String> = {
            let sources = self.sources.lock().await;
            sources
                .values()
                .filter(|s| is_remote_source(&s.url) && !s.loaded)
                .map(|s| s.url.clone())
                .collect()
        };

        let mut restored = 0;
        for url in pending {
            let (data_path, meta_path) = self.cache_paths(&url);
            let Ok(meta) = tokio::fs::read_to_string(&meta_path).await else {
                continue;
            };
            let mut lines = meta.lines();
            if lines.next() != Some(url.as_str()) {
                // Hash collision or foreign file: never apply another URL's rules.
                continue;
            }
            let etag = lines.next().filter(|v| !v.is_empty()).map(str::to_string);
            let last_modified = lines.next().filter(|v| !v.is_empty()).map(str::to_string);

            let Ok(import_permit) = self.import_slots.clone().acquire_owned().await else {
                break;
            };
            let buffer = match read_source(data_path.clone(), import_permit).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!("Cached copy of {} is unreadable: {}", url, e);
                    continue;
                }
            };
            let (_buffer, rules, pattern_bytes, has_regex) = match parse_blocklist(buffer).await {
                Ok(parsed) => parsed,
                Err(e) => {
                    warn!("Failed to parse cached copy of {}: {}", url, e);
                    continue;
                }
            };

            let mut sources = self.sources.lock().await;
            if retained_rules_fit(&sources, &url, rules.len(), pattern_bytes)
                && let Some(state) = sources.get_mut(&url)
                && !state.loaded
            {
                info!(
                    "Restored cached blocklist source: {} ({} rules)",
                    url,
                    rules.len()
                );
                state.etag = etag;
                state.last_modified = last_modified;
                state.last_rules = Arc::new(rules);
                state.pattern_bytes = pattern_bytes;
                state.has_regex = has_regex;
                state.loaded = true;
                restored += 1;
            }
        }

        if restored > 0 {
            self.sources_dirty.store(true, Ordering::Release);
        }
        restored
    }

    async fn prune_cached_sources(&self, keep_urls: &[String]) {
        let keep: HashSet<String> = keep_urls.iter().map(|u| cache_key(u)).collect();
        let Ok(mut entries) = tokio::fs::read_dir(self.file_path(CACHE_DIR)).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !keep.contains(stem) {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }

    pub async fn get_sources_status(&self) -> Vec<(String, usize, bool)> {
        let sources = self.sources.lock().await;
        sources
            .values()
            .filter(|source| source.active)
            .map(|s| {
                (
                    s.url.clone(),
                    s.last_rules.len(),
                    s.etag.is_some() || s.last_modified.is_some(),
                )
            })
            .collect()
    }

    /// Returns None for HTTP 304. Publish validators only with successfully
    /// parsed rules, or a failed import could remain pinned to stale data by 304s.
    async fn fetch_source(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<Option<FetchedSource>, Box<dyn std::error::Error + Send + Sync>> {
        // The same byte/rule limits apply to local, remote and cached input.
        if url.starts_with('/') || url.starts_with("file://") {
            let path = PathBuf::from(url.trim_start_matches("file://"));
            let import_permit = self.import_slots.clone().acquire_owned().await?;
            let buffer = read_source(path, import_permit).await?;
            let (buffer, rules, pattern_bytes, has_regex) = parse_blocklist(buffer).await?;
            return Ok(Some(FetchedSource {
                _permit: buffer.permit,
                body: None,
                pattern_bytes,
                etag: None,
                last_modified: None,
                rules,
                has_regex,
            }));
        }

        let mut req = self.client.get(url);
        if let Some(etag) = etag {
            req = req.header("If-None-Match", etag);
        }
        if let Some(lm) = last_modified {
            req = req.header("If-Modified-Since", lm);
        }

        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            debug!("Source {} not modified (304)", url);
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(format!("HTTP error status: {}", resp.status()).into());
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        let new_last_modified = resp
            .headers()
            .get("Last-Modified")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let import_permit = self.import_slots.clone().acquire_owned().await?;
        let buffer = ImportBuffer {
            bytes: read_response(resp).await?,
            permit: import_permit,
        };
        let (buffer, rules, pattern_bytes, has_regex) = parse_blocklist(buffer).await?;
        Ok(Some(FetchedSource {
            _permit: buffer.permit,
            body: Some(buffer.bytes),
            pattern_bytes,
            etag: new_etag,
            last_modified: new_last_modified,
            rules,
            has_regex,
        }))
    }

    /// Sets the bounded number of source downloads and parsers in flight.
    pub fn set_fetch_concurrency(&self, concurrency: usize) -> Result<(), String> {
        if !(1..=16).contains(&concurrency) {
            return Err("blocklist fetch concurrency must be between 1 and 16".into());
        }
        self.fetch_concurrency.store(concurrency, Ordering::Relaxed);
        Ok(())
    }

    fn extend_remote_regex(
        sources: &[Arc<Vec<FilterRule>>],
        allow: &mut HashSet<String>,
        deny: &mut HashSet<String>,
    ) {
        for source in sources {
            for rule in source
                .iter()
                .filter(|rule| rule.rule_type == RuleType::Regex)
            {
                match rule.action {
                    RuleAction::Allow => {
                        allow.insert(rule.pattern.clone());
                    }
                    RuleAction::Deny => {
                        deny.insert(rule.pattern.clone());
                    }
                }
            }
        }
    }

    async fn validate_source_regex(
        &self,
        url: &str,
        candidate: Arc<Vec<FilterRule>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let permit = self.compile_slots.clone().acquire_owned().await?;
        let mut sources: Vec<_> = self
            .sources
            .lock()
            .await
            .values()
            .filter(|source| source.url != url && source.active && source.has_regex)
            .map(|source| source.last_rules.clone())
            .collect();
        sources.push(candidate);
        let mut allow = self.regex_allows.lock().await.clone();
        let mut deny = self.regex_denies.lock().await.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            Self::extend_remote_regex(&sources, &mut allow, &mut deny);
            Self::build_regex_filter(allow.into_iter().collect(), deny.into_iter().collect())
                .map(|_| ())
        })
        .await??;
        Ok(())
    }

    /// Fetches all sources over the network (conditional GET, so unchanged
    /// sources are cheap but still cost a round-trip), then rebuilds and
    /// reloads the filter snapshot. Use this for the scheduler and explicit
    /// "sync sources" requests. For a local-only rule change (add/remove a
    /// single allow/deny/regex entry), call `rebuild_snapshot()` directly
    /// instead — it reuses already-fetched source rules with no network I/O.
    pub async fn refresh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _refresh_guard = self.refresh_lock.lock().await;
        info!("Starting blocklist refresh...");

        // Release the sources lock before network I/O so a slow download cannot
        // stall rule edits, snapshot rebuilds, or dashboard reads.
        let requests: Vec<(String, Option<String>, Option<String>)> = {
            let sources = self.sources.lock().await;
            sources
                .values()
                .filter(|source| source.active)
                .map(|s| (s.url.clone(), s.etag.clone(), s.last_modified.clone()))
                .collect()
        };

        let mut any_changed = false;
        let mut fetched = stream::iter(requests.into_iter().map(
            |(url, etag, last_modified)| async move {
                info!("Fetching blocklist source: {}", url);
                let result = self
                    .fetch_source(&url, etag.as_deref(), last_modified.as_deref())
                    .await;
                (url, result)
            },
        ))
        .buffer_unordered(self.fetch_concurrency.load(Ordering::Relaxed));
        while let Some((url, result)) = fetched.next().await {
            match result {
                Ok(Some(mut fetched)) => {
                    let candidate = Arc::new(std::mem::take(&mut fetched.rules));
                    if fetched.has_regex
                        && let Err(error) =
                            self.validate_source_regex(&url, candidate.clone()).await
                    {
                        warn!(
                            "Source {url} exceeds the regex compile budget; retaining its previous rules and disk cache: {error}"
                        );
                        continue;
                    }
                    let mut sources = self.sources.lock().await;
                    if !retained_rules_fit(&sources, &url, candidate.len(), fetched.pattern_bytes) {
                        warn!(
                            "Source {} exceeds aggregate rule limit; retaining previous rules",
                            url
                        );
                        continue;
                    }
                    // The source may have been removed while we were fetching.
                    if let Some(state) = sources.get_mut(&url) {
                        if !state.active {
                            continue;
                        }
                        state.etag = fetched.etag.clone();
                        state.last_modified = fetched.last_modified.clone();
                        state.last_rules = candidate;
                        state.pattern_bytes = fetched.pattern_bytes;
                        state.has_regex = fetched.has_regex;
                        state.loaded = true;
                        any_changed = true;
                        info!(
                            "Successfully updated source: {} (found {} rules)",
                            url,
                            state.last_rules.len()
                        );
                    } else {
                        continue;
                    }
                    drop(sources);
                    if let Some(bytes) = fetched.body.take()
                        && let Err(error) = self
                            .write_cached_source(
                                &url,
                                fetched.etag.as_deref(),
                                fetched.last_modified.as_deref(),
                                &bytes,
                            )
                            .await
                    {
                        warn!("Failed to cache blocklist source {}: {}", url, error);
                    }
                }
                Ok(None) => debug!("Source {} unchanged", url),
                Err(e) => {
                    warn!(
                        "Failed to fetch source {}, retaining last known rules: {:?}",
                        url, e
                    );
                }
            }
        }

        let should_rebuild = {
            let sources = self.sources.lock().await;
            let has_any_remote_rules = sources.values().any(|s| !s.last_rules.is_empty());
            let has_any_local_rules = {
                let allows = self.local_allows.lock().await;
                let denies = self.local_denies.lock().await;
                let regex_allows = self.regex_allows.lock().await;
                let regex_denies = self.regex_denies.lock().await;
                let auto_denies = self.auto_denies.lock().await;
                !allows.is_empty()
                    || !denies.is_empty()
                    || !regex_allows.is_empty()
                    || !regex_denies.is_empty()
                    || !auto_denies.is_empty()
            };

            self.sources_dirty.load(Ordering::Acquire)
                || any_changed
                || has_any_local_rules
                || !has_any_remote_rules
        };

        if !should_rebuild {
            info!("No sources or local rules changed. Skipping reload.");
            return Ok(());
        }

        self.rebuild_snapshot().await
    }

    /// Rebuilds and atomically publishes the filter from cached source and local
    /// rules, without network I/O. Use refresh() when downloads are also needed.
    pub async fn rebuild_snapshot(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _rebuild_guard = self.rebuild_lock.lock().await;
        let compile_permit = self.compile_slots.clone().acquire_owned().await?;
        let publication = SnapshotBuildGuard {
            dirty: self.sources_dirty.clone(),
            published: false,
        };
        self.sources_dirty.store(false, Ordering::Release);

        // Share source rules while gathering inputs, then compile on the blocking
        // pool so large lists cannot stall DNS runtime workers.
        let inputs = RuleInputs {
            sources: self
                .sources
                .lock()
                .await
                .values()
                .filter(|source| source.active)
                .map(|s| s.last_rules.clone())
                .collect(),
            local_allows: self.local_allows.lock().await.iter().cloned().collect(),
            local_denies: self.local_denies.lock().await.iter().cloned().collect(),
            // Smart auto-block (add_auto_deny) entries are durable deny rules.
            auto_denies: self.auto_denies.lock().await.iter().cloned().collect(),
            regex_allows: self.regex_allows.lock().await.iter().cloned().collect(),
            regex_denies: self.regex_denies.lock().await.iter().cloned().collect(),
        };

        let engine = self.filter_engine.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = compile_permit;
            let snapshot = Self::build_snapshot(inputs)?;
            engine.reload(snapshot);
            publication.publish();
            Ok::<(), regex::Error>(())
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.sources_dirty.store(true, Ordering::Release);
                return Err(error.into());
            }
            Err(error) => {
                self.sources_dirty.store(true, Ordering::Release);
                return Err(error.into());
            }
        }
        info!("Filter snapshot rebuilt and reloaded (including local rules).");

        Ok(())
    }

    /// Builds the exact/trie/regex filter structures from collected rules.
    /// CPU-bound; call from a blocking thread.
    fn build_snapshot(inputs: RuleInputs) -> Result<FilterSnapshot, regex::Error> {
        let mut exact_allow_set = HashSet::new();
        let mut exact_deny_set = HashSet::new();
        let mut regex_allow_set = HashSet::new();
        let mut regex_deny_set = HashSet::new();

        for rules in &inputs.sources {
            for rule in rules.iter() {
                match (rule.action, rule.rule_type) {
                    (RuleAction::Allow, RuleType::Exact) => {
                        if let Ok(name) = Name::from_str(&rule.pattern) {
                            exact_allow_set.insert(name);
                        }
                    }
                    (RuleAction::Deny, RuleType::Exact) => {
                        if let Ok(name) = Name::from_str(&rule.pattern) {
                            exact_deny_set.insert(name);
                        }
                    }
                    (RuleAction::Allow, RuleType::Regex) => {
                        regex_allow_set.insert(rule.pattern.clone());
                    }
                    (RuleAction::Deny, RuleType::Regex) => {
                        regex_deny_set.insert(rule.pattern.clone());
                    }
                }
            }
        }

        exact_allow_set.extend(
            inputs
                .local_allows
                .iter()
                .filter_map(|p| Name::from_str(p).ok()),
        );
        exact_deny_set.extend(
            inputs
                .local_denies
                .iter()
                .chain(&inputs.auto_denies)
                .filter_map(|p| Name::from_str(p).ok()),
        );
        regex_allow_set.extend(inputs.regex_allows);
        regex_deny_set.extend(inputs.regex_denies);

        // The subdomain trie matches both exact names and any subdomains.
        // Inserting exact rules only into the trie avoids storing every domain
        // twice in memory (once in ExactFilter HashSet and once in SubdomainTrie).
        let exact = ExactFilter::new();
        let mut trie = SubdomainTrie::new();

        for name in &exact_allow_set {
            trie.insert_allow(name);
        }

        for name in &exact_deny_set {
            trie.insert_deny(name);
        }

        let allow_regex: Vec<String> = regex_allow_set.into_iter().collect();
        let deny_regex: Vec<String> = regex_deny_set.into_iter().collect();
        let regex_filter = Self::build_regex_filter(allow_regex, deny_regex)?;

        Ok(FilterSnapshot::new(exact, trie, regex_filter))
    }

    /// Skip individually invalid imported patterns; partition valid large sets.
    /// If compilation still fails, the caller retains the entire last working snapshot.
    fn build_regex_filter(
        allow: Vec<String>,
        deny: Vec<String>,
    ) -> Result<RegexFilter, regex::Error> {
        let keep_valid = |patterns: Vec<String>| -> Vec<String> {
            patterns
                .into_iter()
                .filter(
                    |pattern| match RegexFilter::new(std::slice::from_ref(pattern), &[]) {
                        Ok(_) => true,
                        Err(error) => {
                            warn!("Skipping invalid regex rule {:?}: {}", pattern, error);
                            false
                        }
                    },
                )
                .collect()
        };
        // Fast path also avoids compiling every ordinary rule individually.
        match RegexFilter::new(&allow, &deny) {
            Ok(filter) => Ok(filter),
            Err(_) => RegexFilter::new(&keep_valid(allow), &keep_valid(deny)),
        }
    }

    /// Schedules a background `rebuild_snapshot()`, coalescing bursts: any
    /// number of requests made while a rebuild is running collapse into a
    /// single follow-up rebuild. Used from the query path (smart auto-block),
    /// where each new rule would otherwise trigger its own full rebuild.
    pub fn request_rebuild(self: &Arc<Self>) {
        self.rebuild_requested.store(true, Ordering::SeqCst);
        if self.rebuild_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let updater = self.clone();
        tokio::spawn(async move {
            loop {
                while updater.rebuild_requested.swap(false, Ordering::SeqCst) {
                    if let Err(e) = updater.rebuild_snapshot().await {
                        error!("Background filter rebuild failed: {:?}", e);
                    }
                }
                updater.rebuild_running.store(false, Ordering::SeqCst);
                // A request may have landed between the last swap and the
                // store above; pick it up unless another task already has.
                if !updater.rebuild_requested.load(Ordering::SeqCst)
                    || updater.rebuild_running.swap(true, Ordering::SeqCst)
                {
                    break;
                }
            }
        });
    }

    pub async fn start_scheduler(
        self: Arc<Self>,
        cron_expr: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sched = JobScheduler::new().await?;
        let updater = self.clone();

        let job = Job::new_async(cron_expr, move |_uuid, _l| {
            let updater = updater.clone();
            Box::pin(async move {
                if let Err(e) = updater.refresh().await {
                    error!("Scheduled blocklist refresh failed: {:?}", e);
                }
            })
        })?;

        sched.add(job).await?;
        sched.start().await?;

        info!("Blocklist updater scheduler active: {}", cron_expr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filter::FilterVerdict;

    #[tokio::test]
    async fn auto_deny_growth_is_bounded_without_discarding_existing_rules() {
        let directory = tempfile::tempdir().unwrap();
        let engine = Arc::new(FilterEngine::new(FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::empty(),
        )));
        let updater =
            BlocklistUpdater::new_with_dir(engine, vec![], directory.path().to_path_buf());
        updater
            .auto_denies
            .lock()
            .await
            .extend((0..MAX_AUTO_DENY_RULES).map(|i| format!("rule-{i}.example")));
        assert!(
            !updater
                .add_auto_deny("one-more.example".into())
                .await
                .unwrap()
        );
        let rules = updater.auto_denies.lock().await;
        assert_eq!(rules.len(), MAX_AUTO_DENY_RULES);
        assert!(rules.contains("rule-0.example"));
        assert!(!directory.path().join("auto_blocked.txt").exists());
    }

    #[tokio::test]
    async fn source_fetches_obey_configured_concurrency() {
        use std::sync::atomic::AtomicUsize;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let active_clone = active.clone();
        let peak_clone = peak.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let active = active_clone.clone();
                let peak = peak_clone.clone();
                tokio::spawn(async move {
                    let mut request = [0; 2048];
                    let received = socket.read(&mut request).await.unwrap();
                    assert!(received > 0);
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nblocked.example\n").await.unwrap();
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let updater = BlocklistUpdater::new_with_dir(
            empty_engine(),
            (0..8).map(|i| format!("http://{address}/{i}")).collect(),
            dir.path().to_path_buf(),
        );
        assert!(updater.set_fetch_concurrency(0).is_err());
        updater.set_fetch_concurrency(3).unwrap();
        updater.refresh().await.unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 3);
        assert!(
            updater
                .get_sources_status()
                .await
                .iter()
                .all(|(_, rules, _)| *rules == 1)
        );
        server.abort();
    }

    #[tokio::test]
    async fn failed_persistence_keeps_memory_and_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let updater =
            BlocklistUpdater::new_with_dir(empty_engine(), vec![], dir.path().to_path_buf());
        updater
            .add_local_rule("old.example".into(), RuleAction::Allow)
            .await
            .unwrap();
        // A directory at the temporary path forces replacement to fail.
        std::fs::create_dir(dir.path().join("local_allow.tmp")).unwrap();
        assert!(
            updater
                .add_local_rule("new.example".into(), RuleAction::Allow)
                .await
                .is_err()
        );
        assert!(!updater.local_allows.lock().await.contains("new.example"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("local_allow.txt")).unwrap(),
            "old.example\n"
        );
    }

    #[tokio::test]
    async fn failed_opposite_removal_rolls_back_first_file() {
        let dir = tempfile::tempdir().unwrap();
        let updater =
            BlocklistUpdater::new_with_dir(empty_engine(), vec![], dir.path().to_path_buf());
        updater
            .add_local_rule("flip.example".into(), RuleAction::Deny)
            .await
            .unwrap();
        std::fs::create_dir(dir.path().join("local_deny.tmp")).unwrap();
        assert!(
            updater
                .add_local_rule("flip.example".into(), RuleAction::Allow)
                .await
                .is_err()
        );
        assert!(!updater.local_allows.lock().await.contains("flip.example"));
        assert!(updater.local_denies.lock().await.contains("flip.example"));
        assert!(
            std::fs::read_to_string(dir.path().join("local_allow.txt"))
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_updater_pipeline_and_failure_isolation() {
        let plain_file = std::env::temp_dir().join("test_plain_blocklist.txt");
        tokio::fs::write(&plain_file, b"blocked1.example.com\nblocked2.example.com\n")
            .await
            .unwrap();

        let hosts_file = std::env::temp_dir().join("test_hosts_blocklist.txt");
        tokio::fs::write(
            &hosts_file,
            b"127.0.0.1 blocked3.example.com\n0.0.0.0 blocked4.example.com\n",
        )
        .await
        .unwrap();

        let exact = ExactFilter::new();
        let trie = SubdomainTrie::new();
        let regex = RegexFilter::new(&[], &[]).unwrap();
        let snapshot = FilterSnapshot::new(exact, trie, regex);
        let engine = Arc::new(FilterEngine::new(snapshot));

        let urls = vec![
            format!("file://{}", plain_file.to_str().unwrap()),
            format!("file://{}", hosts_file.to_str().unwrap()),
            "file:///nonexistent/path/to/blocklist.txt".to_string(),
        ];

        let updater = BlocklistUpdater::new(engine.clone(), urls);

        updater.refresh().await.unwrap();

        assert_eq!(
            engine.check(&Name::from_str("blocked1.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("blocked2.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("blocked3.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("blocked4.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("allowed.example.com.").unwrap()),
            FilterVerdict::Pass
        );

        let _ = std::fs::remove_file(plain_file);
        let _ = std::fs::remove_file(hosts_file);
    }

    #[tokio::test]
    async fn test_auto_denies_are_folded_into_rebuilt_snapshot() {
        let snapshot = FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        let engine = Arc::new(FilterEngine::new(snapshot));
        // Use a scratch dir so add_auto_deny's on-disk persistence doesn't
        // write auto_blocked.txt into the repo's working directory.
        let base_dir = std::env::temp_dir().join(format!("dns-deny-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();
        let updater = BlocklistUpdater::new_with_dir(engine.clone(), vec![], base_dir.clone());

        assert_eq!(
            engine.check(&Name::from_str("auto-blocked.example.com.").unwrap()),
            FilterVerdict::Pass
        );

        updater
            .add_auto_deny("auto-blocked.example.com".to_string())
            .await
            .unwrap();
        updater.rebuild_snapshot().await.unwrap();

        assert_eq!(
            engine.check(&Name::from_str("auto-blocked.example.com.").unwrap()),
            FilterVerdict::Block
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn test_local_allow_deny_persist_across_restart() {
        // Use a scratch dir so this test's on-disk persistence doesn't write
        // local_allow.txt/local_deny.txt into the repo's working directory.
        let base_dir =
            std::env::temp_dir().join(format!("dns-deny-test-persist-{}", std::process::id()));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();

        let snapshot = FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        let engine = Arc::new(FilterEngine::new(snapshot));
        let updater = BlocklistUpdater::new_with_dir(engine.clone(), vec![], base_dir.clone());

        updater
            .add_local_rule("persisted-allow.example.com".to_string(), RuleAction::Allow)
            .await
            .unwrap();
        updater
            .add_local_rule("persisted-deny.example.com".to_string(), RuleAction::Deny)
            .await
            .unwrap();

        // Simulate a process restart: construct a brand new BlocklistUpdater
        // pointed at the same directory, with a fresh FilterEngine.
        let snapshot2 = FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        let engine2 = Arc::new(FilterEngine::new(snapshot2));
        let reloaded = BlocklistUpdater::new_with_dir(engine2, vec![], base_dir.clone());

        assert!(
            reloaded
                .local_allows
                .lock()
                .await
                .contains("persisted-allow.example.com"),
            "expected local_allows to survive a restart"
        );
        assert!(
            reloaded
                .local_denies
                .lock()
                .await
                .contains("persisted-deny.example.com"),
            "expected local_denies to survive a restart"
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn test_adding_to_allow_removes_from_deny_and_vice_versa() {
        let base_dir =
            std::env::temp_dir().join(format!("dns-deny-test-exclusive-{}", std::process::id()));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();
        let snapshot = FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        let engine = Arc::new(FilterEngine::new(snapshot));
        let updater = BlocklistUpdater::new_with_dir(engine, vec![], base_dir.clone());

        updater
            .add_local_rule("flip.example.com".to_string(), RuleAction::Deny)
            .await
            .unwrap();
        assert!(
            updater
                .local_denies
                .lock()
                .await
                .contains("flip.example.com")
        );

        updater
            .add_local_rule("flip.example.com".to_string(), RuleAction::Allow)
            .await
            .unwrap();
        assert!(
            updater
                .local_allows
                .lock()
                .await
                .contains("flip.example.com")
        );
        assert!(
            !updater
                .local_denies
                .lock()
                .await
                .contains("flip.example.com"),
            "adding to allow must remove the same pattern from deny"
        );

        updater
            .add_local_rule("flip.example.com".to_string(), RuleAction::Deny)
            .await
            .unwrap();
        assert!(
            updater
                .local_denies
                .lock()
                .await
                .contains("flip.example.com")
        );
        assert!(
            !updater
                .local_allows
                .lock()
                .await
                .contains("flip.example.com"),
            "adding to deny must remove the same pattern from allow"
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn test_regex_adding_to_allow_removes_from_deny_and_vice_versa() {
        let base_dir = std::env::temp_dir().join(format!(
            "dns-deny-test-regex-exclusive-{}",
            std::process::id()
        ));
        tokio::fs::create_dir_all(&base_dir).await.unwrap();
        let snapshot = FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        );
        let engine = Arc::new(FilterEngine::new(snapshot));
        let updater = BlocklistUpdater::new_with_dir(engine, vec![], base_dir.clone());

        updater
            .add_regex_rule(r"^flip\.".to_string(), RuleAction::Deny)
            .await
            .unwrap();
        assert!(updater.regex_denies.lock().await.contains(r"^flip\."));

        updater
            .add_regex_rule(r"^flip\.".to_string(), RuleAction::Allow)
            .await
            .unwrap();
        assert!(updater.regex_allows.lock().await.contains(r"^flip\."));
        assert!(
            !updater.regex_denies.lock().await.contains(r"^flip\."),
            "adding to regex allow must remove the same pattern from regex deny"
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    fn empty_engine() -> Arc<FilterEngine> {
        Arc::new(FilterEngine::new(FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        )))
    }

    #[tokio::test]
    async fn test_request_rebuild_applies_auto_deny_without_explicit_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let engine = empty_engine();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![],
            dir.path().to_path_buf(),
        ));
        let name = Name::from_str("smart-blocked.example.com.").unwrap();

        assert!(
            updater
                .add_auto_deny("smart-blocked.example.com".to_string())
                .await
                .unwrap()
        );
        updater.request_rebuild();
        // A burst of requests must coalesce rather than error or deadlock.
        updater.request_rebuild();
        updater.request_rebuild();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while engine.check(&name) != FilterVerdict::Block {
            assert!(
                std::time::Instant::now() < deadline,
                "auto-deny was never applied to the live filter"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn test_invalid_regex_does_not_break_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        // Write rule files directly: the API validates regexes, but remote
        // sources and hand-edited files don't.
        std::fs::write(
            dir.path().join("local_deny.txt"),
            "exact-blocked.example.com\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("regex_deny.txt"),
            "^valid-regex\\.\n(unclosed\n",
        )
        .unwrap();

        let engine = empty_engine();
        let updater =
            BlocklistUpdater::new_with_dir(engine.clone(), vec![], dir.path().to_path_buf());
        updater.rebuild_snapshot().await.unwrap();

        assert_eq!(
            engine.check(&Name::from_str("exact-blocked.example.com.").unwrap()),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.check(&Name::from_str("valid-regex.example.com.").unwrap()),
            FilterVerdict::Block
        );
    }

    #[tokio::test]
    async fn test_refresh_does_not_hold_sources_lock_during_fetch() {
        // A source that accepts the connection and never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            empty_engine(),
            vec![format!("http://{addr}/hosts")],
            dir.path().to_path_buf(),
        ));

        let refreshing = updater.clone();
        let refresh = tokio::spawn(async move { refreshing.refresh().await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let budget = std::time::Duration::from_secs(2);
        tokio::time::timeout(budget, updater.rebuild_snapshot())
            .await
            .expect("rebuild_snapshot blocked behind an in-progress refresh")
            .unwrap();
        tokio::time::timeout(budget, updater.get_sources_status())
            .await
            .expect("get_sources_status blocked behind an in-progress refresh");

        refresh.abort();
        server.abort();
    }

    /// Minimal HTTP server answering every request with `200`, an ETag and
    /// `body`. Returns its base URL; abort the handle to take it offline.
    async fn serve_blocklist(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn test_downloaded_source_is_restored_from_cache_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (base, server) = serve_blocklist("cached-blocked.example.com\n").await;
        let url = format!("{base}/hosts");
        let name = Name::from_str("cached-blocked.example.com.").unwrap();

        let updater =
            BlocklistUpdater::new_with_dir(empty_engine(), vec![url.clone()], dir.path().into());
        updater.refresh().await.unwrap();
        server.abort();

        // "Restart" with the source offline: a fresh updater and engine.
        let engine = empty_engine();
        let restarted =
            BlocklistUpdater::new_with_dir(engine.clone(), vec![url.clone()], dir.path().into());
        assert_eq!(
            restarted
                .load_cached_sources(std::slice::from_ref(&url))
                .await,
            1
        );
        restarted.rebuild_snapshot().await.unwrap();
        assert_eq!(engine.check(&name), FilterVerdict::Block);

        // Validators were restored too, so the next refresh is conditional.
        let status = restarted.get_sources_status().await;
        assert_eq!(status, vec![(url, 1, true)]);
    }

    #[tokio::test]
    async fn test_cache_entry_for_a_different_url_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://lists.example.com/a.txt".to_string();
        let updater =
            BlocklistUpdater::new_with_dir(empty_engine(), vec![url.clone()], dir.path().into());
        let (data_path, meta_path) = updater.cache_paths(&url);
        std::fs::create_dir_all(data_path.parent().unwrap()).unwrap();
        std::fs::write(&data_path, "wrong.example.com\n").unwrap();
        std::fs::write(&meta_path, "https://other.example.com/b.txt\n\n\n").unwrap();

        assert_eq!(updater.load_cached_sources(&[url]).await, 0);
    }

    #[tokio::test]
    async fn test_prune_and_invalidate_remove_cached_copies() {
        let dir = tempfile::tempdir().unwrap();
        let kept = "https://lists.example.com/kept.txt".to_string();
        let gone = "https://lists.example.com/gone.txt".to_string();
        let updater =
            BlocklistUpdater::new_with_dir(empty_engine(), vec![kept.clone()], dir.path().into());
        for url in [&kept, &gone] {
            updater
                .write_cached_source(url, None, None, b"x.example.com\n")
                .await
                .unwrap();
        }

        updater
            .load_cached_sources(std::slice::from_ref(&kept))
            .await;
        assert!(updater.cache_paths(&kept).0.exists());
        assert!(!updater.cache_paths(&gone).0.exists());
        assert!(!updater.cache_paths(&gone).1.exists());

        updater.invalidate_source(&kept).await;
        assert!(!updater.cache_paths(&kept).0.exists());
        assert!(!updater.cache_paths(&kept).1.exists());
    }

    /// Runs `work` on this (single-threaded) test runtime alongside a 1ms
    /// timer task, and reports whether the timer fired before `work`
    /// finished. CPU-bound work done inline on the runtime starves the timer
    /// until it completes; work moved to the blocking pool doesn't.
    async fn runtime_stayed_responsive<F: std::future::Future>(work: F) -> bool {
        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();
        let timer = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            flag.store(true, Ordering::SeqCst);
        });
        work.await;
        let responsive = fired.load(Ordering::SeqCst);
        timer.abort();
        responsive
    }

    #[tokio::test]
    async fn test_parsing_and_rebuild_run_off_the_runtime_thread() {
        let dir = tempfile::tempdir().unwrap();
        // Large enough that parsing it and building the trie takes far
        // longer than the 1ms timer.
        let list: String = (0..50_000)
            .map(|i| format!("host{i}.big-list.example\n"))
            .collect();
        let list_path = dir.path().join("big.txt");
        std::fs::write(&list_path, &list).unwrap();

        // Control: the harness must actually detect blocking work.
        assert!(
            !runtime_stayed_responsive(async {
                std::thread::sleep(std::time::Duration::from_millis(50))
            })
            .await
        );

        let engine = empty_engine();
        let updater = BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![list_path.to_str().unwrap().to_string()],
            dir.path().into(),
        );

        // `parse_blocklist`'s only await is the hand-off to the blocking pool,
        // so this isolates parsing (unlike `refresh`, whose file read yields
        // on its own).
        assert!(
            runtime_stayed_responsive(async {
                let (_, rules, _, _) = parse_blocklist(list.into_bytes()).await.unwrap();
                assert_eq!(rules.len(), 50_000);
            })
            .await,
            "blocklist parsing blocked the runtime thread"
        );

        updater.refresh().await.unwrap();
        assert!(
            runtime_stayed_responsive(async { updater.rebuild_snapshot().await.unwrap() }).await,
            "rebuild_snapshot blocked the runtime thread"
        );
        assert_eq!(
            engine.check(&Name::from_str("host123.big-list.example.").unwrap()),
            FilterVerdict::Block
        );
    }
}

#[cfg(test)]
mod import_security_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn paused_source_keeps_validators_for_its_retained_rules() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/list", listener.local_addr().unwrap());
        let (requested, received) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let length = socket.read(&mut request).await.unwrap();
            assert!(length > 0);
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nETag: good\r\nConnection: close\r\n\r\nblocked.example\n").await.unwrap();
            drop(socket);
            let (mut socket, _) = listener.accept().await.unwrap();
            let length = socket.read(&mut request).await.unwrap();
            assert!(length > 0);
            requested.send(()).unwrap();
            released.await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nETag: newer\r\nConnection: close\r\n\r\nnew.example\n").await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(FilterEngine::new(FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::empty(),
        )));
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![url.clone()],
            dir.path().into(),
        ));
        updater.refresh().await.unwrap();
        let refreshing = updater.clone();
        let refresh = tokio::spawn(async move { refreshing.refresh().await.unwrap() });
        received.await.unwrap();
        updater.sync_sources(&[]).await;
        release.send(()).unwrap();
        refresh.await.unwrap();
        updater.sync_sources(std::slice::from_ref(&url)).await;
        let sources = updater.sources.lock().await;
        assert_eq!(sources[&url].etag.as_deref(), Some("good"));
        assert_eq!(sources[&url].last_rules[0].pattern, "blocked.example");
        assert_eq!(
            engine.check(&Name::from_ascii("blocked.example.").unwrap()),
            filter::FilterVerdict::Block
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_declared_and_chunked_sources_preserve_rules_and_disk_cache() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for attempt in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let length = socket.read(&mut request).await.unwrap();
                if attempt > 0 {
                    assert!(
                        String::from_utf8_lossy(&request[..length]).contains("if-none-match: good")
                    );
                }
                match attempt {
                    0 => socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nETag: good\r\nConnection: close\r\n\r\nblocked.example\n").await.unwrap(),
                    1 => {
                        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: bad\r\nConnection: close\r\n\r\n", ingest::MAX_SOURCE_BYTES + 1);
                        socket.write_all(header.as_bytes()).await.unwrap();
                    }
                    _ => {
                        socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: bad\r\nConnection: close\r\n\r\n").await.unwrap();
                        let block = vec![b'x'; 64 * 1024];
                        for _ in 0..=(ingest::MAX_SOURCE_BYTES / block.len()) {
                            if socket.write_all(b"10000\r\n").await.is_err()
                                || socket.write_all(&block).await.is_err()
                                || socket.write_all(b"\r\n").await.is_err() { break; }
                        }
                        let _ = socket.write_all(b"0\r\n\r\n").await;
                    }
                }
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(FilterEngine::new(FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::empty(),
        )));
        let url = format!("http://{address}/list");
        let updater = BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![url.clone()],
            dir.path().to_path_buf(),
        );
        updater.refresh().await.unwrap();
        let (body_path, meta_path) = updater.cache_paths(&url);
        let metadata = tokio::fs::read(&meta_path).await.unwrap();
        for _ in 0..2 {
            updater.refresh().await.unwrap();
            assert_eq!(
                engine.check(&Name::from_ascii("blocked.example.").unwrap()),
                filter::FilterVerdict::Block
            );
            assert_eq!(
                tokio::fs::read(&body_path).await.unwrap(),
                b"blocked.example\n"
            );
            assert_eq!(tokio::fs::read(&meta_path).await.unwrap(), metadata);
        }
        server.await.unwrap();
    }

    #[test]
    fn aggregate_rule_budget_rejects_growth_and_allows_replacement() {
        let rules = vec![
            FilterRule {
                pattern: "blocked.example".into(),
                action: RuleAction::Deny,
                rule_type: RuleType::Exact
            };
            MAX_RETAINED_SOURCE_RULES
        ];
        let sources = HashMap::from([(
            "one".into(),
            SourceState {
                url: "one".into(),
                etag: None,
                last_modified: None,
                pattern_bytes: rules.iter().map(|rule| rule.pattern.len()).sum(),
                last_rules: Arc::new(rules),
                active: true,
                loaded: false,
                has_regex: false,
            },
        )]);
        let new = [FilterRule {
            pattern: "new.example".into(),
            action: RuleAction::Deny,
            rule_type: RuleType::Exact,
        }];
        assert!(!retained_rules_fit(
            &sources,
            "two",
            new.len(),
            new[0].pattern.len()
        ));
        assert!(retained_rules_fit(
            &sources,
            "one",
            new.len(),
            new[0].pattern.len()
        ));
    }
}
