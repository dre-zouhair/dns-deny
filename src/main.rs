use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};

use core_dns::cache::l1::L1Cache;
use core_dns::cache::l2::L2Cache;
use core_dns::config::{Config, ConfigHandle};
use core_dns::config_store::ConfigStore;
use core_dns::handler::{DnsHandler, RATE_LIMIT_CONFIG, RateLimitConfig};
use core_dns::listener::run_server;
use core_dns::network::NetworkTracker;
use core_dns::recursor::RecursiveResolver;
use core_dns::updater::BlocklistUpdater;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing — RUST_LOG controls log levels at runtime.
    // Default: info for all crates; quieter for high-volume filter/ingest crates.
    let env_filter = EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| {
        EnvFilter::new("dns_deny=info,core_dns=info,filter=warn,logger=info,api=info,ingest=warn")
    });
    fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(false)
        .init();

    info!("Initializing DNS Deny server...");

    let state_db_path = env::var("DNS_STATE_DB").unwrap_or_else(|_| "state.db".to_string());
    let config_path = env::var("DNS_CONFIG").unwrap_or_else(|_| "config/default.toml".to_string());

    let (config_handle, _source) = initialize_runtime_config(
        std::path::Path::new(&state_db_path),
        std::path::Path::new(&config_path),
    )?;
    let config = Arc::new(config_handle);

    let (
        upstreams,
        dnssec_validation,
        ratelimit_qps_per_worker,
        ratelimit_max_ips,
        ratelimit_window_duration_secs,
        cache_l1_max_entries,
        cache_l2_max_size_mb,
        _cache_negative_ttl_fallback_secs,
        _auto_block_upstream_sinkholes,
        auto_block_upstreams,
        _smart_ip_blocking,
        logging_enabled,
        logging_db_path,
        logging_channel_capacity,
        logging_retention_days,
        bind_address,
        blocklist_refresh_cron,
    ) = {
        let conf = config.load();
        (
            conf.upstreams.clone(),
            conf.dnssec_validation,
            conf.ratelimit_qps_per_worker,
            conf.ratelimit_max_ips,
            conf.ratelimit_window_duration_secs,
            conf.cache_l1_max_entries,
            conf.cache_l2_max_size_mb,
            conf.cache_negative_ttl_fallback_secs,
            conf.auto_block_upstream_sinkholes,
            conf.auto_block_upstreams.clone(),
            conf.smart_ip_blocking,
            conf.logging_enabled,
            conf.logging_db_path.clone(),
            conf.logging_channel_capacity,
            conf.logging_retention_days,
            conf.bind_address.clone(),
            conf.blocklist_refresh_cron.clone(),
        )
    };

    let rate_limit_config = RateLimitConfig {
        limit_per_window: ratelimit_qps_per_worker,
        max_entries: ratelimit_max_ips,
        window_duration: Duration::from_secs(ratelimit_window_duration_secs),
    };
    RATE_LIMIT_CONFIG
        .set(rate_limit_config)
        .map_err(|_| "failed to set global rate limit config")?;

    let dns_port: u16 = env::var("DNS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(53);

    // DNS_PORT overrides are applied after config validation; check the actual ports.
    {
        let conf = config.load();
        if conf.api_enabled && conf.api_port == dns_port {
            return Err(format!(
                "api_port ({}) collides with the DNS listener port ({}); \
                 DNS_PORT may have overridden the configured DNS port",
                conf.api_port, dns_port
            )
            .into());
        }
    }

    // Reject an invalid bind address rather than exposing DNS on all interfaces.
    let ip_addr: IpAddr = bind_address
        .parse()
        .map_err(|e| format!("invalid bind_address '{}': {}", bind_address, e))?;
    let listen_addr = SocketAddr::new(ip_addr, dns_port);

    if upstreams.is_empty() {
        return Err("no upstream servers configured".into());
    }

    let mut name_servers = Vec::new();
    for upstream in &upstreams {
        name_servers.push(core_dns::config::build_name_server_config(upstream)?);
    }
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut resolver_opts = ResolverOpts::default();
    resolver_opts.validate = dnssec_validation;
    resolver_opts.preserve_intermediates = true;
    resolver_opts.attempts = 2; // 1 retry on timeout
    resolver_opts.timeout = Duration::from_secs(2);

    let resolver =
        TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
            .with_options(resolver_opts.clone())
            .build()?;

    // Construct once so enabling recursive mode at runtime uses the requested resolver.
    let recursive_resolver = Some(Arc::new(RecursiveResolver::new(dnssec_validation)?));

    let discovery_resolver = if !auto_block_upstreams.is_empty() {
        let mut disc_servers = Vec::new();
        for upstream in &auto_block_upstreams {
            let name_server = core_dns::config::build_name_server_config(upstream)?;
            match upstream.protocol.as_str() {
                "udp" => {
                    disc_servers.push(name_server.clone());
                }
                "tcp" => {
                    disc_servers.push(name_server.clone());
                }
                "dot" => {
                    disc_servers.push(name_server.clone());
                }
                "doh" => {
                    disc_servers.push(name_server);
                }
                other => {
                    return Err(
                        format!("unsupported auto_block upstream protocol: {}", other).into(),
                    );
                }
            }
        }
        let disc_config = ResolverConfig::from_parts(None, vec![], disc_servers);
        Some(
            TokioResolver::builder_with_config(disc_config, TokioRuntimeProvider::default())
                .with_options(resolver_opts)
                .build()?,
        )
    } else {
        None
    };

    let l1_cache = Arc::new(L1Cache::new(cache_l1_max_entries));
    // Reclaim expired entries even when they are never looked up again.
    l1_cache.clone().start_reaper_task(Duration::from_secs(60));
    let l2_cache = L2Cache::new(cache_l2_max_size_mb * 1024 * 1024);

    let exact = filter::exact::ExactFilter::new();
    let trie = filter::trie::SubdomainTrie::new();
    let regex_filter = filter::regex_set::RegexFilter::new(&[], &[])?;
    let snapshot = filter::snapshot::FilterSnapshot::new(exact, trie, regex_filter);
    let filter_engine = Arc::new(filter::FilterEngine::new(snapshot));

    let logger = if logging_enabled {
        info!("Initializing query logger at {}", logging_db_path);
        let ql = logger::QueryLogger::new(
            &logging_db_path,
            logging_channel_capacity,
            logging_retention_days,
        );
        Some(Arc::new(ql))
    } else {
        None
    };

    let updater = Arc::new(BlocklistUpdater::new(
        filter_engine.clone(),
        config.load().blocklist_urls.clone(),
    ));

    updater.set_fetch_concurrency(config.load().blocklist_fetch_concurrency)?;

    // Restore filtering before opening the listener, including when the network is down.
    updater
        .bind_config(config.clone())
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    let configured_urls = config.load().configured_blocklist_urls();
    updater.load_cached_sources(&configured_urls).await;
    info!("Filter ready from local rules and cached blocklist sources");

    // Refresh from the network in the background so it doesn't block startup.
    let startup_updater = updater.clone();

    let network_tracker = Arc::new(NetworkTracker::new());
    // Refresh neighbor mappings off the query path.
    network_tracker
        .clone()
        .start_arp_refresh_task(Duration::from_secs(5));

    tokio::spawn(async move {
        tracing::info!("Performing initial remote blocklist sync...");
        if let Err(e) = startup_updater.refresh().await {
            tracing::error!("Failed to reload engine after initial sync: {:?}", e);
        } else {
            tracing::info!("Initial remote blocklist sync complete.");
        }
    });

    // Keep remote sources current without requiring an admin sync.
    if let Err(e) = updater
        .clone()
        .start_scheduler(&blocklist_refresh_cron)
        .await
    {
        tracing::error!(
            "Failed to start blocklist refresh scheduler ({}): {:?}",
            blocklist_refresh_cron,
            e
        );
    }

    // Persist expired pauses even when no query arrives to observe their expiry.
    let pause_sweeper = Arc::new(core_dns::protection::PauseSweeper::new(
        config.clone(),
        updater.clone(),
        l1_cache.clone(),
        l2_cache.clone(),
    ));
    pause_sweeper.start_pause_sweep_task(Duration::from_secs(30));

    let doh_client_slot = {
        let conf = config.load();
        let client = if conf.encrypted_upstream_enabled {
            info!(
                "Initializing DNS-over-HTTPS (DoH) upstream at: {}",
                conf.encrypted_upstream_url
            );
            Some(Arc::new(core_dns::doh::DohClient::new(
                conf.encrypted_upstream_url.clone(),
            )?))
        } else {
            None
        };
        Arc::new(arc_swap::ArcSwapOption::new(client))
    };

    // The optional API dependency is absent from resolver-only builds.
    #[cfg(feature = "feat-api")]
    if config.load().api_enabled {
        let api_config = config.clone();
        let api_updater = updater.clone();
        let api_logger = logger.clone();
        let api_l1 = l1_cache.clone();
        let api_l2 = l2_cache.clone();
        let api_nt = network_tracker.clone();
        api::start_admin_api_with_doh(
            api_config,
            api_updater,
            api_l1,
            api_l2,
            api_logger,
            api_nt,
            doh_client_slot.clone(),
        )
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    }

    let handler = DnsHandler::new(
        resolver,
        recursive_resolver,
        discovery_resolver,
        l1_cache,
        l2_cache,
        filter_engine,
        updater.clone(),
        config.clone(),
        logger,
        network_tracker.clone(),
        doh_client_slot,
    );

    let num_workers = num_cpus::get().max(1);

    info!("DNS Deny listening on {}", listen_addr);
    run_server(listen_addr, handler, num_workers).await?;

    Ok(())
}

mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLoadSource {
    Database(i64),
    Seed(i64),
}

pub fn initialize_runtime_config(
    state_db_path: &std::path::Path,
    seed_toml_path: &std::path::Path,
) -> Result<(ConfigHandle, ConfigLoadSource), Box<dyn std::error::Error>> {
    let store = ConfigStore::open(state_db_path)?;
    if let Some((config, revision)) = store.load_current()? {
        info!(
            "Loaded configuration from SQLite state database '{}' (revision {})",
            state_db_path.display(),
            revision
        );
        if config.api_enabled && core_dns::config::is_known_default_api_key(&config.api_key) {
            warn!(
                "The admin API key is a publicly known default value. Anyone who can reach \
                 the dashboard can administer this server -- change it from the dashboard now."
            );
        }
        let handle = ConfigHandle::new_persistent(store, config, revision)
            .map_err(|e| format!("failed to initialize runtime snapshot: {e}"))?;
        Ok((handle, ConfigLoadSource::Database(revision)))
    } else {
        info!(
            "State database '{}' has no configuration row; seeding from '{}'",
            state_db_path.display(),
            seed_toml_path.display()
        );
        let raw_config = Config::load(seed_toml_path)?;
        // The configured key is used as-is. A published sample key still
        // works, but is called out so it gets changed before exposure.
        if raw_config.api_enabled && core_dns::config::is_known_default_api_key(&raw_config.api_key)
        {
            warn!(
                "Seed config '{}' uses a publicly known sample api_key. Set your own api_key \
                 in the config file, or change the password from the dashboard after signing in.",
                seed_toml_path.display()
            );
        }
        raw_config
            .validate()
            .map_err(|e| format!("Configuration error: {e}"))?;
        let revision = store.insert_seed(&raw_config)?;
        info!(
            "Seeded configuration into '{}' from '{}' (revision {})",
            state_db_path.display(),
            seed_toml_path.display(),
            revision
        );
        let handle = ConfigHandle::new_persistent(store, raw_config, revision)
            .map_err(|e| format!("failed to initialize runtime snapshot: {e}"))?;
        Ok((handle, ConfigLoadSource::Seed(revision)))
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    fn write_test_toml(path: &std::path::Path, safesearch: bool) {
        let content = format!(
            r#"
dnssec_validation = false
ratelimit_qps_per_worker = 1000
ratelimit_window_duration_secs = 1
ratelimit_max_ips = 10000
cache_l1_max_entries = 10000
cache_l2_max_size_mb = 64
cache_negative_ttl_fallback_secs = 60
blocklist_urls = ["https://example.com/hosts"]
logging_enabled = false
logging_db_path = ":memory:"
logging_channel_capacity = 1000
logging_retention_days = 90
api_enabled = false
api_port = 8080
api_key = "test-secret-key"
api_ratelimit_qps = 10
enforce_safesearch = {safesearch}

[[upstreams]]
address = "1.1.1.2"
protocol = "udp"
"#
        );
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn test_fresh_database_seeds_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);

        let (handle, source) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source, ConfigLoadSource::Seed(1));
        assert_eq!(handle.revision(), 1);
        assert!(!handle.load().enforce_safesearch);
    }

    #[test]
    fn test_existing_database_starts_with_missing_toml() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);

        let _ = initialize_runtime_config(&db_path, &toml_path).unwrap();
        std::fs::remove_file(&toml_path).unwrap();

        let (handle, source) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source, ConfigLoadSource::Database(1));
        assert_eq!(handle.revision(), 1);
    }

    #[test]
    fn test_existing_database_ignores_changed_toml() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);

        let _ = initialize_runtime_config(&db_path, &toml_path).unwrap();

        write_test_toml(&toml_path, true);

        let (handle, source) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source, ConfigLoadSource::Database(1));
        assert_eq!(handle.revision(), 1);
        assert!(!handle.load().enforce_safesearch);
    }

    #[test]
    fn test_invalid_seed_fails_only_when_seed_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let invalid_toml = dir.path().join("invalid.toml");
        std::fs::write(&invalid_toml, "invalid toml syntax [[[").unwrap();

        assert!(initialize_runtime_config(&db_path, &invalid_toml).is_err());

        let valid_toml = dir.path().join("valid.toml");
        write_test_toml(&valid_toml, false);
        let _ = initialize_runtime_config(&db_path, &valid_toml).unwrap();

        let (handle, source) = initialize_runtime_config(&db_path, &invalid_toml).unwrap();
        assert_eq!(source, ConfigLoadSource::Database(1));
        assert_eq!(handle.revision(), 1);
    }

    #[test]
    fn test_corrupt_invalid_state_database_fails_without_seed_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let valid_toml = dir.path().join("valid.toml");
        write_test_toml(&valid_toml, false);

        std::fs::write(&db_path, "not a sqlite database file").unwrap();

        let result = initialize_runtime_config(&db_path, &valid_toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_uses_the_configured_api_key_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);
        let content = std::fs::read_to_string(&toml_path)
            .unwrap()
            .replace("api_enabled = false", "api_enabled = true")
            .replace("test-secret-key", "my-secure-dashboard-key-123");
        std::fs::write(&toml_path, content).unwrap();

        let (handle, _) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(handle.load().api_key, "my-secure-dashboard-key-123");

        let (handle2, source) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source, ConfigLoadSource::Database(1));
        assert_eq!(handle2.load().api_key, "my-secure-dashboard-key-123");
    }

    #[test]
    fn test_seed_stores_a_configured_api_token_only_as_a_digest() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);
        let content = std::fs::read_to_string(&toml_path).unwrap().replace(
            "api_key = \"test-secret-key\"",
            "api_key = \"test-secret-key\"\napi_token = \"configured-integration-token\"",
        );
        assert!(content.contains("api_token ="));
        std::fs::write(&toml_path, content).unwrap();

        let (handle, _) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(
            handle.load().api_token_sha256.as_deref(),
            Some(core_dns::config::api_token_digest("configured-integration-token").as_str())
        );
        drop(handle);
        let stored = std::fs::read(&db_path).unwrap();
        let needle = b"configured-integration-token";
        assert!(!stored.windows(needle.len()).any(|window| window == needle));
    }

    #[test]
    fn test_deleting_development_database_causes_seed_again() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let toml_path = dir.path().join("config.toml");
        write_test_toml(&toml_path, false);

        let (handle, source) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source, ConfigLoadSource::Seed(1));
        assert_eq!(handle.revision(), 1);

        std::fs::remove_file(&db_path).unwrap();

        let (handle2, source2) = initialize_runtime_config(&db_path, &toml_path).unwrap();
        assert_eq!(source2, ConfigLoadSource::Seed(1));
        assert_eq!(handle2.revision(), 1);
    }
}
