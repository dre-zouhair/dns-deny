//! Local dashboard fixture for browser regression tests; never binds publicly.
use core_dns::{
    cache::{l1::L1Cache, l2::L2Cache},
    config::{Config, ConfigHandle, UpstreamConfig},
    config_store::ConfigStore,
    network::NetworkTracker,
    updater::BlocklistUpdater,
};
use filter::{
    FilterEngine, FilterVerdict, exact::ExactFilter, regex_set::RegexFilter,
    snapshot::FilterSnapshot, trie::SubdomainTrie,
};
use hickory_proto::{op::ResponseCode, rr::RecordType};
use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
    let directory = PathBuf::from(std::env::var("DNS_UI_TEST_DIR")?);
    std::fs::create_dir_all(&directory)?;
    std::fs::create_dir_all(directory.join("lists"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let seed =
        Config::load(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml"))
            .map_err(|error| error.to_string())?;
    let config = Config {
        bind_address: "127.0.0.1".into(),
        api_bind_address: "127.0.0.1".into(),
        api_allow_insecure_http: true,
        api_enabled: true,
        api_port: port,
        api_key: "test-secret-key".into(),
        api_token: None,
        api_token_sha256: None,
        api_ratelimit_qps: 10000,
        upstreams: vec![UpstreamConfig {
            address: "127.0.0.1:9".into(),
            protocol: "udp".into(),
            tls_sni: None,
            doh_path: None,
        }],
        blocklist_urls: vec![],
        blocklist_categories: vec![],
        logging_enabled: true,
        logging_db_path: directory.join("queries.db").to_string_lossy().into_owned(),
        logging_channel_capacity: 2048,
        discovery_timeout_ms: 20,
        ..seed
    };
    let logger = Arc::new(logger::QueryLogger::new(&config.logging_db_path, 2048, 7));
    let store = ConfigStore::open(directory.join("state.db"))?;
    let revision = store.insert_seed(&config)?;
    let config = Arc::new(ConfigHandle::new_persistent(store, config, revision)?);
    let snapshot = FilterSnapshot::new(
        ExactFilter::new(),
        SubdomainTrie::new(),
        RegexFilter::new(&[], &[])?,
    );
    let engine = Arc::new(FilterEngine::new(snapshot));
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine,
        vec![],
        directory.join("lists"),
    ));
    let tracker = Arc::new(NetworkTracker::new());
    let client: IpAddr = "192.0.2.10".parse()?;
    tracker.track_query(client).await;
    for index in 0..250 {
        logger.log(
            client,
            format!("seed-{index}.example."),
            RecordType::A,
            ResponseCode::NoError,
            1_500_000,
            FilterVerdict::Block,
            "Fixture".into(),
        );
    }
    for payload in [
        "xss-fixture.<img src=x onerror=globalThis.__logXss=1>",
        "xss-fixture.</div><script>globalThis.__logXss=1</script>",
        "xss-fixture.\"><div data-init=\"globalThis.__logXss=1\">injected</div>",
        "xss-fixture.<svg onload=globalThis.__logXss=1>",
    ] {
        logger.log(
            client,
            payload.into(),
            RecordType::A,
            ResponseCode::NoError,
            1_500_000,
            FilterVerdict::Pass,
            payload.to_string().into(),
        );
    }
    api::start_admin_api(
        config,
        updater,
        Arc::new(L1Cache::new(1000)),
        L2Cache::new(64 * 1024 * 1024),
        Some(logger.clone()),
        tracker,
    )
    .await?;
    println!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(5));
        let mut index = 0u64;
        loop {
            interval.tick().await;
            logger.log(
                client,
                if index.is_multiple_of(101) {
                    format!("live-xss-{index}.<img src=x onerror=globalThis.__logXss=1>\n<div data-init=\"globalThis.__logXss=1\">injected</div>")
                } else {
                    format!("live-{index}.example.")
                },
                RecordType::A,
                ResponseCode::NoError,
                1_500_000,
                FilterVerdict::Pass,
                "Fixture".into(),
            );
            index += 1;
        }
    });
    std::future::pending::<()>().await;
    Ok(())
}
