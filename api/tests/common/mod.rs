//! Shared startup for the single-surface builds (`web_only_tests.rs`,
//! `api_only_tests.rs`). The full build uses `api_tests.rs` helpers.

use std::sync::Arc;
use std::time::Duration;

use core_dns::config::Config;
use core_dns::updater::BlocklistUpdater;
use filter::FilterEngine;
use filter::exact::ExactFilter;
use filter::regex_set::RegexFilter;
use filter::snapshot::FilterSnapshot;
use filter::trie::SubdomainTrie;

pub async fn start_server() -> (String, tempfile::TempDir, reqwest::Client) {
    let port = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut config = Config::load("../config/default.toml").unwrap();
    config.bind_address = "127.0.0.1".into();
    config.api_bind_address = "127.0.0.1".into();
    config.api_port = port;
    config.api_allow_insecure_http = true;
    config.api_key = "test-secret-key".into();
    config.api_ratelimit_qps = 1000;
    config.logging_enabled = false;
    config.blocklist_urls.clear();

    let directory = tempfile::tempdir().unwrap();
    let store =
        core_dns::config_store::ConfigStore::open(directory.path().join("state.db")).unwrap();
    let revision = store.insert_seed(&config).unwrap();
    let config =
        Arc::new(core_dns::config::ConfigHandle::new_persistent(store, config, revision).unwrap());
    let engine = Arc::new(FilterEngine::new(FilterSnapshot::new(
        ExactFilter::new(),
        SubdomainTrie::new(),
        RegexFilter::new(&[], &[]).unwrap(),
    )));
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine,
        vec![],
        directory.path().to_path_buf(),
    ));
    api::start_admin_api(
        config,
        updater,
        Arc::new(core_dns::cache::l1::L1Cache::new(100)),
        core_dns::cache::l2::L2Cache::new(1024 * 1024),
        None,
        Arc::new(core_dns::network::NetworkTracker::new()),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (format!("http://127.0.0.1:{port}"), directory, client)
}
