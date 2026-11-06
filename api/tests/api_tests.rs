//! Integration coverage for the combined dashboard and JSON API build.
//! `web_only_tests.rs` and `api_only_tests.rs` cover single-surface builds.
#![cfg(all(feature = "feat-json-api", feature = "feat-web-ui"))]

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use core_dns::config::{BlocklistCategory, Config, UpstreamConfig};
use core_dns::updater::BlocklistUpdater;
use filter::exact::ExactFilter;
use filter::regex_set::RegexFilter;
use filter::snapshot::FilterSnapshot;
use filter::trie::SubdomainTrie;
use filter::{FilterEngine, FilterVerdict};
use hickory_proto::rr::Name;

fn make_test_config(port: u16, qps: u64) -> Config {
    Config {
        bind_address: "127.0.0.1".to_string(),
        api_bind_address: "127.0.0.1".to_string(),
        api_allow_insecure_http: true,
        api_trusted_proxy_cidrs: vec!["127.0.0.1/32".into()],
        upstreams: vec![UpstreamConfig {
            address: "1.1.1.1:53".to_string(),
            protocol: "udp".to_string(),
            tls_sni: None,
            doh_path: None,
        }],
        dnssec_validation: false,
        ratelimit_qps_per_worker: 1000,
        ratelimit_window_duration_secs: 1,
        ratelimit_max_ips: 1024,
        allowed_client_cidrs: vec![],
        cache_l1_max_entries: 1000,
        cache_l2_max_size_mb: 64,
        cache_negative_ttl_fallback_secs: 5,
        blocklist_urls: vec![],
        blocklist_categories: vec![],
        blocklist_refresh_cron: "0 0 3 * * *".to_string(),
        blocklist_fetch_concurrency: 4,
        discovery_timeout_ms: 250,
        auto_block_upstream_sinkholes: true,
        auto_block_upstreams: vec![],
        smart_ip_blocking: false,
        device_blocking_enabled: false,
        device_policies: std::collections::HashMap::new(),
        device_policy_ip_overrides: std::collections::BTreeMap::new(),
        device_schedules: vec![],
        local_dns_records: vec![],
        client_aliases: vec![],
        blocked_services: vec![],
        custom_services: vec![],
        protection_pause_default_duration_secs: 172800,
        protection_paused_until: None,
        category_pauses: std::collections::HashMap::new(),
        service_pauses: std::collections::HashMap::new(),
        device_pauses: std::collections::HashMap::new(),
        ml_scoring_enabled: false,
        enforce_safesearch: false,
        recursive_resolver_enabled: false,
        encrypted_upstream_enabled: false,
        encrypted_upstream_allow_plaintext_fallback: false,
        encrypted_upstream_url: "https://cloudflare-dns.com/dns-query".to_string(),
        doh_upstreams: vec![
            "https://cloudflare-dns.com/dns-query".to_string(),
            "https://dns.google/dns-query".to_string(),
            "https://dns.quad9.net/dns-query".to_string(),
        ],
        logging_enabled: false,
        logging_db_path: ":memory:".to_string(),
        logging_channel_capacity: 64,
        logging_retention_days: 7,
        api_enabled: true,
        api_port: port,
        api_key: "test-secret-key".to_string(),
        api_token: None,
        api_token_sha256: None,
        api_ratelimit_qps: qps,
    }
}

fn make_engine() -> Arc<FilterEngine> {
    let snapshot = FilterSnapshot::new(
        ExactFilter::new(),
        SubdomainTrie::new(),
        RegexFilter::new(&[], &[]).unwrap(),
    );
    Arc::new(FilterEngine::new(snapshot))
}

/// Binds port 0, returns the actual OS-assigned port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Starts the Admin API on the given config and returns the base URL and TempDir handle.
async fn start_server(config: Config) -> (String, tempfile::TempDir) {
    let port = config.api_port;
    let temp_dir = tempfile::tempdir().unwrap();
    let state_db = temp_dir.path().join("state.db");
    let store = core_dns::config_store::ConfigStore::open(&state_db).unwrap();
    let revision = store.insert_seed(&config).unwrap();
    let config =
        Arc::new(core_dns::config::ConfigHandle::new_persistent(store, config, revision).unwrap());
    let engine = make_engine();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));
    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(config, updater, l1_cache, l2_cache, None, network_tracker)
        .await
        .expect("Failed to start admin API");

    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("http://127.0.0.1:{}", port), temp_dir)
}

fn auth_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap()
}

// ─── Checkpoint: API Authentication ─────────────────────────────────────────

#[tokio::test]
async fn test_security_sql_payloads_are_bound_as_log_filter_values() {
    let entries = [
        log_entry(
            today_start_ms(),
            "first.example",
            [192, 0, 2, 1],
            FilterVerdict::Pass,
        ),
        log_entry(
            today_start_ms() + 1,
            "second.example",
            [192, 0, 2, 2],
            FilterVerdict::Block,
        ),
    ];
    let (base, _dirs) = start_server_with_logs(&entries).await;
    let client = auth_client();
    for field in ["q", "client"] {
        for payload in [
            "' OR 1=1 --",
            "'; DROP TABLE stats_meta;--",
            "' UNION SELECT 1,2,3,4,5,6,7,8 --",
        ] {
            let response = client
                .get(format!("{base}/api/v1/logs"))
                .bearer_auth("test-secret-key")
                .query(&[(field, payload)])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            let data: serde_json::Value = response.json().await.unwrap();
            assert_eq!(data["count"], 0, "{field}={payload}");
        }
    }
    let (_, data) = get_json(&base, "/api/v1/logs").await;
    assert_eq!(data["count"], 2);
    let (_, data) = get_json(&base, "/api/v1/stats").await;
    assert_eq!(data["total_queries"], 2);
}

#[tokio::test]
async fn test_security_log_search_ignores_non_partition_sql_identifiers() {
    let entries = [log_entry(
        today_start_ms(),
        "safe.example",
        [192, 0, 2, 1],
        FilterVerdict::Pass,
    )];
    let (base, (logs, _server)) = start_server_with_logs(&entries).await;
    let db = rusqlite::Connection::open(logs.path().join("logs.db")).unwrap();
    db.execute_batch(
        "CREATE TABLE audit_canary(value INTEGER); INSERT INTO audit_canary VALUES (1);",
    )
    .unwrap();
    for name in [
        "logs_9999_99_99",
        "logs_2000_01_01; DROP TABLE audit_canary;--",
        "logs_bad\"name",
    ] {
        db.execute(
            &format!(
                "CREATE TABLE \"{}\" (unrelated INTEGER)",
                name.replace('"', "\"\"")
            ),
            [],
        )
        .unwrap();
    }
    let (status, data) = get_json(&base, "/api/v1/logs?q=not-present").await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(data["count"], 0);
    assert_eq!(
        db.query_row("SELECT value FROM audit_canary", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn test_security_csv_export_neutralizes_whitespace_and_unicode_formula_prefixes() {
    let names = [
        "=1+1",
        "+1+1",
        "-1+1",
        "@SUM(1)",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "  =1+1",
        "＝1+1",
        "＋1+1",
        "－1+1",
        "＠SUM(1)",
    ];
    let entries: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            log_entry(
                today_start_ms() + index as i64,
                name,
                [192, 0, 2, 1],
                FilterVerdict::Pass,
            )
        })
        .collect();
    let (base, _dirs) = start_server_with_logs(&entries).await;
    let response = auth_client()
        .get(format!("{base}/api/v1/logs/export"))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let csv = response.text().await.unwrap();
    for name in names {
        assert!(
            csv.contains(&format!("\"'{name}\"")),
            "unsafe exported cell: {name:?}"
        );
    }
}

#[tokio::test]
async fn test_security_auth_bypass_and_traversal_attempts() {
    let (base, _dir) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    for suffix in ["", "?key=test-secret-key", "?api_key=test-secret-key"] {
        let response = client
            .get(format!("{base}/api/v1/config{suffix}"))
            .header("x-api-key", "test-secret-key")
            .header("x-forwarded-user", "admin")
            .header("cookie", "dns_deny_session=test-secret-key")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
    for path in [
        "/.env",
        "/.git/config",
        "/%2e%2e/Cargo.toml",
        "/%2e%2e%2fCargo.toml",
        "/vendor/%2e%2e/%2e%2e/Cargo.toml",
        "/%2fetc%2fpasswd",
    ] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert!(
            !response.status().is_success(),
            "unexpected file access: {path}"
        );
        assert!(!response.text().await.unwrap().contains("root:x:"));
    }
}

#[tokio::test]
async fn test_security_csrf_login_and_mutation_attempts_leave_state_unchanged() {
    let (base, directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    for origin in [None, Some("null"), Some("https://attacker.example")] {
        for path in ["/ui/auth/login", "/ui/action/config/pause"] {
            let mut request = client
                .post(format!("{base}{path}"))
                .header("cookie", &cookie)
                .form(&[
                    ("password", "test-secret-key"),
                    ("intent", "save"),
                    ("seconds", "5"),
                ]);
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
            assert!(!response.headers().contains_key("set-cookie"));
        }
    }
    let store =
        core_dns::config_store::ConfigStore::open(directory.path().join("state.db")).unwrap();
    let (config, _) = store.load_current().unwrap().unwrap();
    assert_eq!(config.protection_pause_default_duration_secs, 172800);
}

#[tokio::test]
async fn test_security_password_limits_reject_bcrypt_truncation_and_short_unicode() {
    let (base, _directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    for password in ["a".repeat(73), "😀😀".to_string()] {
        let response = client.post(format!("{base}/api/v1/config/password"))
            .bearer_auth("test-secret-key")
            .json(&serde_json::json!({"current_password": "test-secret-key", "new_password": password}))
            .send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(
            client
                .get(format!("{base}/ui/auth/session"))
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        get_json(&base, "/api/v1/config").await.0,
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_security_regex_line_injection_is_rejected_without_changing_rules() {
    let (base, directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    for pattern in ["^first\\.\n.*", "^first\\.\r.*"] {
        let response = client
            .post(format!("{base}/api/v1/lists/regex-deny"))
            .bearer_auth("test-secret-key")
            .json(&serde_json::json!({"pattern": pattern}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    }
    let (_, data) = get_json(&base, "/api/v1/lists/regex-deny").await;
    assert_eq!(data, serde_json::json!([]));
    assert!(!directory.path().join("regex_deny.txt").exists());
    let pattern = r"^escaped\nsequence$";
    let response = client
        .post(format!("{base}/api/v1/lists/regex-deny"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"pattern": pattern}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(directory.path().join("regex_deny.txt")).unwrap(),
        format!("{pattern}\n")
    );
}

#[tokio::test]
async fn test_reactive_pages_use_fresh_nonce_without_relaxing_api_csp() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let mut nonces = Vec::new();
    for (path, _script) in [
        ("/lists.html", "lists"),
        ("/services.html", "services"),
        ("/network.html", "network"),
        ("/config.html", "config"),
        ("/doh.html", "doh"),
        ("/", "overview"),
        ("/index.html", "overview"),
        ("/livetail.html", "livetail"),
    ] {
        for _ in 0..2 {
            let response = client
                .get(format!("{base}{path}?tab=allowdeny"))
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert!(
                response.headers()["content-type"]
                    .to_str()
                    .unwrap()
                    .starts_with("text/html")
            );
            let policy = response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .to_string();
            let script_policy = policy
                .split(';')
                .find(|part| part.trim().starts_with("script-src"))
                .unwrap();
            assert!(!script_policy.contains("unsafe-inline"));
            assert!(!script_policy.contains("unsafe-eval"));
            assert!(!script_policy.contains("https://"));
            let nonce = script_policy
                .split("'nonce-")
                .nth(1)
                .unwrap()
                .split('\'')
                .next()
                .unwrap();
            assert_eq!(nonce.len(), 64);
            assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let html = response.text().await.unwrap();
            assert!(html.contains("src=\"/ui.js?v="));
            assert!(!html.contains("__PAGE_NONCE__"));
            assert!(!html.contains("onclick="));
            nonces.push(nonce.to_string());
        }
    }
    let unique: std::collections::HashSet<_> = nonces.iter().collect();
    assert_eq!(unique.len(), nonces.len());

    let response = client
        .get(format!("{base}/api/v1/config"))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(!policy.contains("unsafe-eval"));
    assert!(!policy.contains("'nonce-"));
}

#[tokio::test]
async fn test_auth_missing_token_returns_401() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/stats", base))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Missing token must return 401"
    );
}

#[tokio::test]
async fn test_auth_wrong_token_returns_401() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Wrong token must return 401"
    );
}

#[tokio::test]
async fn test_auth_valid_token_passes() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();

    // Stats endpoint may return 200 (empty DB is fine) or 500 (no actual DB); not 401/403
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Valid token must not be rejected"
    );
}

// ─── Checkpoint: Read-only Stats ─────────────────────────────────────────────

#[tokio::test]
async fn test_stats_returns_json_without_sql_error_details() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();

    // With an in-memory / non-existent DB path, we expect either:
    //   200 with zeroed stats   — empty DB opened ok
    //   500 with sanitised msg  — cannot open :memory: read-only
    // In either case the body must NOT contain raw SQL text or file paths.
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("sqlite"),
        "Response must not leak SQLite internals: {body}"
    );
    assert!(
        !body.contains("SQLITE_"),
        "Response must not leak SQLite error codes: {body}"
    );
}

#[tokio::test]
async fn test_stats_shape_on_empty_db() {
    // Use a real temp file so the DB can be opened read-only after creation.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs_2024_01_01 (
                id INTEGER PRIMARY KEY,
                name TEXT,
                client_ip TEXT,
                qtype TEXT,
                response_code TEXT,
                duration_ns INTEGER,
                verdict TEXT,
                timestamp INTEGER
            );",
        )
        .unwrap();
    }

    let port = free_port().await;
    let mut cfg = make_test_config(port, 100);
    cfg.logging_db_path = db_path;

    let (base, _temp_dir) = start_server(cfg).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json.get("total_queries").is_some(),
        "Missing total_queries field"
    );
    assert!(
        json.get("blocked_queries").is_some(),
        "Missing blocked_queries field"
    );
    assert!(json.get("block_rate").is_some(), "Missing block_rate field");
    assert!(
        json.get("top_blocked").is_some(),
        "Missing top_blocked field"
    );
    assert!(
        json.get("top_allowed").is_some(),
        "Missing top_allowed field"
    );
    assert!(
        json.get("client_breakdown").is_some(),
        "Missing client_breakdown field"
    );

    assert_eq!(json["total_queries"], 0);
    assert_eq!(json["blocked_queries"], 0);
}

// ─── Checkpoint: Windowed dashboard statistics (rollups) ─────────────────────

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

fn log_entry(ms: i64, name: &str, client: [u8; 4], verdict: FilterVerdict) -> logger::LogEntry {
    logger::LogEntry {
        timestamp: std::time::UNIX_EPOCH + Duration::from_millis(ms as u64),
        client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::from(client)),
        name: name.to_string(),
        qtype: hickory_proto::rr::RecordType::A,
        response_code: hickory_proto::op::ResponseCode::NoError,
        duration_ns: 1000,
        verdict,
        resolver: "Standard Upstreams".into(),
    }
}

/// Midnight UTC today, in Unix ms. Seed timestamps are anchored to it so the
/// tests can't straddle a day boundary depending on when they run.
fn today_start_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    now - now.rem_euclid(DAY_MS)
}

/// Returns the base URL plus the log and server temp dirs, which must stay
/// alive for the duration of the test.
async fn start_server_with_logs(
    entries: &[logger::LogEntry],
) -> (String, (tempfile::TempDir, tempfile::TempDir)) {
    let log_dir = tempfile::tempdir().unwrap();
    let db_path = log_dir.path().join("logs.db");
    logger::persist_entries_blocking(&db_path, entries).unwrap();

    let port = free_port().await;
    let mut cfg = make_test_config(port, 1000);
    cfg.logging_db_path = db_path.to_str().unwrap().to_string();
    let (base, server_dir) = start_server(cfg).await;
    (base, (log_dir, server_dir))
}

async fn get_json(base: &str, path: &str) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = auth_client()
        .get(format!("{}{}", base, path))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

#[tokio::test]
async fn test_stats_windows_select_the_right_time_range() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let this_hour = now - now.rem_euclid(HOUR_MS);
    let today = today_start_ms();
    let entries = [
        log_entry(this_hour, "recent.com", [10, 0, 0, 1], FilterVerdict::Block),
        log_entry(
            today - 3 * DAY_MS + HOUR_MS,
            "week.com",
            [10, 0, 0, 2],
            FilterVerdict::Pass,
        ),
        log_entry(
            today - 30 * DAY_MS + HOUR_MS,
            "month.com",
            [10, 0, 0, 3],
            FilterVerdict::Pass,
        ),
    ];
    let (base, _logs) = start_server_with_logs(&entries).await;

    for (window, total, blocked) in [("24h", 1, 1), ("7d", 2, 1), ("all", 3, 1)] {
        let (status, json) = get_json(&base, &format!("/api/v1/stats?window={window}")).await;
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(json["total_queries"], total, "window {window}: {json}");
        assert_eq!(json["blocked_queries"], blocked, "window {window}: {json}");
    }

    // Default for /stats stays the whole retention window (backward compatible).
    let (_, json) = get_json(&base, "/api/v1/stats").await;
    assert_eq!(json["total_queries"], 3);

    let (_, json) = get_json(&base, "/api/v1/stats/top-clients?window=24h").await;
    assert_eq!(json["clients"].as_array().unwrap().len(), 1);
    assert_eq!(json["clients"][0]["client_ip"], "10.0.0.1");

    // Default for queries-over-time stays 24 hourly buckets.
    let (_, json) = get_json(&base, "/api/v1/stats/queries-over-time").await;
    let buckets = json["buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 24);
    assert_eq!(buckets[23]["start_ms"], this_hour);
    assert_eq!(buckets[23]["total"], 1);

    let (_, json) = get_json(&base, "/api/v1/stats/queries-over-time?window=7d").await;
    let buckets = json["buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 168);
    let sum: u64 = buckets.iter().map(|b| b["total"].as_u64().unwrap()).sum();
    assert_eq!(sum, 2);

    let (_, json) = get_json(&base, "/api/v1/stats/queries-over-time?window=all").await;
    let buckets = json["buckets"].as_array().unwrap();
    assert_eq!(
        buckets.len(),
        31,
        "one daily bucket from the oldest day to today"
    );
    assert_eq!(buckets[0]["start_ms"], today - 30 * DAY_MS);
    let sum: u64 = buckets.iter().map(|b| b["total"].as_u64().unwrap()).sum();
    assert_eq!(sum, 3);
}

#[tokio::test]
async fn test_top_blocked_ranks_by_total_across_the_window() {
    // Every day, ten one-off domains get 5 hits each and steady.com gets 4:
    // steady.com is #11 on every single day but #1 overall. The old
    // per-partition LIMIT 10 merge never surfaced it.
    let today = today_start_ms();
    let mut entries = Vec::new();
    for day in 1..=10 {
        let ts = today - day * DAY_MS + HOUR_MS;
        for k in 0..10 {
            for _ in 0..5 {
                entries.push(log_entry(
                    ts,
                    &format!("day{day}-dom{k}.com"),
                    [10, 0, 0, 1],
                    FilterVerdict::Block,
                ));
            }
        }
        for _ in 0..4 {
            entries.push(log_entry(
                ts,
                "steady.com",
                [10, 0, 0, 1],
                FilterVerdict::Block,
            ));
        }
    }
    let (base, _logs) = start_server_with_logs(&entries).await;

    let (_, json) = get_json(&base, "/api/v1/stats?window=all").await;
    assert_eq!(json["top_blocked"][0]["domain"], "steady.com", "{json}");
    assert_eq!(json["top_blocked"][0]["count"], 40);

    let (_, json) = get_json(&base, "/api/v1/stats/top-blocked?window=all").await;
    assert_eq!(json["domains"][0]["domain"], "steady.com", "{json}");
}

#[tokio::test]
async fn test_stats_reject_unknown_window() {
    let (base, _logs) = start_server_with_logs(&[]).await;
    for path in [
        "/api/v1/stats?window=1y",
        "/api/v1/stats/top-blocked?window=1y",
        "/api/v1/stats/top-clients?window=1y",
        "/api/v1/stats/queries-over-time?window=1y",
        "/api/v1/stats/query-types?window=1y",
        "/api/v1/stats/upstreams?window=1y",
    ] {
        let (status, _) = get_json(&base, path).await;
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{path}");
    }
}

#[tokio::test]
async fn test_logs_listing_returns_newest_entries_across_partitions() {
    let today = today_start_ms();
    let entries = [
        log_entry(
            today - 2 * DAY_MS + HOUR_MS,
            "oldest.com",
            [10, 0, 0, 1],
            FilterVerdict::Pass,
        ),
        log_entry(
            today - DAY_MS + HOUR_MS,
            "middle.com",
            [10, 0, 0, 1],
            FilterVerdict::Pass,
        ),
        log_entry(
            today + 60_000,
            "newest.com",
            [10, 0, 0, 1],
            FilterVerdict::Pass,
        ),
    ];
    let (base, _logs) = start_server_with_logs(&entries).await;

    let (_, json) = get_json(&base, "/api/v1/logs?limit=2").await;
    let names: Vec<&str> = json["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["newest.com", "middle.com"]);

    let (_, json) = get_json(&base, "/api/v1/logs?limit=2&offset=2").await;
    assert_eq!(json["logs"][0]["name"], "oldest.com");
}

// ─── Checkpoint: List Management (ArcSwap snapshot rebuild) ──────────────────

#[tokio::test]
async fn test_add_deny_rule_triggers_snapshot_rebuild() {
    let port = free_port().await;

    let config = make_test_config(port, 100);
    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(config));
    let engine = make_engine();
    let temp_dir = tempfile::tempdir().unwrap();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));

    let updater_clone = updater.clone();

    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(
        shared_config,
        updater_clone,
        l1_cache,
        l2_cache,
        None,
        network_tracker,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = format!("http://127.0.0.1:{}", port);
    let client = auth_client();

    let resp = client
        .post(format!("{}/api/v1/lists/deny", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "pattern": "blocked-via-api.example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let denies = updater.local_denies.lock().await;
    assert!(
        denies.contains("blocked-via-api.example.com"),
        "Expected 'blocked-via-api.example.com' in local_denies, got: {:?}",
        *denies
    );
}

#[tokio::test]
async fn test_remove_auto_blocked_domain_unblocks_it() {
    let port = free_port().await;
    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(make_test_config(
        port, 100,
    )));
    let engine = make_engine();
    let temp_dir = tempfile::tempdir().unwrap();
    // Older builds stored auto-blocked names with the client's original case.
    std::fs::write(
        temp_dir.path().join("auto_blocked.txt"),
        "Split-Horizon.Example.com\n",
    )
    .unwrap();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));
    updater.rebuild_snapshot().await.unwrap();
    let name = Name::from_str("split-horizon.example.com.").unwrap();
    assert_eq!(engine.check(&name), FilterVerdict::Block);

    api::start_admin_api(
        shared_config,
        updater.clone(),
        Arc::new(core_dns::cache::l1::L1Cache::new(100)),
        core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024),
        None,
        Arc::new(core_dns::network::NetworkTracker::new()),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let base = format!("http://127.0.0.1:{}", port);
    let client = auth_client();

    let resp = client
        .delete(format!("{}/api/v1/lists/auto-blocked", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "pattern": "split-horizon.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(updater.auto_denies.lock().await.is_empty());
    assert_eq!(engine.check(&name), FilterVerdict::Pass);
    assert_eq!(
        std::fs::read_to_string(temp_dir.path().join("auto_blocked.txt"))
            .unwrap()
            .trim(),
        ""
    );

    let resp = client
        .delete(format!("{}/api/v1/lists/auto-blocked", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "pattern": "split-horizon.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_add_allow_rule_stored() {
    let port = free_port().await;

    let config = make_test_config(port, 100);
    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(config));
    let engine = make_engine();
    let temp_dir = tempfile::tempdir().unwrap();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));
    let updater_clone = updater.clone();

    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(
        shared_config,
        updater_clone,
        l1_cache,
        l2_cache,
        None,
        network_tracker,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = format!("http://127.0.0.1:{}", port);
    let client = auth_client();

    let resp = client
        .post(format!("{}/api/v1/lists/allow", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "pattern": "allowed-via-api.example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let allows = updater.local_allows.lock().await;
    assert!(
        allows.contains("allowed-via-api.example.com"),
        "Expected 'allowed-via-api.example.com' in local_allows, got: {:?}",
        *allows
    );
}

#[tokio::test]
async fn test_remove_nonexistent_rule_returns_404() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .delete(format!("{}/api/v1/lists/deny", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "pattern": "does-not-exist.example.com" }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "Removing a non-existent rule must return 404"
    );
}

// ─── Checkpoint: Config & Rate Limiting ──────────────────────────────────────

#[tokio::test]
async fn test_get_config_returns_json() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json.get("upstreams").is_some(),
        "Config response missing 'upstreams'"
    );
    assert!(
        json.get("api_enabled").is_some(),
        "Config response missing 'api_enabled'"
    );
}

#[tokio::test]
async fn test_rate_limit_returns_429() {
    // Set a very tight QPS limit (2 req/s) to make it easy to exceed
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 2)).await;
    let client = auth_client();

    let mut got_429 = false;

    // Fire 20 rapid requests — at qps=2, the 3rd+ within the same second must be 429
    for _ in 0..20 {
        let resp = client
            .get(format!("{}/api/v1/config", base))
            .bearer_auth("test-secret-key")
            .send()
            .await
            .unwrap();

        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }

    assert!(
        got_429,
        "Expected a 429 Too Many Requests after exceeding the rate limit"
    );
}

// ─── Checkpoint: SSE Live Tail Cleanup ───────────────────────────────────────

#[tokio::test]
async fn test_sse_endpoint_disabled_without_logger() {
    // When logging is disabled (logger=None), /api/v1/tail should return 400 Bad Request
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let resp = client
        .get(format!("{}/api/v1/tail", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "SSE endpoint must return 400 when logging is disabled"
    );
}

#[tokio::test]
async fn test_sse_client_disconnect_does_not_panic() {
    use logger::QueryLogger;

    let port = free_port().await;
    let cfg = make_test_config(port, 100);
    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(cfg));
    let engine = make_engine();
    let temp_dir = tempfile::tempdir().unwrap();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));

    let logger = Arc::new(QueryLogger::new(":memory:", 64, 90));
    let logger_opt = Some(logger);

    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(
        shared_config,
        updater,
        l1_cache,
        l2_cache,
        logger_opt,
        network_tracker,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = format!("http://127.0.0.1:{}", port);

    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let mut resp = client
        .get(format!("{}/ui/queries/stream", base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ct.contains("text/event-stream"),
        "Expected SSE content-type, got: {ct}"
    );

    let first = tokio::time::timeout(Duration::from_secs(2), resp.chunk())
        .await
        .expect("SSE must flush a connection comment immediately")
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("connected"));

    drop(resp);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let follow_up = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_ne!(
        follow_up.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Server must still be healthy after client disconnect"
    );
}

// ─── Full API Contract Test ───────────────────────────────────────────────────

#[tokio::test]
async fn test_full_api_contract() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    // --- /api/v1/stats ---
    let r = client
        .get(format!("{}/api/v1/stats", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success() || r.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "GET /api/v1/stats unexpected status: {}",
        r.status()
    );

    // --- /api/v1/stats/query-types ---
    let r = client
        .get(format!("{}/api/v1/stats/query-types", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let types_resp: serde_json::Value = r.json().await.unwrap();
    assert!(types_resp["types"].is_array());

    // --- /api/v1/stats/upstreams ---
    let r = client
        .get(format!("{}/api/v1/stats/upstreams", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let upstreams_resp: serde_json::Value = r.json().await.unwrap();
    assert!(upstreams_resp["upstreams"].is_array());

    // --- GET /api/v1/config ---
    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "GET /api/v1/config must be 200"
    );
    let initial_config: serde_json::Value = r.json().await.unwrap();
    assert_eq!(initial_config["recursive_resolver_enabled"], false);

    // --- POST /api/v1/config/password (update password) ---
    // 1. Changing password with incorrect current password should fail
    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "current_password": "wrong-current-password",
            "new_password": "my-new-super-secret-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 2. Correct update should succeed
    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "current_password": key,
            "new_password": "my-new-super-secret-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    // 3. Old password should now fail authentication
    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 4. New password should succeed authentication
    let new_key = "my-new-super-secret-password";
    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(new_key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    // 5. Restore password back to the original key for subsequent tests
    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .bearer_auth(new_key)
        .json(&serde_json::json!({
            "current_password": new_key,
            "new_password": key
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    // --- POST /api/v1/config/resolver (update) ---
    let r = client
        .post(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "recursive_resolver_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST /api/v1/config/resolver must be 200"
    );

    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let verified_config: serde_json::Value = r.json().await.unwrap();
    assert_eq!(verified_config["recursive_resolver_enabled"], true);

    // --- POST /api/v1/lists/allow ---
    let r = client
        .post(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "contract-test-allow.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST /api/v1/lists/allow must be 200"
    );

    // --- DELETE /api/v1/lists/allow (remove it) ---
    let r = client
        .delete(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "contract-test-allow.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "DELETE /api/v1/lists/allow must be 200"
    );

    // --- POST /api/v1/lists/deny ---
    let r = client
        .post(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "contract-test-deny.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST /api/v1/lists/deny must be 200"
    );

    // --- DELETE /api/v1/lists/deny (remove it) ---
    let r = client
        .delete(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "contract-test-deny.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "DELETE /api/v1/lists/deny must be 200"
    );

    // --- Regex rules integration tests ---
    let r = client
        .post(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": r"^safe\." }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST regex-allow must be 200"
    );

    let r = client
        .get(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let allows: Vec<String> = r.json().await.unwrap();
    assert!(allows.contains(&r"^safe\.".to_string()));

    let r = client
        .delete(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": r"^safe\." }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "DELETE regex-allow must be 200"
    );

    // --- Blocklist Categories integration test ---
    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let config_val: serde_json::Value = r.json().await.unwrap();
    assert!(config_val.get("blocklist_categories").is_some());

    let r = client
        .post(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "blocklist_urls": [],
            "blocklist_categories": [
                {
                    "id": "malware",
                    "name": "Malware & Security",
                    "urls": ["http://127.0.0.1/malware.txt"],
                    "enabled": true
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let updated_config_val: serde_json::Value = r.json().await.unwrap();
    let categories = updated_config_val["blocklist_categories"]
        .as_array()
        .unwrap();
    assert!(
        categories
            .iter()
            .any(|c| c["id"] == "malware" && c["enabled"] == true)
    );

    let r = client
        .post(format!("{}/api/v1/lists/regex-deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "[invalid-regex" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid regex must return 400"
    );

    let r = client
        .post(format!("{}/api/v1/lists/regex-deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": r"^ads?[0-9]*\." }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST regex-deny must be 200"
    );

    let r = client
        .get(format!("{}/api/v1/lists/regex-deny", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let denies: Vec<String> = r.json().await.unwrap();
    assert!(denies.contains(&r"^ads?[0-9]*\.".to_string()));

    let r = client
        .delete(format!("{}/api/v1/lists/regex-deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": r"^ads?[0-9]*\." }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "DELETE regex-deny must be 200"
    );

    // --- Client Alias endpoints tests ---
    let r = client
        .post(format!("{}/api/v1/network/aliases", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "identifier": "invalid-ip-or-mac", "name": "Test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid IP/MAC must return 400"
    );

    let r = client
        .post(format!("{}/api/v1/network/aliases", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "identifier": "192.168.1.50", "name": "Work Laptop" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST /api/v1/network/aliases must succeed"
    );

    let r = client
        .post(format!("{}/api/v1/network/aliases", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "identifier": "00:1a:2b:3c:4d:5e", "name": "Living Room TV" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::OK,
        "POST /api/v1/network/aliases with MAC must succeed"
    );

    let r = client
        .get(format!("{}/api/v1/network/aliases", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let aliases: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        aliases
            .iter()
            .any(|a| a["identifier"] == "192.168.1.50" && a["name"] == "Work Laptop")
    );
    assert!(
        aliases
            .iter()
            .any(|a| a["identifier"] == "00:1a:2b:3c:4d:5e" && a["name"] == "Living Room TV")
    );

    let r = client
        .delete(format!("{}/api/v1/network/aliases/192.168.1.50", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .delete(format!("{}/api/v1/network/aliases/00:1a:2b:3c:4d:5e", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    // --- GET /api/v1/tail (no logger → 400) ---
    let r = client
        .get(format!("{}/api/v1/tail", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "GET /api/v1/tail without logger must be 400"
    );

    // --- GET /api/v1/logs ---
    let r = client
        .get(format!("{}/api/v1/logs?limit=5&offset=0", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let logs_resp: serde_json::Value = r.json().await.unwrap();
    assert!(logs_resp.get("logs").is_some());

    // --- GET /api/v1/logs/export ---
    let r = client
        .get(format!("{}/api/v1/logs/export", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let csv_headers = r.headers();
    assert_eq!(
        csv_headers.get(reqwest::header::CONTENT_TYPE).unwrap(),
        "text/csv"
    );

    // --- GET /api/v1/config/services ---
    let r = client
        .get(format!("{}/api/v1/config/services", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let services: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        services
            .iter()
            .any(|s| s["id"] == "tiktok" && s["blocked"] == false)
    );

    // --- POST /api/v1/config/services ---
    let r = client
        .post(format!("{}/api/v1/config/services", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "blocked_services": ["tiktok"],
            "custom_services": [
                {
                    "id": "custom_mygame",
                    "name": "My Custom Game",
                    "description": "Custom block for My Custom Game",
                    "wildcards": ["mygame.com", "api.mygame.net"],
                    "enabled": true
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/config/services", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let services: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        services
            .iter()
            .any(|s| s["id"] == "tiktok" && s["blocked"] == true)
    );

    let mygame = services
        .iter()
        .find(|s| s["id"] == "custom_mygame")
        .unwrap();
    assert_eq!(mygame["name"], "My Custom Game");
    assert_eq!(mygame["blocked"], true);
    assert_eq!(mygame["is_custom"], true);
    assert_eq!(mygame["wildcards"].as_array().unwrap().len(), 2);

    // --- Auth checks on every endpoint ---
    for path in &[
        "/api/v1/stats",
        "/api/v1/stats/query-types",
        "/api/v1/stats/upstreams",
        "/api/v1/config",
        "/api/v1/tail",
        "/api/v1/logs",
        "/api/v1/logs/export",
        "/api/v1/config/services",
    ] {
        let r = client
            .get(format!("{}{}", base, path))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "GET {} without auth must be 401",
            path
        );
    }

    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "POST /api/v1/config/password without auth must be 401"
    );
}

// ─── Checkpoint: Temporary Protection Pause ──────────────────────────────────

#[tokio::test]
async fn test_protection_status_empty_by_default() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let r = client
        .get(format!("{}/api/v1/protection/status", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let status: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status["global_paused_until"], serde_json::Value::Null);
    assert_eq!(status["category_pauses"].as_object().unwrap().len(), 0);
    assert_eq!(status["service_pauses"].as_object().unwrap().len(), 0);
    assert_eq!(status["default_duration_secs"], 172800);
}

#[tokio::test]
async fn test_protection_pause_and_resume_global_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "scope": "global" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK, "pause must be 200");

    let r = client
        .get(format!("{}/api/v1/protection/status", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let status: serde_json::Value = r.json().await.unwrap();
    assert!(
        status["global_paused_until"].as_i64().is_some(),
        "expected a future timestamp, got {:?}",
        status["global_paused_until"]
    );

    let r = client
        .post(format!("{}/api/v1/protection/resume", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "scope": "global" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK, "resume must be 200");

    let r = client
        .get(format!("{}/api/v1/protection/status", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let status: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status["global_paused_until"], serde_json::Value::Null);
}

#[tokio::test]
async fn test_protection_pause_service_scope_requires_id() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "scope": "service" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_protection_pause_honours_explicit_duration() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    // The admin UI's "Pause 1 Hour" must actually pause for an hour rather
    // than falling back to protection_pause_default_duration_secs.
    let before = core_dns::config::now_epoch();
    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "scope": "global", "duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = r.json().await.unwrap();
    let paused_until = body["paused_until"].as_i64().unwrap();
    assert!(
        (paused_until - (before + 3600)).abs() <= 5,
        "paused_until {} should be ~1h out from {}",
        paused_until,
        before
    );
}

#[tokio::test]
async fn test_protection_pause_indefinite_does_not_expire() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({ "scope": "global", "indefinite": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["paused_until"].as_i64().unwrap(),
        core_dns::config::INDEFINITE_PAUSE_EPOCH
    );
}

#[tokio::test]
async fn test_protection_pause_rejects_absurd_duration() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();

    for bad in [0u64, 400 * 24 * 60 * 60] {
        let r = client
            .post(format!("{}/api/v1/protection/pause", base))
            .bearer_auth("test-secret-key")
            .json(&serde_json::json!({ "scope": "global", "duration_secs": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "duration_secs={} must be rejected",
            bad
        );
    }
}

#[tokio::test]
async fn test_upstreams_config_round_trip_and_validation() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/config/upstreams", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(body["upstreams"].is_array());

    // Valid save round-trips.
    let r = client.post(format!("{}/api/v1/config/upstreams", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "upstreams": [{ "address": "9.9.9.9:53", "protocol": "tcp", "tls_sni": null, "doh_path": null }]
        }))
        .send().await.unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/config/upstreams", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["upstreams"][0]["address"], "9.9.9.9:53");

    // A config that would refuse to boot must never be persisted.
    for bad in [
        serde_json::json!({ "upstreams": [] }),
        serde_json::json!({ "upstreams": [{ "address": "not-an-ip", "protocol": "udp", "tls_sni": null, "doh_path": null }] }),
        serde_json::json!({ "upstreams": [{ "address": "1.1.1.1:853", "protocol": "dot", "tls_sni": null, "doh_path": null }] }),
        serde_json::json!({ "upstreams": [{ "address": "1.1.1.1:53", "protocol": "carrier-pigeon", "tls_sni": null, "doh_path": null }] }),
    ] {
        let r = client
            .post(format!("{}/api/v1/config/upstreams", base))
            .bearer_auth(key)
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "must reject {:?}",
            bad
        );
    }

    // ...and the last good value is still in place.
    let r = client
        .get(format!("{}/api/v1/config/upstreams", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["upstreams"][0]["address"], "9.9.9.9:53");
    assert_eq!(body["upstreams"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_protection_pause_rejects_repausing_already_paused_scope() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";
    let body = serde_json::json!({ "scope": "service", "id": "tiktok" });

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::CONFLICT,
        "re-pausing an already-paused scope must be 409"
    );
}

#[tokio::test]
async fn test_protection_pause_category_reflected_in_config_get() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "scope": "category", "id": "gambling" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/config", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let config_val: serde_json::Value = r.json().await.unwrap();
    let paused_until = config_val["category_pauses"]["gambling"].as_i64();
    assert!(
        paused_until.is_some(),
        "expected category_pauses.gambling to be a future epoch, got {:?}",
        config_val["category_pauses"]
    );
}

#[tokio::test]
async fn test_update_config_resyncs_when_categories_change() {
    // Category-only edits must resync sources as well as uncategorized URL edits.
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let payload = serde_json::json!({
        "blocklist_urls": [],
        "blocklist_categories": [
            {
                "id": "gambling",
                "name": "Gambling",
                "urls": ["http://127.0.0.1:1/gambling.txt"],
                "enabled": true
            }
        ]
    });
    let r = client
        .post(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/lists/sources/status", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let sources: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        sources
            .iter()
            .any(|s| s["url"] == "http://127.0.0.1:1/gambling.txt"),
        "expected the newly-enabled category's URL to be tracked by the updater, got {:?}",
        sources
    );
}

#[tokio::test]
async fn test_detection_config_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/config/detection", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["smart_ip_blocking"], false);
    assert_eq!(got["auto_block_upstream_sinkholes"], true);
    assert_eq!(got["ml_scoring_enabled"], false);

    let payload = serde_json::json!({
        "smart_ip_blocking": true,
        "auto_block_upstream_sinkholes": false,
        "ml_scoring_enabled": true
    });
    let r = client
        .post(format!("{}/api/v1/config/detection", base))
        .bearer_auth(key)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/config/detection", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["smart_ip_blocking"], true);
    assert_eq!(got["auto_block_upstream_sinkholes"], false);
    assert_eq!(got["ml_scoring_enabled"], true);
}

#[tokio::test]
async fn test_protection_settings_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/protection/settings", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["protection_pause_default_duration_secs"], 172800);

    let r = client
        .post(format!("{}/api/v1/protection/settings", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "protection_pause_default_duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/protection/settings", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["protection_pause_default_duration_secs"], 3600);
}

#[tokio::test]
async fn test_protection_settings_rejects_zero_duration() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/protection/settings", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "protection_pause_default_duration_secs": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_device_blocking_config_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/network/device-blocking", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["device_blocking_enabled"], false);

    let r = client
        .post(format!("{}/api/v1/network/device-blocking", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "device_blocking_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/network/device-blocking", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["device_blocking_enabled"], true);
}

#[tokio::test]
async fn test_resolver_config_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["recursive_resolver_enabled"], false);

    let r = client
        .post(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "recursive_resolver_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK, "{:?}", r.text().await);

    let r = client
        .get(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    assert_eq!(got["recursive_resolver_enabled"], true);
}

#[tokio::test]
async fn test_resolver_config_supports_recursive_with_dnssec_validation() {
    let port = free_port().await;
    let mut config = make_test_config(port, 100);
    config.dnssec_validation = true;
    let (base, _temp_dir) = start_server(config).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "recursive_resolver_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK, "{:?}", r.text().await);
}

#[tokio::test]
async fn test_blocklist_config_round_trip_and_resyncs_sources() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let empty: serde_json::Value = r.json().await.unwrap();
    assert_eq!(empty["blocklist_urls"].as_array().unwrap().len(), 0);
    assert_eq!(empty["blocklist_categories"].as_array().unwrap().len(), 0);

    let payload = serde_json::json!({
        "blocklist_urls": [],
        "blocklist_categories": [
            {
                "id": "gambling",
                "name": "Gambling",
                "urls": ["http://127.0.0.1:1/gambling.txt"],
                "enabled": true
            }
        ]
    });
    let r = client
        .post(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK, "{:?}", r.text().await);

    let r = client
        .get(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let got: serde_json::Value = r.json().await.unwrap();
    let categories = got["blocklist_categories"].as_array().unwrap();
    assert!(
        categories
            .iter()
            .any(|c| c["id"] == "gambling" && c["enabled"] == true)
    );

    let r = client
        .get(format!("{}/api/v1/lists/sources/status", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let sources: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(
        sources
            .iter()
            .any(|s| s["url"] == "http://127.0.0.1:1/gambling.txt"),
        "expected the newly-enabled category's URL to be tracked by the updater, got {:?}",
        sources
    );
}

#[tokio::test]
async fn test_get_allow_and_deny_round_trip() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .get(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let list: Vec<String> = r.json().await.unwrap();
    assert!(list.is_empty());

    let r = client
        .post(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "visible-allow.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let list: Vec<String> = r.json().await.unwrap();
    assert_eq!(list, vec!["visible-allow.example.com".to_string()]);

    let r = client
        .get(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let list: Vec<String> = r.json().await.unwrap();
    assert!(list.is_empty());
}

#[tokio::test]
async fn test_adding_to_allow_removes_from_deny_via_api() {
    let port = free_port().await;
    let (base, _temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "flip-via-api.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let list: Vec<String> = r.json().await.unwrap();
    assert_eq!(list, vec!["flip-via-api.example.com".to_string()]);

    let r = client
        .post(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "flip-via-api.example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let list: Vec<String> = r.json().await.unwrap();
    assert!(
        list.is_empty(),
        "expected deny list to be empty after the same pattern was added to allow, got {:?}",
        list
    );

    let r = client
        .get(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let list: Vec<String> = r.json().await.unwrap();
    assert_eq!(list, vec!["flip-via-api.example.com".to_string()]);
}

#[tokio::test]
async fn test_lists_summary_reports_counts_across_all_list_types() {
    let port = free_port().await;
    let mut config = make_test_config(port, 100);

    let temp_dir = tempfile::tempdir().unwrap();
    let fixture_path = temp_dir.path().join("category-fixture.txt");
    tokio::fs::write(
        &fixture_path,
        b"one.example.com\ntwo.example.com\nthree.example.com\n",
    )
    .await
    .unwrap();
    let fixture_url = format!("file://{}", fixture_path.to_str().unwrap());

    config.blocklist_categories = vec![BlocklistCategory {
        id: "summary-test-cat".to_string(),
        name: "Summary Test Category".to_string(),
        urls: vec![fixture_url.clone()],
        enabled: true,
    }];

    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(config));
    let engine = make_engine();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![fixture_url.clone()],
        temp_dir.path().to_path_buf(),
    ));
    updater.refresh().await.unwrap();

    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(
        shared_config,
        updater.clone(),
        l1_cache,
        l2_cache,
        None,
        network_tracker,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = format!("http://127.0.0.1:{}", port);
    let client = auth_client();
    let key = "test-secret-key";

    client
        .post(format!("{}/api/v1/lists/allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "summary-allow.example.com" }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/api/v1/lists/deny", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": "summary-deny.example.com" }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": r"^summary-regex-allow\." }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{}/api/v1/lists/malicious-ips", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "ip": "203.0.113.9" }))
        .send()
        .await
        .unwrap();

    let r = client
        .get(format!("{}/api/v1/lists/summary", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let summary: serde_json::Value = r.json().await.unwrap();

    assert_eq!(summary["local_allow"]["count"], 1);
    assert_eq!(summary["local_deny"]["count"], 1);
    assert_eq!(summary["regex_allow"]["count"], 1);
    assert_eq!(summary["regex_deny"]["count"], 0);
    assert_eq!(summary["malicious_ips"]["count"], 1);
    assert_eq!(summary["auto_blocked"]["count"], 0);
    assert_eq!(summary["uncategorized_sources"]["url_count"], 0);

    let categories = summary["categories"].as_array().unwrap();
    let cat = categories
        .iter()
        .find(|c| c["id"] == "summary-test-cat")
        .expect("summary-test-cat present");
    assert_eq!(cat["enabled"], true);
    assert_eq!(cat["paused"], false);
    assert_eq!(cat["url_count"], 1);
    assert_eq!(
        cat["rule_count"], 3,
        "expected the fixture's 3 lines to be counted, got {:?}",
        cat
    );
}

#[tokio::test]
async fn test_regex_duplicate_add_still_cross_removes_and_rebuilds() {
    let port = free_port().await;
    let config = make_test_config(port, 100);

    let temp_dir = tempfile::tempdir().unwrap();
    let shared_config = Arc::new(core_dns::config::ConfigHandle::new(config));
    let engine = make_engine();
    let updater = Arc::new(BlocklistUpdater::new_with_dir(
        engine.clone(),
        vec![],
        temp_dir.path().to_path_buf(),
    ));

    let pattern = r"^dual-membership\.example\.com$";

    // Seed legacy dual membership directly; add_regex_rule would self-heal it.
    {
        let mut allows = updater.regex_allows.lock().await;
        allows.insert(pattern.to_string());
    }
    {
        let mut denies = updater.regex_denies.lock().await;
        denies.insert(pattern.to_string());
    }

    // This unrelated deny witnesses snapshot publication: it is persisted in
    // updater state but absent from the live engine until a rebuild runs.
    let witness_domain = "pending-rebuild-witness.example.com";
    {
        let mut denies = updater.local_denies.lock().await;
        denies.insert(witness_domain.to_string());
    }
    assert_eq!(
        engine.check(&Name::from_str(witness_domain).unwrap()),
        FilterVerdict::Pass,
        "sanity check: witness domain must not be blocked before any rebuild runs"
    );

    let l1_cache = Arc::new(core_dns::cache::l1::L1Cache::new(100));
    let l2_cache = core_dns::cache::l2::L2Cache::new(64 * 1024 * 1024);
    let network_tracker = Arc::new(core_dns::network::NetworkTracker::new());

    api::start_admin_api(
        shared_config,
        updater.clone(),
        l1_cache,
        l2_cache,
        None,
        network_tracker,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = format!("http://127.0.0.1:{}", port);
    let client = auth_client();
    let key = "test-secret-key";

    // A duplicate allow still removes the deny entry, even though the API returns 400.
    let r = client
        .post(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "pattern": pattern }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "duplicate regex-allow add should still 400, got {:?}",
        r.text().await
    );

    // Prove the cross-removal side effect happened even on the 400 path.
    let r = client
        .get(format!("{}/api/v1/lists/regex-deny", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let list: Vec<String> = r.json().await.unwrap();
    assert!(
        !list.contains(&pattern.to_string()),
        "expected the duplicate regex-allow add to still cross-remove the pattern from regex-deny, got {:?}",
        list
    );

    // The duplicate add must retain the allow entry.
    let r = client
        .get(format!("{}/api/v1/lists/regex-allow", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let list: Vec<String> = r.json().await.unwrap();
    assert_eq!(list, vec![pattern.to_string()]);

    // The unrelated witness is blocked only if the duplicate-add path rebuilt the snapshot.
    assert_eq!(
        engine.check(&Name::from_str(witness_domain).unwrap()),
        FilterVerdict::Block,
        "expected the filter snapshot to have been rebuilt (picking up the pending local-deny rule) even though the regex-allow add was a duplicate"
    );
}

// Browser sessions and API credentials are deliberately separate.
#[tokio::test]
async fn test_web_cookie_does_not_authenticate_the_json_api() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    for request in [
        client
            .get(format!("{base}/api/v1/lists/allow"))
            .header("cookie", &cookie),
        client
            .get(format!("{base}/api/v1/lists/allow"))
            .bearer_auth(cookie.split('=').nth(1).unwrap()),
        client.get(format!("{base}/api/v1/lists/allow?key=test-secret-key")),
    ] {
        assert_eq!(
            request.send().await.unwrap().status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        client
            .get(format!("{base}/api/v1/lists/allow"))
            .bearer_auth("test-secret-key")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_web_rejects_api_keys_without_a_browser_session() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    for request in [
        client
            .get(format!("{base}/lists.html"))
            .bearer_auth("test-secret-key"),
        client.get(format!("{base}/lists.html?key=test-secret-key")),
        client
            .get(format!("{base}/lists.html"))
            .header("cookie", "dns_deny_session=test-secret-key"),
    ] {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
        assert!(
            response.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/login.html?next=")
        );
    }
}

#[tokio::test]
async fn test_login_rejects_wrong_password_without_issuing_cookie() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let response = auth_client()
        .post(format!("{base}/ui/auth/login"))
        .header("origin", &base)
        .form(&[("password", "wrong-password")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("Invalid admin password")
    );
}

#[tokio::test]
async fn test_login_redirect_stays_on_the_dashboard_origin() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    for next in ["https://evil.example", "//evil.example", "/\\evil.example"] {
        let response = auth_client()
            .post(format!("{base}/ui/auth/login"))
            .header("origin", &base)
            .form(&[("password", "test-secret-key"), ("next", next)])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(response.headers()["location"], "/");
        assert!(!response.text().await.unwrap().contains("token"));
    }
}

#[tokio::test]
async fn test_expired_background_requests_return_to_the_issuing_page() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let host = base.trim_start_matches("http://").to_string();
    let cases = [
        // A poll from an open page returns there, not to the fragment URL.
        (
            Some(format!("{base}/lists.html?tab=regex")),
            "/login.html?next=%2Flists%2Ehtml%3Ftab%3Dregex",
        ),
        // Missing or foreign referers fall back to the dashboard.
        (None, "/login.html?next=%2F"),
        (
            Some("https://evil.example/lists.html".to_string()),
            "/login.html?next=%2F",
        ),
    ];
    for (referer, expected) in cases {
        let mut request = client
            .get(format!("{base}/ui/protection"))
            .header("host", &host)
            .header("datastar-request", "true");
        if let Some(referer) = referer {
            request = request.header("referer", referer);
        }
        let body = request.send().await.unwrap().text().await.unwrap();
        assert!(
            body.contains(&format!("\"{expected}\"")),
            "expected redirect to {expected}, got {body}"
        );
    }
}

#[tokio::test]
async fn test_login_never_returns_to_a_ui_fragment() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let response = auth_client()
        .post(format!("{base}/ui/auth/login"))
        .header("origin", &base)
        .form(&[("password", "test-secret-key"), ("next", "/ui/protection")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/");
}

#[tokio::test]
async fn test_bcrypt_browser_session_uses_cookie_lookup_after_login() {
    let mut config = make_test_config(free_port().await, 1000);
    config.api_key = bcrypt::hash("correct-horse-battery", 4).unwrap();
    let (base, _tmp) = start_server(config).await;
    let client = auth_client();
    let cookie = login_cookie_key(&base, &client, "correct-horse-battery").await;
    for _ in 0..10 {
        assert_eq!(
            client
                .get(format!("{base}/ui/auth/session"))
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::NO_CONTENT
        );
    }
}

#[tokio::test]
async fn test_scalar_updates_persist_and_survive_reopen() {
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    let r = client
        .post(format!("{}/api/v1/config/doh", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "encrypted_upstream_enabled": true,
            "encrypted_upstream_allow_plaintext_fallback": false,
            "encrypted_upstream_url": "https://1.1.1.1/dns-query",
            "doh_upstreams": ["https://1.1.1.1/dns-query"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/config/safesearch", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "enforce_safesearch": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/network/device-blocking", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "device_blocking_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/config/services", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "blocked_services": ["tiktok", "steam"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/config/detection", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "smart_ip_blocking": true,
            "auto_block_upstream_sinkholes": true,
            "ml_scoring_enabled": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/config/upstreams", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "upstreams": [{ "address": "8.8.8.8:53", "protocol": "udp", "tls_sni": null, "doh_path": null }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let resp: serde_json::Value = r.json().await.unwrap();
    assert_eq!(resp["restart_required"], true);

    let r = client
        .post(format!("{}/api/v1/config/resolver", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "recursive_resolver_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let resp: serde_json::Value = r.json().await.unwrap();
    assert_eq!(resp["restart_required"], true);

    let r = client
        .post(format!("{}/api/v1/protection/settings", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "protection_pause_default_duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let db_path = temp_dir.path().join("state.db");
    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (loaded_config, revision) = store.load_current().unwrap().expect("snapshot must exist");
    assert!(revision >= 8);
    assert!(loaded_config.encrypted_upstream_enabled);
    assert_eq!(
        loaded_config.encrypted_upstream_url,
        "https://1.1.1.1/dns-query"
    );
    assert!(loaded_config.enforce_safesearch);
    assert!(loaded_config.device_blocking_enabled);
    assert_eq!(loaded_config.blocked_services, vec!["tiktok", "steam"]);
    assert!(loaded_config.smart_ip_blocking);
    assert!(loaded_config.auto_block_upstream_sinkholes);
    assert!(loaded_config.ml_scoring_enabled);
    assert_eq!(loaded_config.upstreams[0].address, "8.8.8.8:53");
    assert!(loaded_config.recursive_resolver_enabled);
    assert_eq!(loaded_config.protection_pause_default_duration_secs, 3600);
}

#[tokio::test]
async fn test_scalar_updates_forced_db_failure_leaves_live_state_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    // Make database files and directory read-only to force write failure
    for entry in std::fs::read_dir(temp_dir.path()).unwrap().flatten() {
        let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o400));
    }
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o500));

    let r = client
        .post(format!("{}/api/v1/config/safesearch", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "enforce_safesearch": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);

    // Restore permissions so cleanup works
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700));

    let r = client
        .get(format!("{}/api/v1/config/safesearch", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let cfg: serde_json::Value = r.json().await.unwrap();
    assert_eq!(cfg["enforce_safesearch"], false);
}

#[tokio::test]
async fn test_device_policy_mac_is_stored_normalized_without_duplicates() {
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";
    let db_path = temp_dir.path().join("state.db");
    let load = || {
        let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
        store.load_current().unwrap().expect("snapshot exists").0
    };
    let set_policy = |id: &'static str, policy: &'static str| {
        client
            .post(format!("{}/api/v1/network/policy", base))
            .bearer_auth(key)
            .json(&serde_json::json!({ "ip": id, "policy": policy }))
            .send()
    };

    let r = set_policy("AA-BB-CC-DD-EE-FF", "block").await.unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let conf = load();
    assert_eq!(conf.device_policies.len(), 1);
    assert_eq!(
        conf.device_policies
            .get("aa:bb:cc:dd:ee:ff")
            .map(|s| s.as_str()),
        Some("block")
    );

    // A differently-spelled identifier for the same device replaces it.
    let r = set_policy("aa:bb:cc:dd:ee:ff", "whitelist").await.unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let conf = load();
    assert_eq!(conf.device_policies.len(), 1);
    assert_eq!(
        conf.device_policies
            .get("aa:bb:cc:dd:ee:ff")
            .map(|s| s.as_str()),
        Some("whitelist")
    );

    let r = set_policy("AA:BB:CC:DD:EE:FF", "default").await.unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    assert!(load().device_policies.is_empty());
}

#[tokio::test]
async fn test_collection_updates_persist_and_survive_reopen() {
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";
    let db_path = temp_dir.path().join("state.db");

    let r = client
        .post(format!("{}/api/v1/network/policy", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "ip": "192.168.1.50", "policy": "block" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(
        conf.device_policies.get("192.168.1.50").map(|s| s.as_str()),
        Some("block")
    );

    let r = client
        .post(format!("{}/api/v1/network/policy", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "ip": "192.168.1.50", "policy": "default" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(!conf.device_policies.contains_key("192.168.1.50"));

    let r = client
        .post(format!("{}/api/v1/network/schedules", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "ip": "192.168.1.51",
            "policy": "block",
            "days": ["mon"],
            "start_time": "08:00",
            "end_time": "17:00"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(conf.device_schedules.iter().any(|s| s.ip == "192.168.1.51"));

    let r = client
        .delete(format!("{}/api/v1/network/schedules/192.168.1.51", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(!conf.device_schedules.iter().any(|s| s.ip == "192.168.1.51"));

    let r = client
        .post(format!("{}/api/v1/network/aliases", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "identifier": "192.168.1.52", "name": "Work Laptop" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(
        conf.client_aliases
            .iter()
            .any(|a| a.identifier == "192.168.1.52")
    );

    let r = client
        .delete(format!("{}/api/v1/network/aliases/192.168.1.52", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(
        !conf
            .client_aliases
            .iter()
            .any(|a| a.identifier == "192.168.1.52")
    );

    let r = client
        .post(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "name": "printer.lan",
            "record_type": "A",
            "value": "192.168.1.200"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(
        conf.local_dns_records
            .iter()
            .any(|r| r.name == "printer.lan")
    );

    let r = client
        .delete(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "name": "printer.lan",
            "record_type": "A"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(
        !conf
            .local_dns_records
            .iter()
            .any(|r| r.name == "printer.lan")
    );

    let r = client
        .post(format!("{}/api/v1/config/blocklist", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "blocklist_urls": ["https://example.com/hosts.txt"],
            "blocklist_categories": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(conf.blocklist_urls, vec!["https://example.com/hosts.txt"]);
}

#[tokio::test]
async fn test_collection_updates_duplicate_and_not_found_preserve_revision() {
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";
    let db_path = temp_dir.path().join("state.db");

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, initial_rev) = store.load_current().unwrap().expect("snapshot exists");

    // 1. Delete nonexistent schedule -> 404, revision unchanged
    let r = client
        .delete(format!("{}/api/v1/network/schedules/10.99.99.99", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NOT_FOUND);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, rev) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(rev, initial_rev);

    // 2. Delete nonexistent alias -> 404, revision unchanged
    let r = client
        .delete(format!("{}/api/v1/network/aliases/10.99.99.99", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NOT_FOUND);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, rev) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(rev, initial_rev);

    // 3. Delete nonexistent local DNS -> 404, revision unchanged
    let r = client
        .delete(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "name": "missing.lan", "record_type": "A" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NOT_FOUND);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, rev) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(rev, initial_rev);

    // 4. Add local DNS -> 200, revision incremented by 1
    let r = client
        .post(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "name": "test.lan",
            "record_type": "A",
            "value": "1.2.3.4"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, rev_after_add) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(rev_after_add, initial_rev + 1);

    // 5. Add duplicate local DNS -> 400, revision unchanged
    let r = client
        .post(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "name": "test.lan",
            "record_type": "A",
            "value": "1.2.3.4"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::BAD_REQUEST);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (_, rev_after_dup) = store.load_current().unwrap().expect("snapshot exists");
    assert_eq!(rev_after_dup, rev_after_add);
}

#[tokio::test]
async fn test_collection_updates_forced_db_failure_leaves_live_state_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";

    // Make database files and directory read-only to force write failure
    for entry in std::fs::read_dir(temp_dir.path()).unwrap().flatten() {
        let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o400));
    }
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o500));

    let r = client
        .post(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .json(&serde_json::json!({
            "name": "fail.lan",
            "record_type": "A",
            "value": "1.2.3.4"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);

    // Restore permissions so cleanup works
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700));

    let r = client
        .get(format!("{}/api/v1/local-dns", base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let records: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(!records.iter().any(|rec| rec["name"] == "fail.lan"));
}

#[tokio::test]
async fn test_protection_pause_and_resume_survives_reopen() {
    let port = free_port().await;
    let (base, temp_dir) = start_server(make_test_config(port, 100)).await;
    let client = auth_client();
    let key = "test-secret-key";
    let db_path = temp_dir.path().join("state.db");

    let r = client
        .post(format!("{}/api/v1/protection/pause", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "scope": "global", "duration_secs": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(conf.protection_paused_until.is_some());

    let r = client
        .post(format!("{}/api/v1/protection/resume", base))
        .bearer_auth(key)
        .json(&serde_json::json!({ "scope": "global" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (conf, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(conf.protection_paused_until.is_none());
}

#[tokio::test]
async fn test_password_update_failed_commit_retains_credential_and_sessions() {
    use std::os::unix::fs::PermissionsExt;
    let port = free_port().await;
    let mut cfg = make_test_config(port, 100);
    cfg.api_key = bcrypt::hash("original-secret-key", 4).unwrap();
    let (base, temp_dir) = start_server(cfg).await;
    let client = auth_client();

    let cookie = login_cookie_key(&base, &client, "original-secret-key").await;

    let r = client
        .get(format!("{}/ui/auth/session", base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NO_CONTENT);

    // Make database files and directory read-only to force write failure
    for entry in std::fs::read_dir(temp_dir.path()).unwrap().flatten() {
        let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o400));
    }
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o500));

    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .bearer_auth("original-secret-key")
        .json(&serde_json::json!({
            "current_password": "original-secret-key",
            "new_password": "new-secret-password-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);

    // Restore permissions so cleanup works
    let _ = std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700));

    // Session token MUST still be valid because commit failed before revocation!
    let r = client
        .get(format!("{}/ui/auth/session", base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::NO_CONTENT);

    let r = client
        .post(format!("{}/ui/auth/login", base))
        .header("origin", &base)
        .form(&[("password", "original-secret-key")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::SEE_OTHER);

    let r = client
        .post(format!("{}/ui/auth/login", base))
        .header("origin", &base)
        .form(&[("password", "new-secret-password-123")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_password_update_successful_commit_revokes_sessions() {
    let port = free_port().await;
    let mut cfg = make_test_config(port, 100);
    cfg.api_key = bcrypt::hash("original-secret-key", 4).unwrap();
    let (base, temp_dir) = start_server(cfg).await;
    let client = auth_client();
    let db_path = temp_dir.path().join("state.db");

    let cookie = login_cookie_key(&base, &client, "original-secret-key").await;

    let r = client
        .post(format!("{}/api/v1/config/password", base))
        .bearer_auth("original-secret-key")
        .json(&serde_json::json!({
            "current_password": "original-secret-key",
            "new_password": "new-secret-password-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .get(format!("{}/ui/auth/session", base))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    let r = client
        .post(format!("{}/ui/auth/login", base))
        .header("origin", &base)
        .form(&[("password", "original-secret-key")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    let r = client
        .post(format!("{}/ui/auth/login", base))
        .header("origin", &base)
        .form(&[("password", "new-secret-password-123")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::SEE_OTHER);

    let store = core_dns::config_store::ConfigStore::open(&db_path).unwrap();
    let (loaded, _) = store.load_current().unwrap().expect("snapshot exists");
    assert!(bcrypt::verify("new-secret-password-123", &loaded.api_key).unwrap());
}

#[tokio::test]
async fn test_cache_stats_and_invalidate_endpoints() {
    let port = free_port().await;
    let cfg = make_test_config(port, 100);
    let (base, _temp_dir) = start_server(cfg).await;
    let client = auth_client();

    let unauth_client = reqwest::Client::new();
    let r = unauth_client
        .get(format!("{}/api/v1/cache", base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    let r = unauth_client
        .post(format!("{}/api/v1/cache/invalidate", base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::UNAUTHORIZED);

    let r = client
        .get(format!("{}/api/v1/cache", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let stats: serde_json::Value = r.json().await.unwrap();
    assert!(stats["l1_entries"].is_number());
    assert_eq!(stats["l1_max_entries"], 1000);
    assert!(stats["l2_entries"].is_number());
    assert!(stats["l2_size_bytes"].is_number());
    assert_eq!(stats["l2_max_size_bytes"], 64 * 1024 * 1024);
    assert!(stats["filter_cache_entries"].is_number());

    let r = client
        .get(format!("{}/api/v1/cache/stats", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .post(format!("{}/api/v1/cache/invalidate", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let resp: serde_json::Value = r.json().await.unwrap();
    assert_eq!(resp["status"], "success");
    assert_eq!(resp["l1_cleared"], true);
    assert_eq!(resp["l2_cleared"], true);
    assert_eq!(resp["filter_cache_cleared"], true);

    // Stats read straight after the invalidation, with nothing else touching
    // the caches in between: the reported counts must reflect the clear, not
    // moka's stale pre-invalidation totals.
    let r = client
        .get(format!("{}/api/v1/cache", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let stats: serde_json::Value = r.json().await.unwrap();
    assert_eq!(stats["l1_entries"], 0);
    assert_eq!(stats["l2_entries"], 0);
    assert_eq!(stats["l2_size_bytes"], 0);
    assert_eq!(stats["filter_cache_entries"], 0);

    let r = client
        .post(format!("{}/api/v1/cache/clear", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);

    let r = client
        .delete(format!("{}/api/v1/cache", base))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
}

// Browser sessions use a shared cookie; API clients can still send Bearer keys.
async fn login_cookie(base: &str, client: &reqwest::Client) -> String {
    login_cookie_key(base, client, "test-secret-key").await
}

#[tokio::test]
async fn test_web_resolver_and_upstreams_save_atomically() {
    let mut config = make_test_config(free_port().await, 1000);
    config.dnssec_validation = true;
    let (base, directory) = start_server(config).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let load = || {
        core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
            .unwrap()
            .load_current()
            .unwrap()
            .unwrap()
    };
    let (_, original_revision) = load();
    let mut fields = [
        ("_form", "upstreams-form"),
        ("intent", "save"),
        ("_upstreams_present", "1"),
        ("address", "9.9.9.9:53"),
        ("protocol", "dot"),
        ("tls_sni", ""),
        ("doh_path", ""),
        ("recursive_resolver_enabled", "on"),
    ];
    let response = client
        .post(format!("{base}/ui/action/config/main"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .header("datastar-request", "true")
        .form(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let html = response.text().await.unwrap();
    assert!(html.contains("role=\"alert\""));
    assert!(
        html.contains("9.9.9.9:53"),
        "invalid draft must remain editable"
    );
    let (config, revision) = load();
    assert_eq!(revision, original_revision);
    assert!(!config.recursive_resolver_enabled);
    assert_eq!(config.upstreams[0].address, "1.1.1.1:53");

    // Fix the missing-SNI draft by selecting UDP; recursive DNSSEC is supported.
    fields[4].1 = "udp";
    let response = client
        .post(format!("{base}/ui/action/config/main"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .form(&fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    let (config, revision) = load();
    assert!(revision > original_revision);
    assert!(config.recursive_resolver_enabled);
    assert_eq!(config.upstreams[0].address, "9.9.9.9:53");
}

#[tokio::test]
async fn test_web_device_policy_uses_stable_mac_and_removes_legacy_ip() {
    let (base, directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let load = || {
        core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
            .unwrap()
            .load_current()
            .unwrap()
            .unwrap()
    };
    let (_, original_revision) = load();
    for (mac, valid) in [("invalid-mac", false), ("AA-BB-CC-DD-EE-FF", true)] {
        let response = client
            .post(format!("{base}/ui/action/network/devices"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("datastar-request", "true")
            .form(&[
                ("intent", "policy"),
                ("ip", "192.0.2.10"),
                ("mac", mac),
                ("policy", "block"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let (config, revision) = load();
        if valid {
            assert!(revision > original_revision);
            assert_eq!(config.device_policies.len(), 1);
            assert!(!config.device_policies.contains_key("192.0.2.10"));
            assert_eq!(config.device_policies["aa:bb:cc:dd:ee:ff"], "block");
        } else {
            assert_eq!(revision, original_revision);
            assert!(config.device_policies.is_empty());
        }
    }
}

#[tokio::test]
async fn test_web_password_errors_never_reflect_submitted_secrets() {
    let (base, _directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    for datastar in [false, true] {
        let response = client
            .post(format!("{base}/ui/action/config/security"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("datastar-request", datastar.to_string())
            .form(&[
                ("_form", "password-form"),
                ("intent", "save"),
                ("current_password", "test-secret-key"),
                ("new_password", "secret-must-never-appear"),
                ("confirm_password", "different-secret-value"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let html = response.text().await.unwrap();
        assert!(html.contains("New passwords do not match"));
        for secret in [
            "test-secret-key",
            "secret-must-never-appear",
            "different-secret-value",
        ] {
            assert!(!html.contains(secret));
        }
    }
}
async fn login_cookie_key(base: &str, client: &reqwest::Client, key: &str) -> String {
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("origin", base)
        .form(&[("password", key)])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/;"));
    assert!(cookie.contains("Max-Age=43200"));
    cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn test_browser_cookie_authenticates_tabs_and_logout_revokes_shared_session() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let first = auth_client();
    let second = auth_client();
    let cookie = login_cookie(&base, &first).await;
    // Independent clients emulate tabs sharing the browser cookie jar.
    for client in [&first, &second] {
        let response = client
            .get(format!("{base}/ui/auth/session"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    }
    let response = first
        .post(format!("{base}/ui/auth/logout"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let response = second
        .get(format!("{base}/ui/auth/session"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_cookie_mutations_require_same_origin_but_bearer_clients_work() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    for origin in [None, Some("http://evil.example"), Some("null")] {
        let mut request = client
            .post(format!("{base}/ui/action/lists/allow"))
            .header("cookie", &cookie)
            .header("datastar-request", "true")
            .form(&[("intent", "add"), ("pattern", "cookie.example")]);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            reqwest::StatusCode::FORBIDDEN
        );
    }
    let response = client
        .post(format!("{base}/ui/action/lists/allow"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .header("datastar-request", "true")
        .form(&[("intent", "add"), ("pattern", "cookie.example")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response = client
        .post(format!("{base}/api/v1/lists/allow"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"pattern": "script.example"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_cookie_rejects_raw_api_key_and_login_rejects_foreign_origin() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let response = client
        .get(format!("{base}/ui/auth/session"))
        .header("cookie", "dns_deny_session=test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("origin", "https://evil.example")
        .form(&[("password", "test-secret-key")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key("set-cookie"));
}

#[tokio::test]
async fn test_cookie_rotation_and_https_secure_attribute() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let original = login_cookie(&base, &client).await;
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("cookie", &original)
        .header("origin", base.replacen("http://", "https://", 1))
        .form(&[("password", "test-secret-key")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("; Secure"));
    let replacement = cookie.split(';').next().unwrap().to_string();
    assert_ne!(original, replacement);
    for (cookie, expected) in [
        (&original, reqwest::StatusCode::UNAUTHORIZED),
        (&replacement, reqwest::StatusCode::NO_CONTENT),
    ] {
        let response = client
            .get(format!("{base}/ui/auth/session"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn test_api_token_replaces_the_admin_password_for_the_json_api() {
    let (base, directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let status = |credential: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .get(format!("{base}/api/v1/stats"))
                .bearer_auth(credential)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let token_action = |intent: &'static str| {
        client
            .post(format!("{base}/ui/action/config/api-token"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("datastar-request", "true")
            .form(&[("_form", "api-token-generate"), ("intent", intent)])
            .send()
    };

    // Until a token exists, the admin credential keeps working.
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::OK
    );

    let response = token_action("generate").await.unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = response.text().await.unwrap();
    let token = regex::Regex::new(r#"data-copy="([0-9a-f]{64})""#)
        .unwrap()
        .captures(&body)
        .expect("issued token is shown once")[1]
        .to_string();

    // Only the digest is persisted, and the GET config endpoint redacts it.
    let (stored, _) = core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
        .unwrap()
        .load_current()
        .unwrap()
        .unwrap();
    let digest = stored.api_token_sha256.expect("token digest persisted");
    assert_ne!(digest, token);
    assert_eq!(digest.len(), 64);

    assert_eq!(status(token.clone()).await, reqwest::StatusCode::OK);
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(status(digest).await, reqwest::StatusCode::UNAUTHORIZED);
    let config: serde_json::Value = client
        .get(format!("{base}/api/v1/config"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(config["api_token_sha256"], "********");

    // Re-rendering the section never shows the token again.
    let section = client
        .get(format!("{base}/ui/section/config/api-token"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(section.contains("Token active"));
    assert!(!section.contains(&token));

    token_action("revoke").await.unwrap();
    assert_eq!(status(token).await, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_api_token_survives_admin_password_changes() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let body = client
        .post(format!("{base}/ui/action/config/api-token"))
        .header("cookie", &cookie)
        .header("origin", &base)
        .header("datastar-request", "true")
        .form(&[("_form", "api-token-generate"), ("intent", "generate")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = regex::Regex::new(r#"data-copy="([0-9a-f]{64})""#)
        .unwrap()
        .captures(&body)
        .unwrap()[1]
        .to_string();
    let response = client
        .post(format!("{base}/api/v1/config/password"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "current_password": "test-secret-key",
            "new_password": "a-brand-new-password"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_api_token_endpoint_issues_and_revokes_tokens() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let issued: serde_json::Value = client
        .post(format!("{base}/api/v1/auth/token"))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = issued["token"].as_str().unwrap().to_string();
    let stats = |credential: &str| {
        client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth(credential)
            .send()
    };
    assert_eq!(
        stats(&token).await.unwrap().status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        stats("test-secret-key").await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    // Rotating replaces the previous token.
    let rotated: serde_json::Value = client
        .post(format!("{base}/api/v1/auth/token"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rotated = rotated["token"].as_str().unwrap().to_string();
    assert_eq!(
        stats(&token).await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    client
        .delete(format!("{base}/api/v1/auth/token"))
        .bearer_auth(&rotated)
        .send()
        .await
        .unwrap();
    assert_eq!(
        stats("test-secret-key").await.unwrap().status(),
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_static_assets_are_revalidated_and_pages_version_them() {
    let (base, _tmp) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    // Missing files (the test runs without a static directory) must never be
    // cached long-term, even under /vendor/.
    for path in ["/styles.css", "/vendor/missing-1.0.0.js"] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.headers()["cache-control"], "no-cache", "{path}");
    }
    let cookie = login_cookie(&base, &client).await;
    let page = client
        .get(format!("{base}/services.html"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(page.headers()["cache-control"], "no-store");
    let html = page.text().await.unwrap();
    assert!(html.contains("/styles.css?v="));
    assert!(html.contains("/ui.js?v="));
}

#[tokio::test]
async fn test_production_transport_requires_a_trusted_https_proxy() {
    let port = free_port().await;
    let mut config = make_test_config(port, 1000);
    config.api_allow_insecure_http = false;
    let (base, _dir) = start_server(config).await;
    let client = auth_client();
    for https_origin in [false, true] {
        let mut request = client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth("test-secret-key");
        if https_origin {
            request = request.header("origin", base.replace("http://", "https://"));
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            reqwest::StatusCode::UPGRADE_REQUIRED
        );
    }
    let response = client
        .get(format!("{base}/api/v1/stats"))
        .bearer_auth("test-secret-key")
        .header("x-forwarded-proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()["strict-transport-security"],
        "max-age=31536000"
    );
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("x-forwarded-proto", "https")
        .header("origin", base.replace("http://", "https://"))
        .form(&[("password", "test-secret-key")])
        .send()
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("; Secure")
    );
    assert_eq!(
        client
            .get(format!("{base}/"))
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UPGRADE_REQUIRED
    );

    let port = free_port().await;
    let mut config = make_test_config(port, 1000);
    config.api_allow_insecure_http = false;
    config.api_trusted_proxy_cidrs.clear();
    let (base, _dir) = start_server(config).await;
    assert_eq!(
        client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth("test-secret-key")
            .header("x-forwarded-proto", "https")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UPGRADE_REQUIRED
    );
}

#[tokio::test]
async fn test_login_attempts_have_a_separate_stricter_limit() {
    let port = free_port().await;
    let (base, _dir) = start_server(make_test_config(port, 1000)).await;
    let client = auth_client();
    for _ in 0..10 {
        assert_eq!(
            client
                .post(format!("{base}/ui/auth/login"))
                .header("origin", &base)
                .form(&[("password", "incorrect")])
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        client
            .post(format!("{base}/ui/auth/login"))
            .header("origin", &base)
            .form(&[("password", "incorrect")])
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth("test-secret-key")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn test_custom_doh_supports_dnssec_validation_and_persists_settings() {
    let port = free_port().await;
    let mut config = make_test_config(port, 1000);
    config.dnssec_validation = true;
    let (base, directory) = start_server(config).await;
    let response = auth_client()
        .post(format!("{base}/api/v1/config/doh"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({
            "encrypted_upstream_enabled": true,
            "encrypted_upstream_allow_plaintext_fallback": false,
            "encrypted_upstream_url": "https://cloudflare-dns.com/dns-query",
            "doh_upstreams": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (_, config) = get_json(&base, "/api/v1/config/doh").await;
    assert_eq!(config["encrypted_upstream_enabled"], true);
    let (saved, _) = core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
        .unwrap()
        .load_current()
        .unwrap()
        .unwrap();
    assert!(saved.dnssec_validation);
    assert!(saved.encrypted_upstream_enabled);
}

#[tokio::test]
async fn test_proxy_login_quota_uses_the_verified_client_and_ignores_spoofed_prefixes() {
    let port = free_port().await;
    let mut config = make_test_config(port, 1000);
    config.api_allow_insecure_http = false;
    let (base, _dir) = start_server(config).await;
    let client = auth_client();
    for attempt in 0..11 {
        let response = client
            .post(format!("{base}/ui/auth/login"))
            .header("origin", base.replace("http://", "https://"))
            .header("x-forwarded-proto", "https")
            .header(
                "x-forwarded-for",
                format!("203.0.113.{attempt}, 198.51.100.1"),
            )
            .form(&[("password", "incorrect")])
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if attempt < 10 {
                reqwest::StatusCode::UNAUTHORIZED
            } else {
                reqwest::StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("origin", base.replace("http://", "https://"))
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "198.51.100.2")
        .form(&[("password", "incorrect")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_probe_service_deny_precedes_domain_allow_and_safesearch_respects_deny() {
    let (base, _directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let response = client
        .post(format!("{base}/api/v1/lists/allow"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"pattern":"tiktok.com"}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = client
        .post(format!("{base}/api/v1/config/services"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"blocked_services":["tiktok"],"custom_services":[]}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let (_, probe) = get_json(&base, "/api/v1/diagnostics/probe?domain=tiktok.com").await;
    assert_eq!(probe["verdict"], "blocked");
    let response = client
        .post(format!("{base}/api/v1/lists/deny"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"pattern":"www.google.com"}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let response = client
        .post(format!("{base}/api/v1/config/safesearch"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"enforce_safesearch":true}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let (_, probe) = get_json(&base, "/api/v1/diagnostics/probe?domain=www.google.com").await;
    assert_eq!(probe["verdict"], "blocked");
}

#[tokio::test]
async fn test_device_pause_persists_normalizes_conflicts_resumes_and_keeps_static_policy() {
    let mut seed = make_test_config(free_port().await, 1000);
    seed.device_blocking_enabled = true;
    seed.device_policies
        .insert("aa:bb:cc:dd:ee:01".into(), "block".into());
    let (base, directory) = start_server(seed).await;
    let client = auth_client();
    let response = client
        .post(format!("{base}/api/v1/protection/pause"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"scope":"device", "id":"AA-BB-CC-DD-EE-01", "duration_secs":300}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let paused: serde_json::Value = response.json().await.unwrap();
    assert_eq!(paused["id"], "aa:bb:cc:dd:ee:01");
    let until = paused["paused_until"].as_i64().unwrap();
    let store =
        core_dns::config_store::ConfigStore::open(directory.path().join("state.db")).unwrap();
    let (saved, revision) = store.load_current().unwrap().unwrap();
    assert_eq!(saved.device_pauses["aa:bb:cc:dd:ee:01"], until);
    assert_eq!(saved.device_policies["aa:bb:cc:dd:ee:01"], "block");
    let reopened = core_dns::config::ConfigHandle::new_persistent(store, saved, revision).unwrap();
    let (_, status) = get_json(&base, "/api/v1/protection/status").await;
    assert_eq!(status["device_pauses"]["aa:bb:cc:dd:ee:01"], until);
    assert!(reopened.load().is_paused(
        &core_dns::config::PauseScope::Device("AA-BB-CC-DD-EE-01".into()),
        until - 1
    ));
    let duplicate = client
        .post(format!("{base}/api/v1/protection/pause"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"scope":"device", "id":"aa:bb:cc:dd:ee:01", "duration_secs":300}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), reqwest::StatusCode::CONFLICT);
    let resume = client
        .post(format!("{base}/api/v1/protection/resume"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({"scope":"device", "id":"AA-BB-CC-DD-EE-01"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resume.status(), reqwest::StatusCode::OK);
    let (saved, _) = core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
        .unwrap()
        .load_current()
        .unwrap()
        .unwrap();
    assert!(saved.device_pauses.is_empty());
    assert_eq!(saved.device_policies["aa:bb:cc:dd:ee:01"], "block");
}

#[tokio::test]
async fn test_invalid_device_pauses_do_not_mutate_config() {
    let (base, directory) = start_server(make_test_config(free_port().await, 1000)).await;
    let client = auth_client();
    let before = core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
        .unwrap()
        .load_current()
        .unwrap()
        .unwrap();
    for payload in [
        serde_json::json!({"scope":"device", "duration_secs":300}),
        serde_json::json!({"scope":"device", "id":"invalid", "duration_secs":300}),
        serde_json::json!({"scope":"device", "id":"192.0.2.1", "duration_secs":0}),
        serde_json::json!({"scope":"device", "id":"192.0.2.1", "duration_secs":172801}),
        serde_json::json!({"scope":"device", "id":"192.0.2.1", "indefinite":true}),
    ] {
        let response = client
            .post(format!("{base}/api/v1/protection/pause"))
            .bearer_auth("test-secret-key")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "{payload}"
        );
    }
    let after = core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
        .unwrap()
        .load_current()
        .unwrap()
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn test_web_device_timer_and_expired_status_render_without_json_api_calls() {
    let mut seed = make_test_config(free_port().await, 1000);
    seed.device_blocking_enabled = true;
    seed.device_pauses
        .insert("192.0.2.1".into(), core_dns::config::now_epoch() - 1);
    let (base, directory) = start_server(seed).await;
    let client = auth_client();
    let cookie = login_cookie(&base, &client).await;
    let (_, status) = get_json(&base, "/api/v1/protection/status").await;
    assert_eq!(status["device_pauses"], serde_json::json!({}));
    for (intent, paused) in [("pause", true), ("resume", false)] {
        let response = client
            .post(format!("{base}/ui/action/network/devices"))
            .header("cookie", &cookie)
            .header("origin", &base)
            .header("datastar-request", "true")
            .form(&[
                ("intent", intent),
                ("scope", "device"),
                ("id", "AA-BB-CC-DD-EE-01"),
                ("seconds", "300"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let html = response.text().await.unwrap();
        assert!(!html.contains("Could not render"), "{html}");
        let (saved, _) =
            core_dns::config_store::ConfigStore::open(directory.path().join("state.db"))
                .unwrap()
                .load_current()
                .unwrap()
                .unwrap();
        assert_eq!(
            saved.device_pauses.contains_key("aa:bb:cc:dd:ee:01"),
            paused
        );
        if paused {
            assert!(html.contains("aa:bb:cc:dd:ee:01"));
        }
    }
}
