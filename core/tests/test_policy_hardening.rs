#[allow(dead_code)]
mod support;

use core_dns::cache::{l1::L1Cache, l2::L2Cache};
use core_dns::config::{Config, ConfigHandle, LocalDnsRecord};
use core_dns::handler::DnsHandler;
use core_dns::network::NetworkTracker;
use core_dns::updater::BlocklistUpdater;
use filter::{
    FilterEngine, exact::ExactFilter, regex_set::RegexFilter, snapshot::FilterSnapshot,
    trie::SubdomainTrie,
};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType, rdata::A};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use std::sync::Arc;
use std::time::Duration;
use support::{DnsMock, Fixture};

fn test_resolver(mock: &DnsMock) -> TokioResolver {
    test_resolver_with_timeout(mock, Duration::from_millis(200))
}
fn test_resolver_with_timeout(mock: &DnsMock, timeout: Duration) -> TokioResolver {
    let mut nameserver = NameServerConfig::udp(mock.udp_addr().ip());
    nameserver.connections[0].port = mock.udp_addr().port();
    let resolver_config = ResolverConfig::from_parts(None, vec![], vec![nameserver]);
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1;
    opts.preserve_intermediates = true;
    TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .unwrap()
}

struct Harness {
    config: Arc<ConfigHandle>,
    updater: Arc<BlocklistUpdater>,
    address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Harness {
    async fn start(mock: &DnsMock, mutate: impl FnOnce(&mut Config)) -> Self {
        Self::start_with_discovery(mock, None, mutate).await
    }

    async fn start_with_discovery(
        mock: &DnsMock,
        discovery: Option<&DnsMock>,
        mutate: impl FnOnce(&mut Config),
    ) -> Self {
        Self::start_with_limits(mock, discovery, mutate, 1024, 128).await
    }

    async fn start_with_limits(
        mock: &DnsMock,
        discovery: Option<&DnsMock>,
        mutate: impl FnOnce(&mut Config),
        requests: usize,
        upstreams: usize,
    ) -> Self {
        let mut config: Config = toml::from_str(include_str!("../../config/pi-zero.toml")).unwrap();
        config.smart_ip_blocking = true;
        config.auto_block_upstream_sinkholes = false;
        config.device_blocking_enabled = false;
        config.enforce_safesearch = false;
        mutate(&mut config);
        let config = Arc::new(ConfigHandle::new_ephemeral(config));
        let engine = Arc::new(FilterEngine::new(FilterSnapshot::new(
            ExactFilter::new(),
            SubdomainTrie::new(),
            RegexFilter::new(&[], &[]).unwrap(),
        )));
        let dir = tempfile::tempdir().unwrap();
        let updater = Arc::new(BlocklistUpdater::new_with_dir(
            engine.clone(),
            vec![],
            dir.path().to_path_buf(),
        ));
        let resolver = if requests < 1024 || upstreams < 128 {
            test_resolver_with_timeout(mock, Duration::from_secs(2))
        } else {
            test_resolver(mock)
        };
        let handler = DnsHandler::new(
            resolver,
            None,
            discovery.map(test_resolver),
            Arc::new(L1Cache::new(100)),
            L2Cache::new(1024 * 1024),
            engine,
            updater.clone(),
            config.clone(),
            None,
            Arc::new(NetworkTracker::new()),
            Arc::new(arc_swap::ArcSwapOption::empty()),
        )
        .with_query_limits(requests, upstreams);
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut server = hickory_server::Server::new(handler);
            server.register_socket(socket);
            let _ = server.block_until_done().await;
        });
        Self {
            config,
            updater,
            address,
            task,
            _dir: dir,
        }
    }
    async fn query(&self, name: &str) -> Message {
        self.query_type(name, RecordType::A).await
    }

    async fn query_type(&self, name: &str, query_type: RecordType) -> Message {
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), query_type));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&request.to_vec().unwrap(), self.address)
            .await
            .unwrap();
        let mut bytes = [0; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        Message::from_bytes(&bytes[..len]).unwrap()
    }
}

// Regressions for filtering and pause bugs found during review.
#[tokio::test]
async fn test_cname_targets_are_filtered_after_cache_warmup() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "alias.example.",
        RecordType::A,
        Fixture::CnameThenA {
            canonical: Name::from_ascii("denied.example.").unwrap(),
            cname_ttl: 300,
            address: A::new(192, 0, 2, 7),
            address_ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |_| {}).await;
    assert_eq!(
        h.query("alias.example.").await.metadata.response_code,
        ResponseCode::NoError
    );
    h.updater
        .add_local_rule("denied.example".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    assert_eq!(
        h.query("denied.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let response = h.query("alias.example.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
}
#[tokio::test]
async fn test_local_aliases_enforce_domain_and_ip_policy() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "denied.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 8),
            ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |c| {
        c.local_dns_records.push(LocalDnsRecord {
            name: "local.example".into(),
            record_type: "CNAME".into(),
            value: "denied.example".into(),
        })
    })
    .await;
    h.updater
        .add_local_rule("denied.example".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater
        .add_malicious_ips(vec!["192.0.2.8".parse().unwrap()])
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    assert_eq!(
        h.query("denied.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let response = h.query("local.example.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
}
#[tokio::test]
async fn test_pause_and_whitelist_bypass_safesearch() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "google.com.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 2),
            ttl: 300,
        },
    )
    .await;
    for whitelist in [false, true] {
        let h = Harness::start(&mock, |c| {
            c.enforce_safesearch = true;
            if whitelist {
                c.device_blocking_enabled = true;
                c.device_policies
                    .insert("127.0.0.1".into(), "whitelist".into());
            } else {
                c.protection_paused_until = Some(core_dns::config::now_epoch() + 300);
            }
        })
        .await;
        let response = h.query("google.com.").await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(!response.answers.iter().any(|rr| matches!(&rr.data, hickory_proto::rr::RData::CNAME(target) if target.0 == Name::from_ascii("forcesafesearch.google.com.").unwrap())));
    }
}
#[tokio::test]
async fn test_domain_deny_precedes_safesearch() {
    let mock = DnsMock::start().await.unwrap();
    let h = Harness::start(&mock, |c| c.enforce_safesearch = true).await;
    h.updater
        .add_local_rule("www.google.com".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    let response = h.query("www.google.com.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
}
#[tokio::test]
async fn test_source_removal_publishes_even_when_remaining_sources_return_304() {
    let mock = DnsMock::start().await.unwrap();
    let h = Harness::start(&mock, |_| {}).await;
    mock.set_fixture(
        "first.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 1),
            ttl: 300,
        },
    )
    .await;
    let (first, t1) = conditional_source("first.example").await;
    let (second, t2) = conditional_source("second.example").await;
    h.updater
        .sync_sources(&[first.clone(), second.clone()])
        .await;
    h.updater.refresh().await.unwrap();
    assert_eq!(
        h.query("first.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    h.updater.sync_sources(&[second]).await;
    h.updater.refresh().await.unwrap();
    // A source membership edit must publish even if downloads are unchanged.
    assert_eq!(
        h.query("first.example.").await.metadata.response_code,
        ResponseCode::NoError
    );
    t1.abort();
    t2.abort();
}
#[tokio::test]
async fn test_category_resume_retains_rules_offline() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "first.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 1),
            ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |_| {}).await;
    let (url, server) = conditional_source("first.example").await;
    h.updater.sync_sources(std::slice::from_ref(&url)).await;
    h.updater.refresh().await.unwrap();
    assert_eq!(
        h.query("first.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    h.updater.sync_sources(&[]).await;
    h.updater.refresh().await.unwrap();
    assert_eq!(
        h.query("first.example.").await.metadata.response_code,
        ResponseCode::NoError
    );
    server.abort();
    tokio::task::yield_now().await;
    h.updater.sync_sources(std::slice::from_ref(&url)).await;
    h.updater.refresh().await.unwrap();
    assert_eq!(
        h.query("first.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
}
#[tokio::test]
async fn test_large_regex_sets_preserve_existing_deny_rules() {
    let mock = DnsMock::start().await.unwrap();
    let h = Harness::start(&mock, |_| {}).await;
    let blocked = Name::from_ascii("blocked.example.").unwrap();
    h.updater
        .add_regex_rule(r"^blocked\.example$".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    assert_eq!(
        h.query("blocked.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let patterns: Vec<String> = (0..64)
        .map(|i| format!("^entry-{i}[a-z]{{1000}}$"))
        .collect();
    assert!(regex::Regex::new(&patterns[0]).is_ok());
    assert!(RegexFilter::new(&[], &patterns).is_ok());
    h.updater.regex_denies.lock().await.extend(patterns);
    h.updater.rebuild_snapshot().await.unwrap();
    // Oversized sets must preserve unrelated valid denies.
    // An upstream miss is a genuine NXDOMAIN, so inspect the rebuilt engine via a
    // known positive fixture to distinguish filtering from resolution.
    mock.set_fixture(
        "blocked.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 9),
            ttl: 300,
        },
    )
    .await;
    let response = h.query(&blocked.to_string()).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    h.updater
        .regex_denies
        .lock()
        .await
        .extend((0..512).map(|i| format!("^overflow-{i}[a-z]{{1000}}$")));
    assert!(h.updater.rebuild_snapshot().await.is_err());
    let file = h._dir.path().join("regex_deny.txt");
    let before = std::fs::read(&file).unwrap();
    let error = h
        .updater
        .add_regex_rule(r"^new-rule\.example$".into(), ingest::RuleAction::Deny)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&file).unwrap(), before);
    assert!(
        !h.updater
            .regex_denies
            .lock()
            .await
            .contains(r"^new-rule\.example$")
    );
    assert_eq!(
        h.query("blocked.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
}
#[tokio::test]
async fn test_first_query_waits_for_threat_verdict() {
    let mock = DnsMock::start().await.unwrap();
    let threats = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "new-threat.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 10),
            ttl: 300,
        },
    )
    .await;
    threats
        .set_fixture(
            "new-threat.example.",
            RecordType::A,
            Fixture::Delayed {
                delay: Duration::from_millis(80),
                response: Box::new(Fixture::SinkholeA),
            },
        )
        .await;
    threats
        .set_fixture(
            "new-threat.example.",
            RecordType::AAAA,
            Fixture::Nodata {
                rr_ttl: 60,
                minimum: 30,
            },
        )
        .await;
    let h = Harness::start_with_discovery(&mock, Some(&threats), |c| {
        c.auto_block_upstream_sinkholes = true;
        c.discovery_timeout_ms = 200;
    })
    .await;
    assert_eq!(
        h.query("new-threat.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        h.query("new-threat.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
}
#[test]
fn test_invalid_file_schedule_is_rejected() {
    let mut c: Config = toml::from_str(include_str!("../../config/pi-zero.toml")).unwrap();
    c.device_blocking_enabled = true;
    c.device_schedules.push(core_dns::config::DeviceSchedule {
        ip: "127.0.0.1".into(),
        policy: "block".into(),
        days: vec![
            "mon".into(),
            "tue".into(),
            "wed".into(),
            "thu".into(),
            "fri".into(),
            "sat".into(),
            "sun".into(),
        ],
        start_time: "25:00".into(),
        end_time: "26:00".into(),
    });
    assert!(c.validate().is_err());
    assert_eq!(
        core_dns::policy::evaluate_schedule_policy("127.0.0.1", None, &c.device_schedules),
        None
    );
}
#[tokio::test]
async fn test_global_pause_bypasses_device_blocks() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "normal.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 2),
            ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |c| {
        c.device_blocking_enabled = true;
        c.device_policies.insert("127.0.0.1".into(), "block".into());
        c.protection_paused_until = Some(core_dns::config::now_epoch() + 300);
    })
    .await;
    assert_eq!(
        h.query("normal.example.").await.metadata.response_code,
        ResponseCode::NoError
    );
}

async fn conditional_source(domain: &'static str) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0u8; 4096];
            let n = stream.read(&mut bytes).await.unwrap();
            let headers = String::from_utf8_lossy(&bytes[..n]).to_ascii_lowercase();
            let response = if headers.contains("if-none-match:") {
                "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".into()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}\n",
                    domain.len() + 1,
                    domain
                )
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, task)
}

#[tokio::test]
async fn test_category_expiry_restores_cached_rules_before_next_query_without_network() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "expiry.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 8),
            ttl: 300,
        },
    )
    .await;
    let (url, server) = conditional_source("expiry.example").await;
    let h = Harness::start(&mock, |c| {
        c.blocklist_urls.clear();
        c.blocklist_categories = vec![core_dns::config::BlocklistCategory {
            id: "review".into(),
            name: "Review".into(),
            urls: vec![url.clone()],
            enabled: true,
        }];
    })
    .await;
    h.updater.bind_config(h.config.clone()).await.unwrap();
    h.updater.refresh().await.unwrap();
    assert_eq!(
        h.query("expiry.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    h.config
        .update("test:pause", |c| {
            c.pause_for(
                &core_dns::config::PauseScope::Category("review".into()),
                core_dns::config::now_epoch(),
                Some(1),
            );
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        h.query("expiry.example.").await.metadata.response_code,
        ResponseCode::NoError
    );
    server.abort();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        h.query("expiry.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn test_source_reconciliation_uses_latest_committed_configuration() {
    let mock = DnsMock::start().await.unwrap();
    let (url, server) = conditional_source("revision.example").await;
    let h = Harness::start(&mock, |c| {
        c.blocklist_urls.clear();
        c.blocklist_categories = vec![core_dns::config::BlocklistCategory {
            id: "review".into(),
            name: "Review".into(),
            urls: vec![url.clone()],
            enabled: true,
        }];
    })
    .await;
    h.updater.bind_config(h.config.clone()).await.unwrap();
    h.updater.refresh().await.unwrap();
    h.config
        .update("test:pause", |c| {
            c.pause_indefinitely(&core_dns::config::PauseScope::Category("review".into()));
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    let pending = h.updater.clone();
    let first = tokio::spawn(async move {
        pending.ensure_current_sources().await.unwrap();
    });
    h.config
        .update("test:resume", |c| {
            c.category_pauses.clear();
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    h.updater.ensure_current_sources().await.unwrap();
    first.await.unwrap();
    assert_eq!(
        h.query("revision.example.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    server.abort();
}

#[tokio::test]
async fn test_admission_limits_reject_overload_and_release_capacity() {
    for (request_limit, upstream_limit, overload_code) in [
        (2, 8, ResponseCode::Refused),
        (8, 2, ResponseCode::ServFail),
    ] {
        let mock = DnsMock::start().await.unwrap();
        for name in ["first.load.example.", "second.load.example."] {
            mock.set_fixture(
                name,
                RecordType::A,
                Fixture::Delayed {
                    delay: Duration::from_millis(500),
                    response: Box::new(Fixture::PositiveA {
                        address: A::new(192, 0, 2, 1),
                        ttl: 300,
                    }),
                },
            )
            .await;
        }
        mock.set_fixture(
            "third.load.example.",
            RecordType::A,
            Fixture::PositiveA {
                address: A::new(192, 0, 2, 3),
                ttl: 300,
            },
        )
        .await;
        let h = Arc::new(
            Harness::start_with_limits(&mock, None, |_| {}, request_limit, upstream_limit).await,
        );
        let first = h.clone();
        let second = h.clone();
        let first = tokio::spawn(async move { first.query("first.load.example.").await });
        let second = tokio::spawn(async move { second.query("second.load.example.").await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while mock
                .request_count("first.load.example.", RecordType::A)
                .await
                == 0
                || mock
                    .request_count("second.load.example.", RecordType::A)
                    .await
                    == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            h.query("third.load.example.").await.metadata.response_code,
            overload_code
        );
        assert_eq!(
            mock.request_count("third.load.example.", RecordType::A)
                .await,
            0
        );
        let _ = tokio::join!(first, second);
        assert_eq!(
            h.query("third.load.example.").await.metadata.response_code,
            ResponseCode::NoError
        );
    }
}

#[tokio::test]
async fn test_local_address_and_external_alias_obey_malicious_ip_policy() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "target.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 8),
            ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |config| {
        config.local_dns_records = vec![
            LocalDnsRecord {
                name: "address.example".into(),
                record_type: "A".into(),
                value: "192.0.2.8".into(),
            },
            LocalDnsRecord {
                name: "alias.example".into(),
                record_type: "CNAME".into(),
                value: "target.example".into(),
            },
        ];
    })
    .await;
    h.updater
        .add_malicious_ips(vec!["192.0.2.8".parse().unwrap()])
        .await
        .unwrap();
    for name in ["address.example.", "alias.example."] {
        assert_eq!(
            h.query(name).await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    h.config
        .update("test:pause", |config| {
            config.protection_paused_until = Some(core_dns::config::now_epoch() + 300);
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    for name in ["address.example.", "alias.example."] {
        assert_eq!(
            h.query(name).await.metadata.response_code,
            ResponseCode::NoError
        );
    }
}

#[tokio::test]
async fn test_public_looking_local_names_never_reach_upstream_or_discovery() {
    let primary = DnsMock::start().await.unwrap();
    let discovery = DnsMock::start().await.unwrap();
    let h = Harness::start_with_discovery(&primary, Some(&discovery), |c| {
        c.auto_block_upstream_sinkholes = true;
        c.enforce_safesearch = true;
        c.local_dns_records = vec![
            LocalDnsRecord {
                name: "nas.example.com".into(),
                record_type: "A".into(),
                value: "192.168.1.20".into(),
            },
            LocalDnsRecord {
                name: "alias.example.com".into(),
                record_type: "CNAME".into(),
                value: "nas.example.com".into(),
            },
            LocalDnsRecord {
                name: "www.google.com".into(),
                record_type: "A".into(),
                value: "192.168.1.21".into(),
            },
        ];
    })
    .await;
    for name in ["nas.example.com.", "alias.example.com.", "www.google.com."] {
        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::TXT,
        ] {
            let response = h.query_type(name, qtype).await;
            assert_eq!(
                response.response_code,
                ResponseCode::NoError,
                "{name} {qtype:?}"
            );
            for mock in [&primary, &discovery] {
                assert_eq!(mock.request_count(name, qtype).await, 0);
                assert_eq!(mock.request_count(name, RecordType::A).await, 0);
                assert_eq!(mock.request_count(name, RecordType::AAAA).await, 0);
            }
        }
    }
    // Privacy does not bypass local domain policy.
    h.updater
        .add_local_rule("nas.example.com".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    assert_eq!(
        h.query("alias.example.com.").await.response_code,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn test_external_cname_resolution_does_not_disclose_its_local_alias() {
    let primary = DnsMock::start().await.unwrap();
    let discovery = DnsMock::start().await.unwrap();
    primary
        .set_fixture(
            "external.example.com.",
            RecordType::A,
            Fixture::PositiveA {
                address: A::new(192, 0, 2, 10),
                ttl: 300,
            },
        )
        .await;
    discovery
        .set_fixture(
            "external.example.com.",
            RecordType::A,
            Fixture::PositiveA {
                address: A::new(192, 0, 2, 10),
                ttl: 300,
            },
        )
        .await;
    discovery
        .set_fixture(
            "external.example.com.",
            RecordType::AAAA,
            Fixture::Nodata {
                rr_ttl: 300,
                minimum: 300,
            },
        )
        .await;
    let h = Harness::start_with_discovery(&primary, Some(&discovery), |c| {
        c.auto_block_upstream_sinkholes = true;
        c.local_dns_records = vec![LocalDnsRecord {
            name: "private-alias.example.com".into(),
            record_type: "CNAME".into(),
            value: "external.example.com".into(),
        }];
    })
    .await;
    let response = h.query("private-alias.example.com.").await;
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 2);
    for mock in [&primary, &discovery] {
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
            assert_eq!(
                mock.request_count("private-alias.example.com.", qtype)
                    .await,
                0
            );
        }
        assert!(
            mock.request_count("external.example.com.", RecordType::A)
                .await
                > 0
        );
    }
}

#[tokio::test]
async fn test_device_pause_expiry_restores_blocks_and_rechecks_warmed_aliases() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "paused-alias.example.",
        RecordType::A,
        Fixture::CnameThenA {
            canonical: Name::from_ascii("denied-target.example.").unwrap(),
            cname_ttl: 300,
            address: A::new(192, 0, 2, 10),
            address_ttl: 300,
        },
    )
    .await;
    mock.set_fixture(
        "www.google.com.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 20),
            ttl: 300,
        },
    )
    .await;
    let h = Harness::start(&mock, |config| {
        config.device_blocking_enabled = true;
        config.enforce_safesearch = true;
        config
            .device_policies
            .insert("127.0.0.1".into(), "block".into());
    })
    .await;
    h.updater
        .add_local_rule("denied-target.example".into(), ingest::RuleAction::Deny)
        .await
        .unwrap();
    h.updater.rebuild_snapshot().await.unwrap();
    assert_eq!(
        h.query("paused-alias.example.").await.response_code,
        ResponseCode::Refused
    );
    h.config
        .update("test:device-pause", |config| {
            config.pause_for(
                &core_dns::config::PauseScope::Device("127.0.0.1".into()),
                core_dns::config::now_epoch(),
                Some(300),
            );
            Ok::<(), String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        h.query("paused-alias.example.").await.response_code,
        ResponseCode::NoError
    );
    let google = h.query("www.google.com.").await;
    assert_eq!(google.response_code, ResponseCode::NoError);
    assert_eq!(google.answers[0].record_type(), RecordType::A);
    h.config
        .update("test:expire-pause", |config| {
            config
                .device_pauses
                .insert("127.0.0.1".into(), core_dns::config::now_epoch() - 1);
            Ok::<(), String>(())
        })
        .await
        .unwrap();
    // No sweeper or cache invalidation: the next query restores the block.
    assert_eq!(
        h.query("paused-alias.example.").await.response_code,
        ResponseCode::Refused
    );
    h.config
        .update("test:remove-static-block", |config| {
            config.device_policies.clear();
            Ok::<(), String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        h.query("paused-alias.example.").await.response_code,
        ResponseCode::NXDomain
    );
    let google = h.query("www.google.com.").await;
    assert_eq!(google.answers[0].record_type(), RecordType::CNAME);
}
