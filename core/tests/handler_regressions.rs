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
    let mut nameserver = NameServerConfig::udp(mock.udp_addr().ip());
    nameserver.connections[0].port = mock.udp_addr().port();
    let resolver_config = ResolverConfig::from_parts(None, vec![], vec![nameserver]);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(200);
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
        let resolver = test_resolver(mock);
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
        );
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

#[tokio::test]
async fn malicious_ip_changes_apply_to_cached_answers_and_pause_bypasses_detection() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "cached.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 1),
            ttl: 300,
        },
    )
    .await;
    let harness = Harness::start(&mock, |_| {}).await;
    assert_eq!(
        harness
            .query("cached.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    harness
        .updater
        .add_malicious_ips(vec!["192.0.2.1".parse().unwrap()])
        .await
        .unwrap();
    assert_eq!(
        harness
            .query("cached.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    harness
        .config
        .update("test", |config| {
            config.protection_paused_until = Some(core_dns::config::now_epoch() + 300);
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        harness
            .query("cached.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn device_whitelist_bypasses_malicious_ip_blocking() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "whitelist.example.",
        RecordType::A,
        Fixture::PositiveA {
            address: A::new(192, 0, 2, 1),
            ttl: 300,
        },
    )
    .await;
    let harness = Harness::start(&mock, |config| {
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("127.0.0.1".into(), "whitelist".into());
    })
    .await;
    harness
        .updater
        .add_malicious_ips(vec!["192.0.2.1".parse().unwrap()])
        .await
        .unwrap();
    assert_eq!(
        harness
            .query("whitelist.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert!(harness.updater.auto_denies.lock().await.is_empty());
}

#[tokio::test]
async fn local_cname_preserves_negative_status_and_authority() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "missing.example.",
        RecordType::A,
        Fixture::NxDomain {
            rr_ttl: 60,
            minimum: 30,
        },
    )
    .await;
    let harness = Harness::start(&mock, |config| {
        config.local_dns_records.push(LocalDnsRecord {
            name: "alias.example".into(),
            record_type: "CNAME".into(),
            value: "missing.example".into(),
        });
    })
    .await;
    let response = harness.query("alias.example.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        response
            .authorities
            .iter()
            .any(|r| r.record_type() == RecordType::SOA)
    );
}

#[tokio::test]
async fn local_cname_failure_is_servfail() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture("failed.example.", RecordType::A, Fixture::Servfail)
        .await;
    let harness = Harness::start(&mock, |config| {
        config.local_dns_records.push(LocalDnsRecord {
            name: "alias.example".into(),
            record_type: "CNAME".into(),
            value: "failed.example".into(),
        });
    })
    .await;
    assert_eq!(
        harness.query("alias.example.").await.metadata.response_code,
        ResponseCode::ServFail
    );
}

#[tokio::test]
async fn unavailable_discovery_fails_closed_within_its_budget() {
    let primary = DnsMock::start().await.unwrap();
    let discovery = DnsMock::start().await.unwrap();
    primary
        .set_fixture(
            "fast.example.",
            RecordType::A,
            Fixture::PositiveA {
                address: A::new(192, 0, 2, 1),
                ttl: 30,
            },
        )
        .await;
    for query_type in [RecordType::A, RecordType::AAAA] {
        discovery
            .set_fixture(
                "fast.example.",
                query_type,
                Fixture::Delayed {
                    delay: Duration::from_millis(500),
                    response: Box::new(Fixture::SinkholeA),
                },
            )
            .await;
    }
    let harness = Harness::start_with_discovery(&primary, Some(&discovery), |config| {
        config.auto_block_upstream_sinkholes = true;
        config.discovery_timeout_ms = 250;
    })
    .await;
    let response = tokio::time::timeout(Duration::from_millis(600), harness.query("fast.example."))
        .await
        .expect("discovery must respect its budget");
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(response.answers.is_empty());
    assert_eq!(
        primary.request_count("fast.example.", RecordType::A).await,
        0
    );
    assert!(harness.updater.auto_denies.lock().await.is_empty());
}

#[tokio::test]
async fn oversized_udp_response_is_truncated_after_borrowed_size_probe() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "large.example.",
        RecordType::TXT,
        Fixture::PositiveTxt {
            text: vec!["x".repeat(255); 3],
            ttl: 300,
        },
    )
    .await;
    let harness = Harness::start(&mock, |_| {}).await;
    let response = harness.query_type("large.example.", RecordType::TXT).await;
    assert!(
        response.metadata.truncation,
        "unexpected response: {response:?}"
    );
    assert!(response.answers.is_empty());
}

#[tokio::test]
async fn discovery_verdict_blocks_answers_cached_by_whitelisted_clients() {
    let primary = DnsMock::start().await.unwrap();
    let discovery = DnsMock::start().await.unwrap();
    primary
        .set_fixture(
            "cache-bypass.example.",
            RecordType::A,
            Fixture::PositiveA {
                address: A::new(192, 0, 2, 55),
                ttl: 300,
            },
        )
        .await;
    discovery
        .set_fixture("cache-bypass.example.", RecordType::A, Fixture::SinkholeA)
        .await;
    discovery
        .set_fixture(
            "cache-bypass.example.",
            RecordType::AAAA,
            Fixture::SinkholeA,
        )
        .await;
    let harness = Harness::start_with_discovery(&primary, Some(&discovery), |config| {
        config.auto_block_upstream_sinkholes = true;
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("127.0.0.1".into(), "whitelist".into());
    })
    .await;
    assert_eq!(
        harness
            .query("cache-bypass.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while discovery
            .request_count("cache-bypass.example.", RecordType::A)
            .await
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Let the local discovery response be consumed; no public network is used.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        harness
            .query("cache-bypass.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert!(harness.updater.auto_denies.lock().await.is_empty());
    harness
        .config
        .update("test", |config| {
            config.device_policies.clear();
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        harness
            .query("cache-bypass.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        primary
            .request_count("cache-bypass.example.", RecordType::A)
            .await,
        1
    );
}

#[tokio::test]
async fn primary_sinkhole_cached_by_whitelisted_client_is_rechecked_without_discovery_pool() {
    let primary = DnsMock::start().await.unwrap();
    primary
        .set_fixture(
            "primary-sinkhole.example.",
            RecordType::A,
            Fixture::SinkholeA,
        )
        .await;
    let harness = Harness::start(&primary, |config| {
        config.auto_block_upstream_sinkholes = true;
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("127.0.0.1".into(), "whitelist".into());
    })
    .await;
    assert_eq!(
        harness
            .query("primary-sinkhole.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    harness
        .config
        .update("test", |config| {
            config.device_policies.clear();
            Ok::<_, String>(())
        })
        .await
        .unwrap();
    assert_eq!(
        harness
            .query("primary-sinkhole.example.")
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn concurrent_misses_share_one_fetch_and_then_use_cache() {
    let mock = DnsMock::start().await.unwrap();
    mock.set_fixture(
        "burst.example.",
        RecordType::A,
        Fixture::Delayed {
            delay: Duration::from_millis(50),
            response: Box::new(Fixture::PositiveA {
                address: A::new(192, 0, 2, 1),
                ttl: 300,
            }),
        },
    )
    .await;
    let harness = Arc::new(Harness::start(&mock, |_| {}).await);
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let harness = harness.clone();
        tasks.push(tokio::spawn(async move {
            harness.query("burst.example.").await
        }));
    }
    for task in tasks {
        let response = task.await.unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(mock.request_count("burst.example.", RecordType::A).await, 1);
    assert_eq!(harness.query("burst.example.").await.answers.len(), 1);
    assert_eq!(mock.request_count("burst.example.", RecordType::A).await, 1);
}
