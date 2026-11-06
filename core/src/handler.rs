use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry as DashEntry;
use futures_util::StreamExt;
use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::{DnsError, NetError};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::cache::l1::L1Cache;
use crate::cache::l2::L2Cache;
use crate::cache::{CacheKey, CachedResponse, authoritative_negative_ttl};
use crate::ratelimit::window::RateLimiterSet;
use crate::updater::BlocklistUpdater;
use filter::{FilterEngine, FilterVerdict};

use crate::policy::{DomainPolicy, domain_policy};
use crate::recursor::RecursiveResolver;
use crate::response::error_response;

pub static RATE_LIMIT_CONFIG: OnceLock<RateLimitConfig> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub limit_per_window: u32,
    pub max_entries: usize,
    pub window_duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{DNSClass, Name};

    fn test_key() -> CacheKey {
        CacheKey {
            name: Name::root(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
        }
    }

    #[tokio::test]
    async fn late_follower_observes_stored_result() {
        let map = Arc::new(InFlightMap::new());
        let key = test_key();
        let (sender, _initial_receiver) = tokio::sync::watch::channel(None);
        let sender = Arc::new(sender);
        map.insert(key.clone(), sender.clone());

        let mut follower = match map.entry(key) {
            DashEntry::Occupied(entry) => entry.get().subscribe(),
            DashEntry::Vacant(_) => panic!("expected an in-flight entry"),
        };
        sender.send_replace(Some(Err("upstream failed".to_string())));

        let observed = follower.borrow_and_update().clone();
        assert!(matches!(observed, Some(Err(message)) if message == "upstream failed"));
    }

    #[tokio::test]
    async fn coalesced_followers_share_payload_and_publish_once() {
        let resolved = Arc::new(ResolvedUpstream {
            answer: Arc::new(CachedResponse::new(
                ResponseCode::NoError,
                vec![],
                vec![],
                vec![],
                60,
            )),
            resolver_label: "test".into(),
            discovery: DiscoveryVerdict::Clean,
            cache_published: tokio::sync::OnceCell::new(),
        });
        let (sender, _) = tokio::sync::watch::channel(None);
        sender.send_replace(Some(Ok(resolved.clone())));
        let publications = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let receiver = sender.subscribe();
            let observed: UpstreamResult = receiver.borrow().clone().unwrap();
            let observed = observed.unwrap();
            assert!(Arc::ptr_eq(&observed.answer, &resolved.answer));
            let publications = publications.clone();
            tasks.push(tokio::spawn(async move {
                observed
                    .cache_published
                    .get_or_init(|| async {
                        tokio::task::yield_now().await;
                        publications.fetch_add(1, Ordering::Relaxed);
                    })
                    .await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(publications.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn leader_cleanup_removes_only_its_entry() {
        let map = Arc::new(InFlightMap::new());
        let key = test_key();
        let (sender, _receiver) = tokio::sync::watch::channel(None);
        let sender = Arc::new(sender);
        map.insert(key.clone(), sender.clone());

        drop(InFlightLeader {
            map: map.clone(),
            key,
            sender,
        });

        assert!(map.is_empty());
    }

    #[test]
    fn sinkhole_detection_matches_only_unspecified_addresses() {
        let name = Name::root();
        let v4_sinkhole = Record::from_rdata(
            name.clone(),
            60,
            hickory_proto::rr::RData::A(std::net::Ipv4Addr::UNSPECIFIED.into()),
        );
        let v4_clean = Record::from_rdata(
            name.clone(),
            60,
            hickory_proto::rr::RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1).into()),
        );
        let v6_sinkhole = Record::from_rdata(
            name,
            60,
            hickory_proto::rr::RData::AAAA(std::net::Ipv6Addr::UNSPECIFIED.into()),
        );
        assert!(is_sinkhole_record(&v4_sinkhole));
        assert!(!is_sinkhole_record(&v4_clean));
        assert!(is_sinkhole_record(&v6_sinkhole));
    }

    #[test]
    fn test_auto_blockable_rejects_private_and_single_label_names() {
        use std::str::FromStr;
        let blockable = |s: &str| is_auto_blockable(&Name::from_str(s).unwrap());

        assert!(blockable("malware.example.com."));
        assert!(blockable("EVIL.Example.NET."));

        assert!(!blockable("nas."));
        assert!(!blockable("nas.lan."));
        assert!(!blockable("printer.HOME."));
        assert!(!blockable("tv.local."));
        assert!(!blockable("svc.corp.internal."));
        assert!(!blockable("router.localdomain."));
        assert!(!blockable("nas.home.arpa."));
        assert!(!blockable("."));
    }
}

// Share per-IP limits across runtime threads: Tokio work-stealing gives
// successive requests no stable thread affinity. Never await under this lock.
static RATE_LIMITER: OnceLock<RateLimiterSet> = OnceLock::new();
static RATE_LIMIT_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static LAST_RATE_LIMIT_WARNING_MS: AtomicU64 = AtomicU64::new(0);

fn rate_limiter() -> &'static RateLimiterSet {
    RATE_LIMITER.get_or_init(|| {
        let config = RATE_LIMIT_CONFIG.get().cloned().unwrap_or(RateLimitConfig {
            limit_per_window: 1000,
            max_entries: 100000,
            window_duration: Duration::from_secs(1),
        });
        RateLimiterSet::new(
            config.limit_per_window,
            config.max_entries,
            config.window_duration,
            Instant::now(),
        )
    })
}

fn record_rate_limit_rejection(client_ip: std::net::IpAddr) {
    RATE_LIMIT_REJECTIONS.fetch_add(1, Ordering::Relaxed);
    debug!("Rate limit rejected client packet from {}", client_ip);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let last = LAST_RATE_LIMIT_WARNING_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 60_000
        || LAST_RATE_LIMIT_WARNING_MS
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    let rejected = RATE_LIMIT_REJECTIONS.swap(0, Ordering::Relaxed);
    if rejected > 0 {
        warn!(
            "Rate limiter rejected {} requests in the last minute",
            rejected
        );
    }
}

/// Keeps response codes explicitly: Hickory Lookup constructors force NoError,
/// while upstream NXDOMAIN arrives as an error carrying a valid negative answer.
#[derive(Clone)]
struct UpstreamAnswer {
    response_code: ResponseCode,
    authenticated_data: bool,
    negative_ttl: Option<u32>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscoveryVerdict {
    Sinkhole,
    Clean,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscoveryObservation {
    Sinkhole,
    Clean,
    NxDomain,
    Unavailable,
    NotConfigured,
}

struct ResolvedUpstream {
    answer: Arc<CachedResponse>,
    cache_published: tokio::sync::OnceCell<()>,
    resolver_label: String,
    discovery: DiscoveryVerdict,
}

/// Shares a resolution result and resolver label among coalesced requests.
/// String errors avoid requiring the upstream error type to implement Clone.
type UpstreamResult = Result<Arc<ResolvedUpstream>, String>;
type PrimaryResult = Result<(UpstreamAnswer, String), String>;

type InFlightSender = tokio::sync::watch::Sender<Option<UpstreamResult>>;
type InFlightMap = DashMap<CacheKey, Arc<InFlightSender>>;

/// Removes a leader's entry even when its task is cancelled while resolving.
struct InFlightLeader {
    map: Arc<InFlightMap>,
    key: CacheKey,
    sender: Arc<InFlightSender>,
}

impl Drop for InFlightLeader {
    fn drop(&mut self) {
        self.map
            .remove_if(&self.key, |_, sender| Arc::ptr_eq(sender, &self.sender));
    }
}

type DiscoveryMap =
    DashMap<hickory_proto::rr::Name, Arc<tokio::sync::watch::Sender<Option<DiscoveryObservation>>>>;

struct DiscoveryTask {
    map: Arc<DiscoveryMap>,
    name: hickory_proto::rr::Name,
}

impl Drop for DiscoveryTask {
    fn drop(&mut self) {
        self.map.remove(&self.name);
    }
}

/// Caps how many fire-and-forget background tasks (smart-IP-blocking
/// lookups, auto-deny writes) can be in flight at once. These are spawned
/// straight off the query path with no backpressure of their own -- a flood
/// of queries hitting already-blocked domains (a scan, a misbehaving
/// device, or just heavy legitimate blocklist traffic) would otherwise spawn
/// one upstream lookup or updater write per query, unboundedly. Losing an
/// occasional enrichment attempt under load is fine; leaking an unbounded
/// number of tasks and upstream connections is not.
const MAX_CONCURRENT_BACKGROUND_TASKS: usize = 64;
const MAX_CONCURRENT_REQUESTS: usize = 1024;
const MAX_CONCURRENT_UPSTREAMS: usize = 128;

/// Bounds how many local CNAME records are followed for one query, so a
/// misconfigured local CNAME loop can't spin forever.
const MAX_LOCAL_CNAME_HOPS: usize = 8;

#[derive(Clone)]
pub struct DnsHandler {
    resolver: TokioResolver,
    recursive_resolver: Option<Arc<RecursiveResolver>>,
    discovery_resolver: Option<TokioResolver>,
    l1_cache: Arc<L1Cache>,
    l2_cache: L2Cache,
    _filter_engine: Arc<FilterEngine>,
    updater: Arc<BlocklistUpdater>,
    config: Arc<crate::config::ConfigHandle>,
    logger: Option<Arc<logger::QueryLogger>>,
    network_tracker: Arc<crate::network::NetworkTracker>,
    doh_client: Arc<arc_swap::ArcSwapOption<crate::doh::DohClient>>,
    // Coalesces concurrent identical cache misses: requests for the same
    // CacheKey that arrive while an upstream fetch for that key is already
    // in flight wait on the same result via a watch channel instead of each
    // firing their own redundant upstream/DoH/iterative-resolution query.
    in_flight: Arc<InFlightMap>,
    // Bounds concurrent fire-and-forget background tasks; see
    // MAX_CONCURRENT_BACKGROUND_TASKS.
    background_task_limiter: Arc<tokio::sync::Semaphore>,
    request_slots: Arc<tokio::sync::Semaphore>,
    upstream_slots: Arc<tokio::sync::Semaphore>,
    discovery_cache: moka::sync::Cache<hickory_proto::rr::Name, (DiscoveryObservation, Instant)>,
    discovery_in_flight: Arc<DiscoveryMap>,
    discovery_slots: Arc<tokio::sync::Semaphore>,
}

impl DnsHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolver: TokioResolver,
        recursive_resolver: Option<Arc<RecursiveResolver>>,
        discovery_resolver: Option<TokioResolver>,
        l1_cache: Arc<L1Cache>,
        l2_cache: L2Cache,
        filter_engine: Arc<FilterEngine>,
        updater: Arc<BlocklistUpdater>,
        config: Arc<crate::config::ConfigHandle>,
        logger: Option<Arc<logger::QueryLogger>>,
        network_tracker: Arc<crate::network::NetworkTracker>,
        doh_client: Arc<arc_swap::ArcSwapOption<crate::doh::DohClient>>,
    ) -> Self {
        Self {
            resolver,
            recursive_resolver,
            discovery_resolver,
            l1_cache,
            l2_cache,
            _filter_engine: filter_engine,
            updater,
            config,
            logger,
            network_tracker,
            doh_client,
            in_flight: Arc::new(DashMap::new()),
            request_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            upstream_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_UPSTREAMS)),
            discovery_cache: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(300))
                .build(),
            discovery_in_flight: Arc::new(DashMap::new()),
            discovery_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            background_task_limiter: Arc::new(tokio::sync::Semaphore::new(
                MAX_CONCURRENT_BACKGROUND_TASKS,
            )),
        }
    }

    /// Set admission budgets when embedding the server. Rejections are
    /// immediate, so a slow upstream cannot create an unbounded wait queue.
    pub fn with_query_limits(mut self, requests: usize, upstreams: usize) -> Self {
        self.request_slots = Arc::new(tokio::sync::Semaphore::new(requests.max(1)));
        self.upstream_slots = Arc::new(tokio::sync::Semaphore::new(upstreams.max(1)));
        self
    }

    fn discovery_observation(
        &self,
        name: &hickory_proto::rr::Name,
    ) -> Option<DiscoveryObservation> {
        self.discovery_cache
            .get(name)
            .and_then(|(observation, expires)| (expires > Instant::now()).then_some(observation))
    }

    fn start_discovery(
        &self,
        name: &hickory_proto::rr::Name,
        enabled: bool,
        timeout: Duration,
    ) -> Option<tokio::sync::watch::Receiver<Option<DiscoveryObservation>>> {
        if !enabled || self.discovery_resolver.is_none() || !is_auto_blockable(name) {
            return None;
        }
        let (permit, sender, receiver) = match self.discovery_in_flight.entry(name.clone()) {
            DashEntry::Occupied(entry) => return Some(entry.get().subscribe()),
            DashEntry::Vacant(entry) => {
                let permit = self.discovery_slots.clone().try_acquire_owned().ok()?;
                let (sender, receiver) = tokio::sync::watch::channel(None);
                let sender = Arc::new(sender);
                entry.insert(sender.clone());
                (permit, sender, receiver)
            }
        };
        let handler = self.clone();
        let name = name.clone();
        let cleanup = DiscoveryTask {
            map: self.discovery_in_flight.clone(),
            name: name.clone(),
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _cleanup = cleanup;
            let observation = tokio::time::timeout(timeout, handler.resolve_discovery(&name, true))
                .await
                .unwrap_or(DiscoveryObservation::Unavailable);
            let ttl = if observation == DiscoveryObservation::Unavailable {
                5
            } else {
                300
            };
            handler.discovery_cache.insert(
                name,
                (observation, Instant::now() + Duration::from_secs(ttl)),
            );
            sender.send_replace(Some(observation));
        });
        Some(receiver)
    }

    async fn checked_discovery(
        &self,
        name: &hickory_proto::rr::Name,
        config: &crate::config::Config,
        local_dns: &crate::local_dns::LocalDnsIndex,
    ) -> Result<(), ResponseCode> {
        if local_dns.lookup(&name.clone().into()).is_some()
            || !config.auto_block_upstream_sinkholes
            || self.discovery_resolver.is_none()
            || !is_auto_blockable(name)
        {
            return Ok(());
        }
        let timeout = Duration::from_millis(config.discovery_timeout_ms);
        let observation = if let Some(observation) = self.discovery_observation(name) {
            observation
        } else {
            let Some(mut receiver) = self.start_discovery(name, true, timeout) else {
                return Err(ResponseCode::ServFail);
            };
            tokio::time::timeout(timeout, async {
                loop {
                    if let Some(observation) = *receiver.borrow_and_update() {
                        break observation;
                    }
                    if receiver.changed().await.is_err() {
                        break DiscoveryObservation::Unavailable;
                    }
                }
            })
            .await
            .unwrap_or(DiscoveryObservation::Unavailable)
        };
        match observation {
            DiscoveryObservation::Sinkhole => {
                self.persist_auto_deny(name);
                Err(ResponseCode::NXDomain)
            }
            DiscoveryObservation::Unavailable => Err(ResponseCode::ServFail),
            _ => Ok(()),
        }
    }

    fn persist_auto_deny(&self, name: &hickory_proto::rr::Name) {
        if !is_auto_blockable(name) {
            return;
        }
        let Ok(permit) = self.background_task_limiter.clone().try_acquire_owned() else {
            return;
        };
        let clean_name = name.to_string().trim_end_matches('.').to_ascii_lowercase();
        let updater = self.updater.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match updater.add_auto_deny(clean_name).await {
                Ok(true) => updater.request_rebuild(),
                Ok(false) => {}
                Err(error) => error!("Failed to persist auto-deny: {}", error),
            }
        });
    }

    /// Defers name formatting and borrows resolver labels so disabled logging allocates nothing.
    #[allow(clippy::too_many_arguments)]
    fn log_query<N: FnOnce() -> String>(
        &self,
        client_ip: std::net::IpAddr,
        name: N,
        qtype: RecordType,
        response_code: ResponseCode,
        duration_ns: u64,
        verdict: FilterVerdict,
        resolver: std::borrow::Cow<'static, str>,
    ) {
        if let Some(ref logger) = self.logger {
            logger.log(
                client_ip,
                name(),
                qtype,
                response_code,
                duration_ns,
                verdict,
                resolver,
            );
        }
    }

    fn response_metadata(
        request: &Request,
        response_code: ResponseCode,
        authenticated_data: bool,
    ) -> Metadata {
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.response_code = response_code;
        metadata.recursion_available = true;
        metadata.authoritative = false;
        metadata.authentic_data = authenticated_data;
        metadata
    }

    async fn send_dns_response<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
        metadata: Metadata,
        answers: &[Record],
        authorities: &[Record],
        additionals: &[Record],
    ) -> ResponseInfo {
        let mut response_edns = request.edns.clone();
        if request.protocol().is_datagram()
            && let Some(edns) = response_edns.as_mut()
        {
            edns.set_version(0);
            edns.set_max_payload(edns.max_payload().clamp(512, 1232));
        }
        // Hickory's response encoder enforces the advertised payload and sets
        // TC itself. Avoid encoding the entire response twice per UDP query.
        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = response_edns.as_ref() {
            builder.edns(edns);
        }
        let response = builder.build(metadata, answers, authorities, &[], additionals);

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(error) => {
                error!("Failed to send DNS response: {:?}", error);
                error_response(request, ResponseCode::ServFail)
            }
        }
    }

    async fn send_cached_response<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        cached: &CachedResponse,
        sections: Arc<crate::cache::ResponseSections>,
    ) -> ResponseInfo {
        let (answers, authorities, additionals) = sections.as_ref();
        let metadata =
            Self::response_metadata(request, cached.response_code, cached.authenticated_data);
        self.send_dns_response(
            request,
            response_handle,
            metadata,
            answers,
            authorities,
            additionals,
        )
        .await
    }

    /// Performs the actual upstream resolution (iterative root resolution,
    /// then DoH, then the plain configured resolver as a final fallback).
    /// Only ever called by the "leader" of a coalesced group of identical
    /// concurrent cache misses -- see the call site in `handle_request`.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_upstream(
        &self,
        request: &Request,
        name: &hickory_proto::rr::LowerName,
        query_type: RecordType,
        recursive_resolver_enabled: bool,
        encrypted_upstream_enabled: bool,
        encrypted_upstream_allow_plaintext_fallback: bool,
    ) -> PrimaryResult {
        let _permit = self
            .upstream_slots
            .try_acquire()
            .map_err(|_| "upstream capacity exhausted".to_string())?;
        let name_owned = hickory_proto::rr::Name::from(name.clone());
        let dnssec_validation = self.config.load().dnssec_validation;
        let mut iterative_resolved_msg = None;
        if recursive_resolver_enabled {
            let Some(recursive_resolver) = &self.recursive_resolver else {
                return Err("Recursive mode has no live resolver".into());
            };
            match recursive_resolver
                .resolve(
                    &name_owned,
                    query_type,
                    request
                        .edns
                        .as_ref()
                        .is_some_and(|edns| edns.flags().dnssec_ok),
                )
                .await
            {
                Ok(msg) => {
                    iterative_resolved_msg = Some(msg);
                }
                Err(e) if dnssec_validation => {
                    return Err(format!("Recursive DNSSEC resolution failed: {e}"));
                }
                Err(e) => {
                    warn!(
                        "Iterative root-based resolution failed for {}: {:?}. Falling back to standard resolver.",
                        name, e
                    );
                }
            }
        }

        let mut doh_resolved_msg = None;
        let mut doh_resolved_url = None;
        if iterative_resolved_msg.is_none() && encrypted_upstream_enabled {
            let Some(doh) = self.doh_client.load_full() else {
                return Err("DoH is enabled but no live client is configured".to_string());
            };
            let id = request.metadata.id;
            let op_code = request.metadata.op_code;
            let mut msg =
                hickory_proto::op::Message::new(id, hickory_proto::op::MessageType::Query, op_code);

            msg.metadata.recursion_desired = request.metadata.recursion_desired;
            msg.edns = request.edns.clone();
            msg.add_query(hickory_proto::op::Query::query(
                name_owned.clone(),
                query_type,
            ));

            let result = if dnssec_validation {
                doh.query_validated(msg).await.map_err(
                    |error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) },
                )
            } else {
                let wire = msg
                    .to_vec()
                    .map_err(|error| format!("Cannot encode DoH query: {error}"))?;
                doh.query(&wire).await
            };
            match result {
                Ok(res) => {
                    doh_resolved_msg = Some(res);
                    doh_resolved_url = Some(doh.url().to_string());
                }
                Err(e) if dnssec_validation || !encrypted_upstream_allow_plaintext_fallback => {
                    return Err(format!("DoH resolution failed: {e}"));
                }
                Err(e) => {
                    warn!("DoH resolution failed: {e:?}. Falling back to standard resolver.");
                }
            }
        }

        if let Some(msg) = iterative_resolved_msg {
            let answer = UpstreamAnswer {
                response_code: msg.metadata.response_code,
                authenticated_data: msg.metadata.authentic_data,
                negative_ttl: authoritative_negative_ttl(&msg.authorities),
                answers: msg.answers.clone(),
                authorities: msg.authorities.clone(),
                additionals: msg.additionals.clone(),
            };
            return Ok((answer, "Recursive (Root Servers)".to_string()));
        }
        if let Some(msg) = doh_resolved_msg {
            let answer = UpstreamAnswer {
                response_code: msg.metadata.response_code,
                authenticated_data: dnssec_validation && msg.metadata.authentic_data,
                negative_ttl: authoritative_negative_ttl(&msg.authorities),
                answers: msg.answers.clone(),
                authorities: msg.authorities.clone(),
                additionals: msg.additionals.clone(),
            };
            return Ok((
                answer,
                format!("DoH ({})", doh_resolved_url.unwrap_or_default()),
            ));
        }

        match self.resolver.lookup(name.clone(), query_type).await {
            Ok(lookup) => Ok((
                UpstreamAnswer {
                    response_code: lookup.message().response_code,
                    authenticated_data: dnssec_validation
                        && lookup.message().metadata.authentic_data,
                    negative_ttl: authoritative_negative_ttl(lookup.authorities()),
                    answers: lookup.answers().to_vec(),
                    authorities: lookup.authorities().to_vec(),
                    additionals: lookup.additionals().to_vec(),
                },
                "Standard Upstreams".to_string(),
            )),
            // Hickory represents NXDOMAIN and NODATA as errors. Preserve their rcode
            // and SOA for negative caching; only resolution failures become SERVFAIL.
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => Ok((
                UpstreamAnswer {
                    response_code: no_records.response_code,
                    authenticated_data: false,
                    negative_ttl: no_records.negative_ttl,
                    answers: Vec::new(),
                    authorities: no_records
                        .authorities
                        .map(|a| a.to_vec())
                        .unwrap_or_default(),
                    additionals: Vec::new(),
                },
                "Standard Upstreams".to_string(),
            )),
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    async fn reject_content<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        key: &CacheKey,
        started: Instant,
        reason: &'static str,
    ) -> ResponseInfo {
        self.log_query(
            request.src().ip(),
            || key.name.to_string(),
            key.qtype,
            ResponseCode::NXDomain,
            started.elapsed().as_nanos() as u64,
            FilterVerdict::Block,
            reason.into(),
        );
        self.send_dns_response(
            request,
            response_handle,
            Self::response_metadata(request, ResponseCode::NXDomain, false),
            &[],
            &[],
            &[],
        )
        .await
    }

    fn answer_blocked(
        &self,
        config: &crate::config::Config,
        answers: &[Record],
        bypass: bool,
        now: i64,
    ) -> bool {
        if bypass {
            return false;
        }
        answers.iter().any(|record| {
            domain_policy(config, &self.updater, &record.name, now, false).blocked()
                || matches!(&record.data, hickory_proto::rr::RData::CNAME(target)
                    if domain_policy(config, &self.updater, &target.0, now, false).blocked())
        }) || (config.smart_ip_blocking && self.has_malicious_address(answers))
            || (config.auto_block_upstream_sinkholes
                && self.discovery_resolver.is_none()
                && answers.iter().any(is_sinkhole_record))
    }

    async fn inspect_answer(
        &self,
        config: &crate::config::Config,
        answers: &[Record],
        bypass: bool,
        now: i64,
        local_dns: &crate::local_dns::LocalDnsIndex,
    ) -> Result<(), ResponseCode> {
        if self.answer_blocked(config, answers, bypass, now) {
            let infrastructure_block = (config.smart_ip_blocking
                && self.has_malicious_address(answers))
                || (config.auto_block_upstream_sinkholes
                    && self.discovery_resolver.is_none()
                    && answers.iter().any(is_sinkhole_record));
            if infrastructure_block && let Some(first) = answers.first() {
                self.persist_auto_deny(&first.name);
            }
            return Err(ResponseCode::NXDomain);
        }
        if bypass {
            return Ok(());
        }
        let mut seen = std::collections::HashSet::new();
        for record in answers {
            if let hickory_proto::rr::RData::CNAME(target) = &record.data
                && seen.insert(&target.0)
            {
                if seen.len() > MAX_LOCAL_CNAME_HOPS {
                    return Err(ResponseCode::ServFail);
                }
                self.checked_discovery(&target.0, config, local_dns).await?;
            }
        }
        Ok(())
    }

    async fn policy_error<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
        key: &CacheKey,
        started: Instant,
        code: ResponseCode,
        reason: &'static str,
    ) -> ResponseInfo {
        if code == ResponseCode::NXDomain {
            return self
                .reject_content(request, response_handle, key, started, reason)
                .await;
        }
        self.log_query(
            request.src().ip(),
            || key.name.to_string(),
            key.qtype,
            code,
            started.elapsed().as_nanos() as u64,
            FilterVerdict::Pass,
            reason.into(),
        );
        self.send_dns_response(
            request,
            response_handle,
            Self::response_metadata(request, code, false),
            &[],
            &[],
            &[],
        )
        .await
    }

    fn has_malicious_address(&self, answers: &[Record]) -> bool {
        let ips = self.updater.malicious_ips_snapshot();
        answers.iter().any(|record| match &record.data {
            hickory_proto::rr::RData::A(address) => ips.contains(&std::net::IpAddr::V4(address.0)),
            hickory_proto::rr::RData::AAAA(address) => {
                ips.contains(&std::net::IpAddr::V6(address.0))
            }
            _ => false,
        })
    }

    async fn resolve_discovery(
        &self,
        name: &hickory_proto::rr::Name,
        enabled: bool,
    ) -> DiscoveryObservation {
        let Some(resolver) = self.discovery_resolver.as_ref() else {
            return if enabled {
                DiscoveryObservation::NotConfigured
            } else {
                DiscoveryObservation::Unavailable
            };
        };
        if !enabled {
            return DiscoveryObservation::Unavailable;
        }

        let mut lookups = futures_util::stream::iter([RecordType::A, RecordType::AAAA])
            .map(|kind| resolver.lookup(name.clone(), kind))
            .buffer_unordered(2);
        let mut saw_nxdomain = true;
        let mut saw_unavailable = false;
        while let Some(result) = lookups.next().await {
            match result {
                Ok(lookup) => {
                    saw_nxdomain = false;
                    if lookup.answers().iter().any(is_sinkhole_record) {
                        return DiscoveryObservation::Sinkhole;
                    }
                }
                Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
                    if no_records.response_code != ResponseCode::NXDomain {
                        saw_nxdomain = false;
                    }
                }
                Err(_) => saw_unavailable = true,
            }
        }
        if saw_unavailable {
            DiscoveryObservation::Unavailable
        } else if saw_nxdomain {
            DiscoveryObservation::NxDomain
        } else {
            DiscoveryObservation::Clean
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_with_discovery(
        &self,
        request: &Request,
        name: &hickory_proto::rr::LowerName,
        query_type: RecordType,
        recursive_resolver_enabled: bool,
        encrypted_upstream_enabled: bool,
        encrypted_upstream_allow_plaintext_fallback: bool,
        discovery_enabled: bool,
        discovery_timeout: Duration,
        negative_ttl_fallback: u32,
    ) -> UpstreamResult {
        let name_owned = hickory_proto::rr::Name::from(name.clone());
        let _ = self.start_discovery(&name_owned, discovery_enabled, discovery_timeout);
        // Discovery enriches future requests; a stalled threat resolver must
        // never hold a successful primary answer until its timeout.
        let (answer, resolver_label) = self
            .resolve_upstream(
                request,
                name,
                query_type,
                recursive_resolver_enabled,
                encrypted_upstream_enabled,
                encrypted_upstream_allow_plaintext_fallback,
            )
            .await?;
        let observation = if !discovery_enabled {
            DiscoveryObservation::Unavailable
        } else if self.discovery_resolver.is_none() {
            DiscoveryObservation::NotConfigured
        } else {
            self.discovery_observation(&name_owned)
                .unwrap_or(DiscoveryObservation::Unavailable)
        };
        // Only explicit sinkholes justify permanent auto-blocking. Discovery
        // NXDOMAIN can reflect split-horizon DNS, new domains, or regional answers.
        let discovery = match observation {
            DiscoveryObservation::Sinkhole => DiscoveryVerdict::Sinkhole,
            DiscoveryObservation::Clean | DiscoveryObservation::NxDomain => {
                if discovery_enabled {
                    DiscoveryVerdict::Clean
                } else {
                    DiscoveryVerdict::Unavailable
                }
            }
            DiscoveryObservation::NotConfigured => {
                if answer.answers.iter().any(is_sinkhole_record) {
                    DiscoveryVerdict::Sinkhole
                } else {
                    DiscoveryVerdict::Clean
                }
            }
            DiscoveryObservation::Unavailable => DiscoveryVerdict::Unavailable,
        };
        let answer = Arc::new(CachedResponse::new_with_negative_ttl(
            answer.response_code,
            answer.answers,
            answer.authorities,
            answer.additionals,
            answer.negative_ttl,
            negative_ttl_fallback,
            answer.authenticated_data,
        ));
        Ok(Arc::new(ResolvedUpstream {
            answer,
            cache_published: tokio::sync::OnceCell::new(),
            resolver_label,
            discovery,
        }))
    }
}

/// TLDs that only exist on private networks (RFC 6762, RFC 8375,
/// draft-davies-internal-tld, and common router defaults). Public filtering
/// resolvers know nothing about these names, so their verdicts on them are
/// meaningless.
const PRIVATE_TLDS: &[&str] = &[
    "local",
    "lan",
    "home",
    "internal",
    "localdomain",
    "intranet",
];

/// Whether `name` may be written to the permanent auto-block list: it must
/// look like a public domain -- at least two labels, not under a
/// private-use TLD or `home.arpa`.
fn is_auto_blockable(name: &hickory_proto::rr::Name) -> bool {
    let labels: Vec<&[u8]> = name.iter().collect();
    let Some(tld) = labels.last() else {
        return false;
    };
    if labels.len() < 2 {
        return false;
    }
    if PRIVATE_TLDS
        .iter()
        .any(|private| tld.eq_ignore_ascii_case(private.as_bytes()))
    {
        return false;
    }
    let second = labels[labels.len() - 2];
    !(tld.eq_ignore_ascii_case(b"arpa") && second.eq_ignore_ascii_case(b"home"))
}

fn is_sinkhole_record(record: &Record) -> bool {
    match &record.data {
        hickory_proto::rr::RData::A(address) => address.0 == std::net::Ipv4Addr::UNSPECIFIED,
        hickory_proto::rr::RData::AAAA(address) => address.0 == std::net::Ipv6Addr::UNSPECIFIED,
        _ => false,
    }
}

#[async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let client_ip = request.src().ip();

        // Reject untrusted clients before rate-limit, device, cache, filter,
        // logging, or upstream state can be created for the request.
        let runtime_config = self.config.load_runtime();
        if !runtime_config.allows_client(client_ip) {
            let metadata = Self::response_metadata(request, ResponseCode::Refused, false);
            return self
                .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                .await;
        }

        let now = Instant::now();

        // Reject floods before device tracking, config access, or filtering.
        // Whitelisted devices bypass content policy, but still consume rate limits.
        let allowed = rate_limiter().check_and_increment_now(client_ip);
        if !allowed {
            record_rate_limit_rejection(client_ip);
            let metadata = Self::response_metadata(request, ResponseCode::Refused, false);
            return self
                .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                .await;
        }

        let Ok(_request_permit) = self.request_slots.try_acquire() else {
            return self
                .send_dns_response(
                    request,
                    response_handle,
                    Self::response_metadata(request, ResponseCode::Refused, false),
                    &[],
                    &[],
                    &[],
                )
                .await;
        };
        if let Err(error) = self.updater.ensure_current_sources().await {
            error!("Cannot reconcile filtering sources: {error}");
            return self
                .send_dns_response(
                    request,
                    response_handle,
                    Self::response_metadata(request, ResponseCode::ServFail, false),
                    &[],
                    &[],
                    &[],
                )
                .await;
        }
        let runtime_config = self.config.load_runtime();
        self.network_tracker.track_query(client_ip).await;

        // Hold one immutable config snapshot across awaits; borrow its fields
        // instead of cloning collections on every query, including cache hits.
        let cfg = runtime_config.config();
        let auto_block_upstream_sinkholes = cfg.auto_block_upstream_sinkholes;
        let smart_ip_blocking = cfg.smart_ip_blocking;
        let negative_ttl_fallback = cfg.cache_negative_ttl_fallback_secs;
        let device_blocking_enabled = cfg.device_blocking_enabled;
        let encrypted_upstream_enabled = cfg.encrypted_upstream_enabled;
        let encrypted_upstream_allow_plaintext_fallback =
            cfg.encrypted_upstream_allow_plaintext_fallback;
        let recursive_resolver_enabled = cfg.recursive_resolver_enabled;
        let local_dns = runtime_config.local_dns();
        let enforce_safesearch = cfg.enforce_safesearch;
        let ml_scoring_enabled = cfg.ml_scoring_enabled;
        let protection_paused_until = cfg.protection_paused_until;
        let now_epoch = crate::config::now_epoch();
        #[cfg(not(feature = "feat-scoring"))]
        let _ = ml_scoring_enabled;

        // A global pause bypasses both service blocking and the filter engine.
        let mut force_bypass = protection_paused_until.is_some_and(|t| t > now_epoch);

        // Schedules precede static policies; stable MAC identity precedes IP.
        if device_blocking_enabled && !force_bypass {
            let mac = self
                .network_tracker
                .find_device(&client_ip)
                .and_then(|device| device.mac);
            match runtime_config.effective_device_policy(
                client_ip,
                mac.as_deref(),
                chrono::Local::now(),
            ) {
                crate::policy::DevicePolicy::Block
                | crate::policy::DevicePolicy::IdentityUnknown => {
                    return self
                        .send_dns_response(
                            request,
                            response_handle,
                            Self::response_metadata(request, ResponseCode::Refused, false),
                            &[],
                            &[],
                            &[],
                        )
                        .await;
                }
                crate::policy::DevicePolicy::Whitelist => force_bypass = true,
                crate::policy::DevicePolicy::Filtered => {}
            }
        }

        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                let metadata = Self::response_metadata(request, ResponseCode::FormErr, false);
                return self
                    .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                    .await;
            }
        };

        if request_info.query.query_class() != DNSClass::IN {
            let metadata = Self::response_metadata(request, ResponseCode::NotImp, false);
            return self
                .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                .await;
        }

        let name = request_info.query.name();
        let query_type = request_info.query.query_type();

        let original_query = request_info.query.original();
        let key = CacheKey {
            name: original_query.name().clone(),
            qtype: original_query.query_type(),
            qclass: original_query.query_class(),
        };

        let policy = domain_policy(cfg, &self.updater, &key.name, now_epoch, force_bypass);
        if policy.blocked() {
            return self
                .reject_content(
                    request,
                    response_handle,
                    &key,
                    now,
                    if matches!(policy, DomainPolicy::Service(_)) {
                        "App Blocker"
                    } else {
                        "Blocklist"
                    },
                )
                .await;
        }
        let bypass_detection =
            force_bypass || matches!(policy, DomainPolicy::Allow | DomainPolicy::Bypass);

        if !bypass_detection
            && let Err(code) = self.checked_discovery(&key.name, cfg, local_dns).await
        {
            return self
                .policy_error(
                    request,
                    response_handle,
                    &key,
                    now,
                    code,
                    "Sinkhole Discovery",
                )
                .await;
        }

        if enforce_safesearch
            && local_dns.lookup(name).is_none()
            && !bypass_detection
            && let Some(safe_target) = crate::safesearch::get_safesearch_target(&key.name)
        {
            info!("SafeSearch redirect: {} -> {}", key.name, safe_target);
            let rdata =
                hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(safe_target));
            let record = hickory_proto::rr::Record::from_rdata(key.name.clone(), 60, rdata);
            let records = [record];
            if let Err(code) = self
                .inspect_answer(cfg, &records, false, now_epoch, local_dns)
                .await
            {
                return self
                    .policy_error(
                        request,
                        response_handle,
                        &key,
                        now,
                        code,
                        "SafeSearch Policy",
                    )
                    .await;
            }
            let metadata = Self::response_metadata(request, ResponseCode::NoError, false);
            self.log_query(
                client_ip,
                || key.name.to_string(),
                key.qtype,
                ResponseCode::NoError,
                now.elapsed().as_nanos() as u64,
                FilterVerdict::Pass,
                "SafeSearch Rewrite".into(),
            );
            return self
                .send_dns_response(request, response_handle, metadata, &records, &[], &[])
                .await;
        }

        // A local owner exists for every query type. Return NODATA for a missing
        // type; upstream NXDOMAIN would incorrectly deny the whole name.
        if let Some(entry) = local_dns.lookup(name) {
            let mut local_answers = Vec::new();
            let mut owner = key.name.clone();
            let mut current = entry;
            let mut external_target = None;
            let mut local_response_code = ResponseCode::NoError;
            let mut local_authorities = Vec::new();
            let mut hops = 0;

            // Stub resolvers expect a recursive server to return the whole
            // CNAME chain plus the final address records, so follow local
            // CNAMEs here and resolve an external target upstream below.
            loop {
                if let Some(cname_target) = &current.cname {
                    if domain_policy(
                        cfg,
                        &self.updater,
                        cname_target,
                        now_epoch,
                        bypass_detection,
                    )
                    .blocked()
                    {
                        return self
                            .reject_content(
                                request,
                                response_handle,
                                &key,
                                now,
                                "Local CNAME Policy",
                            )
                            .await;
                    }
                    local_answers.push(Record::from_rdata(
                        owner.clone(),
                        60,
                        hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                            cname_target.clone(),
                        )),
                    ));
                    hops += 1;
                    if query_type == RecordType::CNAME {
                        break;
                    }
                    if hops > MAX_LOCAL_CNAME_HOPS {
                        local_response_code = ResponseCode::ServFail;
                        local_answers.clear();
                        break;
                    }
                    match local_dns
                        .lookup(&hickory_proto::rr::LowerName::from(cname_target.clone()))
                    {
                        Some(next) => {
                            owner = cname_target.clone();
                            current = next;
                            continue;
                        }
                        None => {
                            external_target = Some(cname_target.clone());
                            break;
                        }
                    }
                }

                match query_type {
                    RecordType::A => {
                        local_answers.extend(current.a.iter().copied().map(|ip| {
                            Record::from_rdata(
                                owner.clone(),
                                60,
                                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip)),
                            )
                        }));
                    }
                    RecordType::AAAA => {
                        local_answers.extend(current.aaaa.iter().copied().map(|ip| {
                            Record::from_rdata(
                                owner.clone(),
                                60,
                                hickory_proto::rr::RData::AAAA(hickory_proto::rr::rdata::AAAA(ip)),
                            )
                        }));
                    }
                    _ => {}
                }
                break;
            }

            if let Some(target) = external_target {
                if !bypass_detection
                    && let Err(code) = self.checked_discovery(&target, cfg, local_dns).await
                {
                    return self
                        .policy_error(
                            request,
                            response_handle,
                            &key,
                            now,
                            code,
                            "Local CNAME Discovery",
                        )
                        .await;
                }
                match self
                    .resolve_upstream(
                        request,
                        &hickory_proto::rr::LowerName::from(target.clone()),
                        query_type,
                        recursive_resolver_enabled,
                        encrypted_upstream_enabled,
                        encrypted_upstream_allow_plaintext_fallback,
                    )
                    .await
                {
                    Ok((upstream, _)) => {
                        local_response_code = upstream.response_code;
                        local_authorities = upstream.authorities;
                        local_answers.extend(upstream.answers);
                    }
                    Err(e) => {
                        debug!(
                            "Failed to resolve local CNAME target {} {:?}: {}",
                            target, query_type, e
                        );
                        local_response_code = ResponseCode::ServFail;
                        local_answers.clear();
                    }
                }
            }

            if let Err(code) = self
                .inspect_answer(cfg, &local_answers, bypass_detection, now_epoch, local_dns)
                .await
            {
                return self
                    .policy_error(
                        request,
                        response_handle,
                        &key,
                        now,
                        code,
                        "Local DNS Policy",
                    )
                    .await;
            }
            debug!("Resolved custom local DNS record for {}", key.name);
            let metadata = Self::response_metadata(request, local_response_code, false);
            self.log_query(
                client_ip,
                || key.name.to_string(),
                key.qtype,
                local_response_code,
                now.elapsed().as_nanos() as u64,
                FilterVerdict::Pass,
                "Local DNS".into(),
            );
            return self
                .send_dns_response(
                    request,
                    response_handle,
                    metadata,
                    &local_answers,
                    &local_authorities,
                    &[],
                )
                .await;
        }

        // Scoring only flags names for review; it must never alter DNS responses.
        #[cfg(feature = "feat-scoring")]
        {
            if ml_scoring_enabled {
                let result = scoring::DomainScorer::default().score_domain(&key.name.to_string());
                if result.verdict != scoring::DomainVerdict::Normal {
                    debug!(
                        "ML scoring: '{}' flagged {:?} (score={:.2}, entropy={:.2})",
                        key.name, result.verdict, result.score, result.entropy
                    );
                }
            }
        }

        if let Some(cached) = self.l1_cache.get(&key) {
            if let Err(code) = self
                .inspect_answer(
                    cfg,
                    cached.answers(),
                    bypass_detection,
                    now_epoch,
                    local_dns,
                )
                .await
            {
                return self
                    .policy_error(
                        request,
                        response_handle,
                        &key,
                        now,
                        code,
                        "Cached Answer Policy",
                    )
                    .await;
            }
            if let Some(sections) = cached.sections_at(Instant::now()) {
                debug!("L1 cache hit for {} {:?}", key.name, key.qtype);
                let info = self
                    .send_cached_response(request, response_handle, &cached, sections)
                    .await;
                self.log_query(
                    client_ip,
                    || key.name.to_string(),
                    key.qtype,
                    cached.response_code,
                    now.elapsed().as_nanos() as u64,
                    FilterVerdict::Pass,
                    "L1 Cache".into(),
                );
                return info;
            }
        }

        if let Some(cached) = self.l2_cache.get(&key).await {
            if let Err(code) = self
                .inspect_answer(
                    cfg,
                    cached.answers(),
                    bypass_detection,
                    now_epoch,
                    local_dns,
                )
                .await
            {
                return self
                    .policy_error(
                        request,
                        response_handle,
                        &key,
                        now,
                        code,
                        "Cached Answer Policy",
                    )
                    .await;
            }
            if let Some(sections) = cached.sections_at(Instant::now()) {
                debug!("L2 cache hit for {} {:?}", key.name, key.qtype);

                self.l1_cache.insert(key.clone(), cached.clone());

                let info = self
                    .send_cached_response(request, response_handle, &cached, sections)
                    .await;
                self.log_query(
                    client_ip,
                    || key.name.to_string(),
                    key.qtype,
                    cached.response_code,
                    now.elapsed().as_nanos() as u64,
                    FilterVerdict::Pass,
                    "L2 Cache".into(),
                );
                return info;
            }
        }

        debug!(
            "Cache miss. Forwarding query for {} {:?}",
            key.name, key.qtype
        );

        // Coalesce identical cache misses: one leader resolves upstream while
        // followers await its result. This supplements the L1/L2 caches.
        enum InFlightRole {
            Leader(Arc<InFlightSender>),
            Follower(tokio::sync::watch::Receiver<Option<UpstreamResult>>),
        }

        let role = match self.in_flight.entry(key.clone()) {
            DashEntry::Occupied(e) => InFlightRole::Follower(e.get().subscribe()),
            DashEntry::Vacant(e) => {
                let (tx, _rx) = tokio::sync::watch::channel(None);
                let tx = Arc::new(tx);
                e.insert(tx.clone());
                InFlightRole::Leader(tx)
            }
        };

        // Keep the leader registered through inspection and cache publication.
        let mut _leader_cleanup = None;
        let upstream_result: UpstreamResult = match role {
            InFlightRole::Leader(upstream_tx) => {
                _leader_cleanup = Some(InFlightLeader {
                    map: self.in_flight.clone(),
                    key: key.clone(),
                    sender: upstream_tx.clone(),
                });
                // A prior leader may have populated the cache after our first lookup.
                let cached = match self.l1_cache.get(&key) {
                    Some(value) => Some(value),
                    None => self.l2_cache.get(&key).await,
                }
                .filter(|value| value.remaining_ttl(Instant::now()).is_some());
                let result = if let Some(answer) = cached {
                    Ok(Arc::new(ResolvedUpstream {
                        answer,
                        resolver_label: "Cache".into(),
                        discovery: DiscoveryVerdict::Unavailable,
                        cache_published: tokio::sync::OnceCell::new_with(Some(())),
                    }))
                } else {
                    self.resolve_with_discovery(
                        request,
                        name,
                        query_type,
                        recursive_resolver_enabled,
                        encrypted_upstream_enabled,
                        encrypted_upstream_allow_plaintext_fallback,
                        auto_block_upstream_sinkholes,
                        Duration::from_millis(cfg.discovery_timeout_ms),
                        negative_ttl_fallback,
                    )
                    .await
                };
                // `send_replace` stores the value even if no follower has
                // subscribed yet. A follower that subscribed while holding
                // the DashMap entry guard can therefore never miss it.
                upstream_tx.send_replace(Some(result.clone()));
                result
            }
            InFlightRole::Follower(mut rx) => loop {
                if let Some(result) = rx.borrow_and_update().clone() {
                    break result;
                }
                if rx.changed().await.is_err() {
                    // The leader's sender was dropped without ever sending a
                    // result (e.g. its task was cancelled mid-fetch). Fail
                    // this follower rather than waiting forever.
                    break Err("in-flight upstream request did not complete".to_string());
                }
            },
        };

        match upstream_result {
            Ok(resolved) => {
                let cached_response = &resolved.answer;
                let response_code = cached_response.response_code;
                let metadata = Self::response_metadata(
                    request,
                    response_code,
                    cached_response.authenticated_data,
                );
                let discovery = resolved.discovery;

                let is_upstream_blocked =
                    !bypass_detection && discovery == DiscoveryVerdict::Sinkhole;

                // Smart IP blocking: block a domain whose answer points at a
                // known-malicious IP. Gated on the admin toggle.
                let found_malicious_ip = smart_ip_blocking
                    && !bypass_detection
                    && !is_upstream_blocked
                    && self.has_malicious_address(cached_response.answers());

                if is_upstream_blocked || found_malicious_ip {
                    let domain_name = original_query.name().to_string();
                    self.persist_auto_deny(original_query.name());

                    let metadata = Self::response_metadata(request, ResponseCode::NXDomain, false);
                    let info = self
                        .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                        .await;
                    self.log_query(
                        client_ip,
                        move || domain_name,
                        original_query.query_type(),
                        ResponseCode::NXDomain,
                        now.elapsed().as_nanos() as u64,
                        FilterVerdict::Block,
                        "Smart IP Block".into(),
                    );
                    return info;
                }

                if let Err(code) = self
                    .inspect_answer(
                        cfg,
                        cached_response.answers(),
                        bypass_detection,
                        now_epoch,
                        local_dns,
                    )
                    .await
                {
                    return self
                        .policy_error(request, response_handle, &key, now, code, "Answer Policy")
                        .await;
                }
                // Only successful positive/negative responses are cacheable.
                // Transport failures and SERVFAIL must remain transient.
                if CachedResponse::is_cacheable(response_code) && cached_response.original_ttl > 0 {
                    resolved
                        .cache_published
                        .get_or_init(|| async {
                            self.l2_cache
                                .insert(key.clone(), cached_response.clone())
                                .await;
                            self.l1_cache.insert(key.clone(), cached_response.clone());
                        })
                        .await;
                }

                let info = if let Some(sections) = cached_response.sections_at(Instant::now()) {
                    self.send_cached_response(request, response_handle, cached_response, sections)
                        .await
                } else if cached_response.original_ttl == 0 {
                    self.send_dns_response(
                        request,
                        response_handle,
                        metadata,
                        cached_response.answers(),
                        cached_response.authorities(),
                        cached_response.additionals(),
                    )
                    .await
                } else {
                    return self
                        .policy_error(
                            request,
                            response_handle,
                            &key,
                            now,
                            ResponseCode::ServFail,
                            "Expired Upstream Answer",
                        )
                        .await;
                };

                self.log_query(
                    client_ip,
                    || original_query.name().to_string(),
                    original_query.query_type(),
                    response_code,
                    now.elapsed().as_nanos() as u64,
                    FilterVerdict::Pass,
                    resolved.resolver_label.clone().into(),
                );
                info
            }
            Err(e) => {
                warn!(
                    "Upstream lookup failed for {} {:?}: {:?}",
                    name, query_type, e
                );

                let metadata = Self::response_metadata(request, ResponseCode::ServFail, false);
                let info = self
                    .send_dns_response(request, response_handle, metadata, &[], &[], &[])
                    .await;

                self.log_query(
                    client_ip,
                    || original_query.name().to_string(),
                    original_query.query_type(),
                    ResponseCode::ServFail,
                    now.elapsed().as_nanos() as u64,
                    FilterVerdict::Pass,
                    "Standard Upstreams".into(),
                );
                info
            }
        }
    }
}
