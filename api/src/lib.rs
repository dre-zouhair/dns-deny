// A build without one of the two surfaces leaves code only the other uses
// (JSON handlers and DTOs, or browser sessions and page rendering)
// unreachable. The default build, with both, still lints all of it.
#![cfg_attr(
    not(all(feature = "feat-json-api", feature = "feat-web-ui")),
    allow(dead_code)
)]

#[cfg(not(any(feature = "feat-json-api", feature = "feat-web-ui")))]
compile_error!("the admin server needs `feat-web-ui` and/or `feat-json-api`");

#[cfg(feature = "feat-web-ui")]
mod web;

use arc_swap::ArcSwapOption;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
#[cfg(feature = "feat-json-api")]
use axum::routing::delete;
use axum::{
    Json, Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::{
        Html, IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "feat-web-ui")]
use tower_http::services::ServeDir;

use hickory_proto::rr::Name;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tokio_stream::StreamExt;
use tracing::{error, info};

use core_dns::cache::l1::L1Cache;
use core_dns::cache::l2::L2Cache;
use core_dns::config::{Config, ConfigHandle, ConfigUpdateError};
use core_dns::updater::BlocklistUpdater;
use logger::QueryLogger;
use logger::stats::{self as log_stats, Window};
use rule_types::RuleAction;
use rusqlite::{Connection, OpenFlags};

#[derive(Clone)]
struct ApiState {
    config: Arc<ConfigHandle>,
    updater: Arc<BlocklistUpdater>,
    l1_cache: Arc<L1Cache>,
    l2_cache: L2Cache,
    logger: Option<Arc<QueryLogger>>,
    db_path: PathBuf,
    rate_limiter: Arc<tokio::sync::Mutex<ApiRateLimiterState>>,
    network_tracker: Arc<core_dns::network::NetworkTracker>,
    sessions: Arc<SessionStore>,
    doh_client: Arc<ArcSwapOption<core_dns::doh::DohClient>>,
    stats_cache: Arc<StatsCache>,
    password_work: Arc<tokio::sync::Semaphore>,
    trusted_proxy_nets: Arc<Vec<ipnet::IpNet>>,
}

struct ApiRateLimiterState {
    // Keyed by IP only (not SocketAddr): keying by the full peer address would
    // include the client's ephemeral source port, so a new TCP connection would
    // always start with a fresh quota instead of sharing one per client.
    hits: HashMap<IpAddr, Vec<Instant>>,
    qps_limit: u64,
    login_hits: HashMap<IpAddr, Vec<Instant>>,
}

impl ApiRateLimiterState {
    fn login_allowed(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.login_hits.len() >= 4096 {
            self.login_hits.retain(|_, hits| {
                hits.retain(|time| now.duration_since(*time) < Duration::from_secs(60));
                !hits.is_empty()
            });
            if !self.login_hits.contains_key(&ip) && self.login_hits.len() >= 4096 {
                return false;
            }
        }
        let hits = self.login_hits.entry(ip).or_default();
        hits.retain(|time| now.duration_since(*time) < Duration::from_secs(60));
        if hits.len() >= 10 {
            return false;
        }
        hits.push(now);
        true
    }

    fn is_allowed(&mut self, addr: SocketAddr) -> bool {
        let ip = addr.ip();
        let now = Instant::now();

        // Evict inactive clients so the limiter cannot grow indefinitely.
        if self.hits.len() > 4096 {
            self.hits.retain(|_, timestamps| {
                timestamps.retain(|&t| now.duration_since(t) < Duration::from_secs(1));
                !timestamps.is_empty()
            });
        }

        let timestamps = self.hits.entry(ip).or_default();

        timestamps.retain(|&t| now.duration_since(t) < Duration::from_secs(1));

        if (timestamps.len() as u64) < self.qps_limit {
            timestamps.push(now);
            true
        } else {
            false
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct StatsResponse {
    total_queries: u64,
    blocked_queries: u64,
    block_rate: f64,
    top_blocked: Vec<DomainCount>,
    top_allowed: Vec<DomainCount>,
    client_breakdown: Vec<ClientCount>,
}

#[derive(Serialize, Clone)]
struct DomainCount {
    domain: String,
    count: u64,
}

#[derive(Serialize, Clone)]
struct ClientCount {
    client_ip: String,
    count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalRuleRequest {
    pub pattern: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceRequest {
    pub url: String,
}

#[derive(Serialize)]
struct TopBlockedResponse {
    domains: Vec<DomainCount>,
}

#[derive(Serialize)]
struct TopClientsResponse {
    clients: Vec<ClientCount>,
}

#[derive(Serialize)]
struct QueryBucket {
    /// UTC label: "YYYY-MM-DD HH:00" for hourly buckets, "YYYY-MM-DD" for daily.
    hour: String,
    /// Bucket start (Unix ms), so the dashboard can label it in local time.
    start_ms: i64,
    total: u64,
    blocked: u64,
}

#[derive(Serialize)]
struct QueriesOverTimeResponse {
    buckets: Vec<QueryBucket>,
}

#[derive(Debug, Serialize)]
pub struct SourceStatusInfo {
    pub url: String,
    pub rules: usize,
    pub cached: bool,
}

#[derive(Serialize)]
struct SuccessResponse {
    status: String,
}

#[derive(Serialize)]
struct ConfigUpdateResponse {
    status: String,
    restart_required: bool,
    message: String,
}

#[derive(Deserialize)]
struct ProtectionScopeRequest {
    scope: String, // "global" | "category" | "service" | "device"
    #[serde(default)]
    id: Option<String>,
    /// How long to pause for. Omitted -> `protection_pause_default_duration_secs`.
    /// Ignored when `indefinite` is set. Resume requests ignore both.
    #[serde(default)]
    duration_secs: Option<u64>,
    /// Pause until explicitly resumed, with no expiry.
    #[serde(default)]
    indefinite: bool,
}

/// Caps timed pauses at 30 days; longer pauses must explicitly use indefinite mode.
const MAX_PAUSE_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

#[derive(Serialize)]
struct ProtectionPauseResponse {
    status: String,
    scope: String,
    id: Option<String>,
    paused_until: i64,
}

#[derive(Serialize)]
struct ProtectionStatusResponse {
    default_duration_secs: u64,
    global_paused_until: Option<i64>,
    category_pauses: HashMap<String, i64>,
    service_pauses: HashMap<String, i64>,
    device_pauses: HashMap<String, i64>,
}

#[derive(Serialize)]
struct AutoBlockedResponse {
    domains: Vec<String>,
    count: usize,
}

#[derive(Serialize)]
struct MaliciousIpsResponse {
    count: usize,
    ips: Vec<String>,
}

#[derive(Serialize)]
struct ListCountDto {
    count: usize,
}

#[derive(Serialize)]
struct SourceGroupDto {
    url_count: usize,
    rule_count: usize,
}

#[derive(Serialize)]
struct CategorySummaryDto {
    id: String,
    name: String,
    enabled: bool,
    paused: bool,
    url_count: usize,
    rule_count: usize,
}

#[derive(Serialize)]
struct ListsSummaryResponse {
    local_allow: ListCountDto,
    local_deny: ListCountDto,
    regex_allow: ListCountDto,
    regex_deny: ListCountDto,
    malicious_ips: ListCountDto,
    auto_blocked: ListCountDto,
    uncategorized_sources: SourceGroupDto,
    categories: Vec<CategorySummaryDto>,
}

static MAC_ADDR_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$").unwrap()
});

/// Compares secret bytes without short-circuiting on the first difference.
fn constant_time_eq(a: &str, b: &str) -> bool {
    constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
}

fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// How long an issued session token stays valid.
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Ceiling on concurrently-valid sessions, so a script hammering the login
/// endpoint with the correct key can't grow this map without bound. Once
/// reached, the oldest session is evicted.
const MAX_SESSIONS: usize = 512;

/// In-memory store of issued session tokens.
///
/// Keeps `bcrypt::verify` off the browser's per-request path. A password
/// change stores a bcrypt hash. Browser login verifies it once on
/// a blocking thread, then uses a server-minted HttpOnly session cookie.
/// The JSON API independently verifies Bearer API keys on a blocking thread.
///
/// Tokens are stored as their SHA-256 digest rather than verbatim, so a leak
/// of this map (a core dump, a debugger) doesn't hand over usable
/// credentials. Sessions are process-local and deliberately not persisted:
/// a restart forces re-authentication.
#[derive(Default)]
struct SessionStore {
    sessions: std::sync::RwLock<HashMap<[u8; 32], Instant>>,
    generation: std::sync::atomic::AtomicU64,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

impl SessionStore {
    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Mints a token only if the credential generation still matches the
    /// one captured before password verification. Only its digest is stored.
    fn issue(&self, generation: u64) -> Result<Option<String>, getrandom::Error> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw)?;

        let token: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
        let digest = sha256(token.as_bytes());
        let expires_at = Instant::now() + SESSION_TTL;

        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        // Password verification awaits bcrypt outside this lock. A rotation
        // during that await must not mint a session for the old credential.
        if self.generation() != generation {
            return Ok(None);
        }
        let now = Instant::now();
        sessions.retain(|_, &mut exp| exp > now);
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|&(_, exp)| *exp)
                .map(|(k, _)| *k)
        {
            sessions.remove(&oldest);
        }
        sessions.insert(digest, expires_at);

        Ok(Some(token))
    }

    /// Checks the token digest. Timing differences reveal only a hash, so
    /// this lookup does not require constant-time raw-secret comparison.
    fn verify(&self, token: &str) -> bool {
        let digest = sha256(token.as_bytes());
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(&digest)
            .is_some_and(|&expires_at| expires_at > Instant::now())
    }

    fn revoke(&self, token: &str) {
        let digest = sha256(token.as_bytes());
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&digest);
    }

    /// Drops every session. Called when the password changes, so tokens
    /// issued against the old credential stop working immediately.
    fn revoke_all(&self) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        sessions.clear();
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod session_security_tests {
    #[test]
    fn password_rotation_rejects_sessions_from_in_flight_old_logins() {
        let store = super::SessionStore::default();
        let old_generation = store.generation();
        let old_token = store.issue(old_generation).unwrap().unwrap();
        assert!(store.verify(&old_token));

        // A second login captured this generation before waiting for bcrypt.
        // Rotation completes while it is still verifying the old password.
        store.revoke_all();
        assert!(!store.verify(&old_token));
        assert!(store.issue(old_generation).unwrap().is_none());
        let new_token = store.issue(store.generation()).unwrap().unwrap();
        assert!(store.verify(&new_token));
    }
}

/// True when `api_key` holds a bcrypt hash rather than a plaintext key.
fn is_bcrypt_hash(api_key: &str) -> bool {
    api_key.starts_with("$2b$") || api_key.starts_with("$2a$") || api_key.starts_with("$2y$")
}

/// Verifies raw credentials on a blocking thread: bcrypt is CPU-bound,
/// and the async runtime also serves DNS. Dashboard requests use sessions.
async fn password_work<T: Send + 'static>(
    slots: Arc<tokio::sync::Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, StatusCode> {
    // Do not queue unbounded CPU work. The closure owns the permit so a
    // cancelled HTTP request cannot release it while bcrypt is still running.
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn verify_api_key(
    state: &ApiState,
    presented: &str,
    api_key: &str,
) -> Result<bool, StatusCode> {
    if is_bcrypt_hash(api_key) {
        if presented.len() > 72 {
            return Ok(false);
        }
        let presented = presented.to_string();
        let api_key = api_key.to_string();
        password_work(state.password_work.clone(), move || {
            bcrypt::verify(&presented, &api_key).unwrap_or(false)
        })
        .await
    } else {
        Ok(constant_time_eq(presented, api_key))
    }
}

/// External API credentials are accepted only in the Authorization header.
#[cfg(feature = "feat-json-api")]
fn extract_credential(req: &Request) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

const SESSION_COOKIE: &str = "dns_deny_session";

fn cookie_session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
}

fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uri>().ok())
    else {
        return false;
    };
    matches!(origin.scheme_str(), Some("http" | "https"))
        && origin.authority().is_some_and(|authority| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|host| authority.as_str().eq_ignore_ascii_case(host))
        })
}

fn session_cookie(
    headers: &HeaderMap,
    token: &str,
    max_age: u64,
    allow_insecure_http: bool,
) -> HeaderValue {
    // Browsers supply Origin on sign-in POSTs, including behind TLS proxies.
    // Only a matching HTTPS origin can opt into the Secure attribute.
    let secure = !allow_insecure_http
        || (same_origin(headers)
            && headers
                .get(header::ORIGIN)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("https://")));
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    ))
    .expect("session tokens contain only hexadecimal characters")
}

#[cfg(feature = "feat-json-api")]
/// Mints a JSON API token. Returns the token, shown to the operator once,
/// and the digest to persist.
fn issue_api_token() -> Result<(String, String), getrandom::Error> {
    let token = core_dns::config::generate_api_key()?;
    let digest = core_dns::config::api_token_digest(&token);
    Ok((token, digest))
}

#[cfg(feature = "feat-json-api")]
/// True if `presented` authenticates the JSON API. Once a token has been
/// issued only that token is accepted, checked with a SHA-256 compare.
/// Before that, the admin credential is accepted so existing integrations
/// keep working; a bcrypt-hashed credential costs a bcrypt verify per call.
async fn verify_api_credential(state: &ApiState, presented: &str) -> Result<bool, StatusCode> {
    let config = state.config.load();
    match &config.api_token_sha256 {
        Some(digest) => Ok(constant_time_eq(
            &core_dns::config::api_token_digest(presented),
            digest,
        )),
        None => verify_api_key(state, presented, &config.api_key).await,
    }
}

#[derive(Serialize)]
struct ApiTokenResponse {
    token: String,
}

/// Issues a JSON API token, replacing any existing one. The token is in this
/// response only; just its digest is stored. Callers authenticate with the
/// current credential, so a bootstrap uses the admin password.
#[cfg(feature = "feat-json-api")]
async fn create_api_token(
    State(state): State<ApiState>,
) -> Result<Json<ApiTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (token, digest) = issue_api_token().map_err(|e| {
        error!("Failed to generate API token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to generate API token".to_string(),
            }),
        )
    })?;
    set_api_token_digest(&state, Some(digest)).await?;
    Ok(Json(ApiTokenResponse { token }))
}

/// Revokes the JSON API token; the admin credential authenticates again.
#[cfg(feature = "feat-json-api")]
async fn revoke_api_token(
    State(state): State<ApiState>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    set_api_token_digest(&state, None).await?;
    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[cfg(feature = "feat-json-api")]
async fn set_api_token_digest(
    state: &ApiState,
    digest: Option<String>,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:token", |cfg| {
            cfg.api_token_sha256 = digest;
            Ok::<(), String>(())
        })
        .await
        .map(|_| ())
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist API token: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })
}

// External JSON API: issued web sessions and browser cookies are not API keys.
#[cfg(feature = "feat-json-api")]
async fn auth_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let credential = extract_credential(&req).ok_or(StatusCode::UNAUTHORIZED)?;
    if verify_api_credential(&state, &credential).await? {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Content-Security-Policy for the admin UI.
///
/// Server-rendered dashboard pages receive a fresh nonce in `reactive_page`.
/// Dynamic values stay in text/data attributes, never executable expressions.
///
/// The Datastar runtime and browser conveniences are self-hosted. Only font
/// styles and files load remotely through styles.css's Google Fonts import.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
     font-src 'self' https://fonts.gstatic.com; \
     img-src 'self' data:; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// Datastar compiles expressions with nonce-bearing scripts on migrated pages.
/// Keep its nonce unique per response and out of caches.
fn reactive_page(template: &str) -> axum::response::Response {
    let mut random = [0u8; 32];
    if let Err(err) = getrandom::fill(&mut random) {
        error!("Failed to generate page nonce: {:?}", err);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load page").into_response();
    }
    let nonce: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let policy = CONTENT_SECURITY_POLICY.replace(
        "script-src 'self'",
        &format!("script-src 'self' 'nonce-{nonce}'"),
    );
    let page = template
        .replace(
            "data-nonce=\"__PAGE_NONCE__\"",
            &format!("data-nonce=\"{nonce}\""),
        )
        .replace("nonce=\"__PAGE_NONCE__\"", &format!("nonce=\"{nonce}\""));
    let mut response = Html(page).into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).expect("hex nonce is a valid header value"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Directory of the dashboard's static assets: `DNS_STATIC_DIR`, else
/// `static` in the working directory.
#[cfg(feature = "feat-web-ui")]
fn static_dir() -> PathBuf {
    std::env::var_os("DNS_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("static"))
}

/// Attaches hardening headers to every response, static assets included.
async fn security_headers_middleware(req: Request, next: Next) -> impl IntoResponse {
    use axum::http::header::{HeaderName, HeaderValue};

    let path = req.uri().path();
    let is_api = path.starts_with("/api/");
    let req_path_is_ui = path.starts_with("/ui/");
    let is_vendor = path.starts_with("/vendor/");
    let mut res = next.run(req).await;
    let immutable = is_vendor && res.status().is_success();
    let headers = res.headers_mut();
    if is_api || req_path_is_ui {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    // Without an explicit policy browsers cache static files heuristically
    // for days and keep serving an old stylesheet after an upgrade. Vendor
    // files carry their version in the file name; everything else is
    // revalidated (a cheap 304) on each use. Pages set their own policy.
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }));
    headers
        .entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(CONTENT_SECURITY_POLICY));
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "same-origin"),
        // The admin UI has no use for any of these device APIs.
        (
            "permissions-policy",
            "geolocation=(), microphone=(), camera=(), interest-cohort=()",
        ),
    ] {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(name), HeaderValue::from_str(value)) {
            headers.insert(name, value);
        }
    }
    res
}

async fn rate_limit_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let mut addr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

    if trusted_https_proxy(&req, &state.trusted_proxy_nets) {
        addr.set_ip(forwarded_client_ip(&req, &state.trusted_proxy_nets).unwrap_or(addr.ip()));
    }

    let mut limiter = state.rate_limiter.lock().await;
    if limiter.is_allowed(addr)
        && (req.uri().path() != "/ui/auth/login" || limiter.login_allowed(addr.ip()))
    {
        drop(limiter);
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

fn forwarded_client_ip(req: &Request, trusted_proxy_nets: &[ipnet::IpNet]) -> Option<IpAddr> {
    // Walk from the proxy towards the client. A spoofed leftmost value must
    // not override the actual address appended by the trusted proxy.
    let mut hops = Vec::new();
    for header in req.headers().get_all("x-forwarded-for") {
        for value in header.to_str().ok()?.split(',') {
            if hops.len() == 32 {
                return None;
            }
            hops.push(value.trim().parse::<IpAddr>().ok()?);
        }
    }
    hops.into_iter()
        .rev()
        .find(|ip| !trusted_proxy_nets.iter().any(|net| net.contains(ip)))
}

fn trusted_https_proxy(req: &Request, trusted_proxy_nets: &[ipnet::IpNet]) -> bool {
    let Some(peer) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
    else {
        return false;
    };
    trusted_proxy_nets
        .iter()
        .any(|net| net.contains(&peer.0.ip()))
        && req.headers().get_all("x-forwarded-proto").iter().count() == 1
        && req
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|value| value == "https")
}

async fn require_https_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> axum::response::Response {
    let config = state.config.load();
    let secure = trusted_https_proxy(&req, &state.trusted_proxy_nets);
    if !config.api_allow_insecure_http && !secure {
        return (
            StatusCode::UPGRADE_REQUIRED,
            "HTTPS is required. Use the configured TLS reverse proxy.",
        )
            .into_response();
    }
    let mut response = next.run(req).await;
    if secure {
        response.headers_mut().insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}

// SQLite work runs on the blocking pool so dashboard queries cannot
// occupy runtime workers shared with DNS listeners.

/// Runs blocking SQLite work on the blocking pool and maps both the join
/// failure and the rusqlite error onto a 500.
async fn db_blocking<T, F>(f: F) -> Result<T, (StatusCode, Json<ErrorResponse>)>
where
    F: FnOnce() -> Result<T, rusqlite::Error> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => {
            error!("Database query failed: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database query failure".to_string(),
                }),
            ))
        }
        Err(e) => {
            error!("Database task panicked: {:?}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database query failure".to_string(),
                }),
            ))
        }
    }
}

/// Opens the log database read-only, returning `None` when it doesn't exist
/// yet (a fresh install, or logging disabled) so callers can answer with
/// empty results rather than an error.
fn open_log_db(db_path: &std::path::Path) -> Option<Connection> {
    Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()
}

/// Parses the UTC date out of a `logs_YYYY_MM_DD` table name.
fn partition_date(table: &str) -> Option<chrono::NaiveDate> {
    if !logger::stats::is_partition_name(table) {
        return None;
    }
    let date_str = table.strip_prefix("logs_")?;
    chrono::NaiveDate::parse_from_str(date_str, "%Y_%m_%d").ok()
}

// ── Dashboard statistics ───────────────────────────────────────────────────
//
// Served from the logger's pre-aggregated rollup tables (`logger::stats`)
// rather than by scanning every retained log partition on each dashboard
// refresh.

#[derive(Deserialize)]
struct WindowQuery {
    window: Option<String>,
}

fn parse_window(
    query: &WindowQuery,
    default: Window,
) -> Result<Window, (StatusCode, Json<ErrorResponse>)> {
    match query.window.as_deref() {
        None => Ok(default),
        Some(raw) => Window::parse(raw).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "window must be one of: 24h, 7d, all".to_string(),
                }),
            )
        }),
    }
}

/// Reuses costly 7d/All responses between dashboard polls; cheap 24h
/// responses are computed fresh.
const STATS_CACHE_TTL: Duration = Duration::from_secs(30);

/// (endpoint, window) -> (computed at, response body).
type StatsCacheKey = (&'static str, Window);
type StatsCacheEntry = (Instant, serde_json::Value);

#[derive(Default)]
struct StatsCache {
    entries: std::sync::Mutex<HashMap<StatsCacheKey, StatsCacheEntry>>,
}

impl StatsCache {
    fn get(&self, endpoint: &'static str, window: Window) -> Option<serde_json::Value> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(&(endpoint, window))
            .filter(|(at, _)| at.elapsed() < STATS_CACHE_TTL)
            .map(|(_, value)| value.clone())
    }

    fn put(&self, endpoint: &'static str, window: Window, value: serde_json::Value) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((endpoint, window), (Instant::now(), value));
    }
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Computes one statistics response on the blocking pool (through the
/// response cache for 7d/All). A missing log database (fresh install,
/// logging disabled) reads as an empty in-memory one, so every endpoint
/// answers with zeros instead of an error.
async fn stats_response<T, F>(
    state: &ApiState,
    endpoint: &'static str,
    window: Window,
    compute: F,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)>
where
    T: Serialize + Send + 'static,
    F: FnOnce(&Connection, i64) -> Result<T, rusqlite::Error> + Send + 'static,
{
    let cacheable = window != Window::Last24h;
    if cacheable && let Some(value) = state.stats_cache.get(endpoint, window) {
        return Ok(Json(value));
    }

    let db_path = state.db_path.clone();
    let response = db_blocking(move || {
        let conn = match open_log_db(&db_path) {
            Some(conn) => conn,
            None => Connection::open_in_memory()?,
        };
        compute(&conn, now_epoch_ms())
    })
    .await?;

    let value = serde_json::to_value(response).map_err(|e| {
        error!("Failed to serialize {} statistics: {:?}", endpoint, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to build statistics".to_string(),
            }),
        )
    })?;
    if cacheable {
        state.stats_cache.put(endpoint, window, value.clone());
    }
    Ok(Json(value))
}

fn domain_counts(rows: Vec<(String, u64)>) -> Vec<DomainCount> {
    rows.into_iter()
        .map(|(domain, count)| DomainCount { domain, count })
        .collect()
}

fn client_counts(rows: Vec<(String, u64)>) -> Vec<ClientCount> {
    rows.into_iter()
        .map(|(client_ip, count)| ClientCount { client_ip, count })
        .collect()
}

async fn get_stats(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::All)?;
    stats_response(&state, "stats", window, move |conn, now| {
        let totals = log_stats::totals(conn, window, now)?;
        let block_rate = if totals.total > 0 {
            (totals.blocked as f64 / totals.total as f64) * 100.0
        } else {
            0.0
        };
        let top = |dim| log_stats::top(conn, window, dim, 10, now);
        Ok(StatsResponse {
            total_queries: totals.total,
            blocked_queries: totals.blocked,
            block_rate,
            top_blocked: domain_counts(top(log_stats::DIM_BLOCKED_DOMAIN)?),
            top_allowed: domain_counts(top(log_stats::DIM_ALLOWED_DOMAIN)?),
            client_breakdown: client_counts(top(log_stats::DIM_CLIENT)?),
        })
    })
    .await
}

/// Normalizes and validates local patterns exactly as ingestion does, so
/// accepted rules match queries and differently spelled removals agree.
fn validate_local_pattern(raw: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    rule_types::normalize_domain(raw).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid domain pattern".to_string(),
            }),
        )
    })
}

fn rule_persistence_error(error: std::io::Error) -> (StatusCode, Json<ErrorResponse>) {
    let status = if error.kind() == std::io::ErrorKind::InvalidInput {
        StatusCode::BAD_REQUEST
    } else if error.kind() == std::io::ErrorKind::WouldBlock {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (
        status,
        Json(ErrorResponse {
            error: format!("Rule update failed: {error}"),
        }),
    )
}

async fn add_allow(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pattern = validate_local_pattern(&payload.pattern)?;
    state
        .updater
        .add_local_rule(pattern.clone(), RuleAction::Allow)
        .await
        .map_err(rule_persistence_error)?;

    // Publish the new snapshot before invalidating cached responses, or a
    // concurrent query can repopulate the cache from the old rules.
    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after local list addition: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    if let Ok(name) = Name::from_str(&pattern) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn add_deny(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pattern = validate_local_pattern(&payload.pattern)?;
    state
        .updater
        .add_local_rule(pattern.clone(), RuleAction::Deny)
        .await
        .map_err(rule_persistence_error)?;

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after local list addition: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    if let Ok(name) = Name::from_str(&pattern) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn remove_allow(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pattern = validate_local_pattern(&payload.pattern)?;
    let existed = state
        .updater
        .remove_local_rule(&pattern, RuleAction::Allow)
        .await
        .map_err(rule_persistence_error)?;
    if !existed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Rule not found".to_string(),
            }),
        ));
    }

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after local list removal: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    if let Ok(name) = Name::from_str(&pattern) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn remove_deny(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pattern = validate_local_pattern(&payload.pattern)?;
    let existed = state
        .updater
        .remove_local_rule(&pattern, RuleAction::Deny)
        .await
        .map_err(rule_persistence_error)?;
    if !existed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Rule not found".to_string(),
            }),
        ));
    }

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after local list removal: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    if let Ok(name) = Name::from_str(&pattern) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_allow(State(state): State<ApiState>) -> Json<Vec<String>> {
    let set = state.updater.local_allows.lock().await;
    let mut list: Vec<String> = set.iter().cloned().collect();
    list.sort();
    Json(list)
}

async fn get_deny(State(state): State<ApiState>) -> Json<Vec<String>> {
    let set = state.updater.local_denies.lock().await;
    let mut list: Vec<String> = set.iter().cloned().collect();
    list.sort();
    Json(list)
}

async fn get_regex_allow(State(state): State<ApiState>) -> Json<Vec<String>> {
    let set = state.updater.regex_allows.lock().await;
    let mut list: Vec<String> = set.iter().cloned().collect();
    list.sort();
    Json(list)
}

async fn add_regex_allow(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let inserted = match state
        .updater
        .add_regex_rule(payload.pattern.clone(), RuleAction::Allow)
        .await
    {
        Ok(inserted) => inserted,
        Err(e) => {
            return Err(rule_persistence_error(e));
        }
    };

    // Duplicate adds can still remove the opposite rule. Publish and invalidate
    // before returning even when inserted is false.
    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!(
            "Failed to reload engine after regex allow addition: {:?}",
            e
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    if !inserted {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Regex pattern already exists".to_string(),
            }),
        ));
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn remove_regex_allow(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let existed = state
        .updater
        .remove_regex_rule(&payload.pattern, RuleAction::Allow)
        .await
        .map_err(rule_persistence_error)?;
    if !existed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Regex rule not found".to_string(),
            }),
        ));
    }

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after regex allow removal: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_regex_deny(State(state): State<ApiState>) -> Json<Vec<String>> {
    let set = state.updater.regex_denies.lock().await;
    let mut list: Vec<String> = set.iter().cloned().collect();
    list.sort();
    Json(list)
}

async fn add_regex_deny(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let inserted = match state
        .updater
        .add_regex_rule(payload.pattern.clone(), RuleAction::Deny)
        .await
    {
        Ok(inserted) => inserted,
        Err(e) => {
            return Err(rule_persistence_error(e));
        }
    };

    // Duplicate adds can still remove the opposite rule. Publish and invalidate
    // before returning even when inserted is false.
    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after regex deny addition: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    if !inserted {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Regex pattern already exists".to_string(),
            }),
        ));
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn remove_regex_deny(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let existed = state
        .updater
        .remove_regex_rule(&payload.pattern, RuleAction::Deny)
        .await
        .map_err(rule_persistence_error)?;
    if !existed {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Regex rule not found".to_string(),
            }),
        ));
    }

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after regex deny removal: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_sources_status(State(state): State<ApiState>) -> Json<Vec<SourceStatusInfo>> {
    let statuses = state.updater.get_sources_status().await;
    Json(
        statuses
            .into_iter()
            .map(|(url, rules, cached)| SourceStatusInfo { url, rules, cached })
            .collect(),
    )
}

async fn get_lists_summary(State(state): State<ApiState>) -> Json<ListsSummaryResponse> {
    let conf = state.config.load();
    let now = core_dns::config::now_epoch();

    let rule_counts: std::collections::HashMap<String, usize> = state
        .updater
        .get_sources_status()
        .await
        .into_iter()
        .map(|(url, rules, _cached)| (url, rules))
        .collect();

    let uncategorized_sources = SourceGroupDto {
        url_count: conf.blocklist_urls.len(),
        rule_count: conf
            .blocklist_urls
            .iter()
            .map(|u| rule_counts.get(u).copied().unwrap_or(0))
            .sum(),
    };

    let categories = conf
        .blocklist_categories
        .iter()
        .map(|cat| CategorySummaryDto {
            id: cat.id.clone(),
            name: cat.name.clone(),
            enabled: cat.enabled,
            paused: conf.is_paused(&core_dns::config::PauseScope::Category(cat.id.clone()), now),
            url_count: cat.urls.len(),
            rule_count: cat
                .urls
                .iter()
                .map(|u| rule_counts.get(u).copied().unwrap_or(0))
                .sum(),
        })
        .collect();

    Json(ListsSummaryResponse {
        local_allow: ListCountDto {
            count: state.updater.local_allows.lock().await.len(),
        },
        local_deny: ListCountDto {
            count: state.updater.local_denies.lock().await.len(),
        },
        regex_allow: ListCountDto {
            count: state.updater.regex_allows.lock().await.len(),
        },
        regex_deny: ListCountDto {
            count: state.updater.regex_denies.lock().await.len(),
        },
        malicious_ips: ListCountDto {
            count: state.updater.malicious_ips.lock().await.len(),
        },
        auto_blocked: ListCountDto {
            count: state.updater.auto_denies.lock().await.len(),
        },
        uncategorized_sources,
        categories,
    })
}

async fn sync_sources(State(state): State<ApiState>) -> Json<SuccessResponse> {
    let updater_clone = state.updater.clone();
    let l1_cache = state.l1_cache.clone();
    let l2_cache = state.l2_cache.clone();
    tokio::spawn(async move {
        if let Err(error) = updater_clone.ensure_current_sources().await {
            error!("Source sync failed: {error}");
            return;
        }
        if let Err(e) = updater_clone.refresh().await {
            error!("Failed to refresh blocklist manually: {:?}", e);
        } else {
            l1_cache.clear();
            l2_cache.clear().await;
        }
    });
    Json(SuccessResponse {
        status: "sync_started".to_string(),
    })
}

async fn invalidate_source(
    State(state): State<ApiState>,
    Json(payload): Json<SourceRequest>,
) -> Json<SuccessResponse> {
    state.updater.invalidate_source(&payload.url).await;
    let updater_clone = state.updater.clone();
    let l1_cache = state.l1_cache.clone();
    let l2_cache = state.l2_cache.clone();
    tokio::spawn(async move {
        if let Err(e) = updater_clone.refresh().await {
            error!("Failed to refresh blocklist after invalidation: {:?}", e);
        } else {
            l1_cache.clear();
            l2_cache.clear().await;
        }
    });
    Json(SuccessResponse {
        status: "invalidated".to_string(),
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CacheStatsResponse {
    pub l1_entries: usize,
    pub l1_max_entries: usize,
    pub l2_entries: u64,
    pub l2_size_bytes: u64,
    pub l2_max_size_bytes: u64,
    pub filter_cache_entries: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InvalidateCacheResponse {
    pub status: String,
    pub message: String,
    pub l1_cleared: bool,
    pub l2_cleared: bool,
    pub filter_cache_cleared: bool,
}

/// The filter verdict cache is a `moka::sync` cache, so counting and clearing
/// it blocks while moka drains its housekeeping queue. That cache is on the
/// hot path of every DNS lookup, so keep those calls off the runtime workers.
async fn with_filter_cache<T, F>(state: &ApiState, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce(&BlocklistUpdater) -> T + Send + 'static,
{
    let updater = state.updater.clone();
    tokio::task::spawn_blocking(move || f(&updater)).await.ok()
}

async fn get_cache_stats(State(state): State<ApiState>) -> Json<CacheStatsResponse> {
    let conf = state.config.load();
    let l1_max_entries = conf.cache_l1_max_entries;
    let l2_max_size_bytes = conf.cache_l2_max_size_mb.saturating_mul(1024 * 1024);

    // moka refreshes `entry_count`/`weighted_size` only while draining its
    // housekeeping queue, so an idle L2 would otherwise report totals from
    // before the last invalidation or insert burst.
    state.l2_cache.run_pending_tasks().await;
    let filter_cache_entries =
        with_filter_cache(&state, |updater| updater.filter_cache_entry_count())
            .await
            .unwrap_or(0);

    let l1 = state.l1_cache.clone();
    let l1_entries = tokio::task::spawn_blocking(move || l1.live_len())
        .await
        .unwrap_or(0);
    Json(CacheStatsResponse {
        l1_entries,
        l1_max_entries,
        l2_entries: state.l2_cache.entry_count(),
        l2_size_bytes: state.l2_cache.weighted_size(),
        l2_max_size_bytes,
        filter_cache_entries,
    })
}

async fn invalidate_caches(State(state): State<ApiState>) -> Json<InvalidateCacheResponse> {
    state.l1_cache.clear();
    state.l2_cache.clear().await;
    let filter_cache_cleared = with_filter_cache(&state, |updater| updater.clear_filter_cache())
        .await
        .is_some();
    info!("All DNS resolver (L1, L2) and filter verdict caches invalidated via Admin API");

    Json(InvalidateCacheResponse {
        status: "success".to_string(),
        message: "All DNS resolver and filter verdict caches have been invalidated successfully"
            .to_string(),
        l1_cleared: true,
        l2_cleared: true,
        filter_cache_cleared,
    })
}

async fn get_config(State(state): State<ApiState>) -> Json<Config> {
    let mut config = (*state.config.load()).clone();
    config.api_key = "********".to_string();
    if config.api_token_sha256.is_some() {
        config.api_token_sha256 = Some("********".to_string());
    }
    Json(config)
}

#[derive(Serialize, Deserialize)]
struct DohConfigDto {
    pub encrypted_upstream_enabled: bool,
    #[serde(default)]
    pub encrypted_upstream_allow_plaintext_fallback: bool,
    pub encrypted_upstream_url: String,
    pub doh_upstreams: Vec<String>,
}

async fn get_doh_config(State(state): State<ApiState>) -> Json<DohConfigDto> {
    let config = state.config.load();
    Json(DohConfigDto {
        encrypted_upstream_enabled: config.encrypted_upstream_enabled,
        encrypted_upstream_allow_plaintext_fallback: config
            .encrypted_upstream_allow_plaintext_fallback,
        encrypted_upstream_url: config.encrypted_upstream_url.clone(),
        doh_upstreams: config.doh_upstreams.clone(),
    })
}

async fn update_doh_config(
    State(state): State<ApiState>,
    Json(payload): Json<DohConfigDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let replacement = if payload.encrypted_upstream_enabled {
        Some(Arc::new(
            core_dns::doh::DohClient::new(payload.encrypted_upstream_url.clone()).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?,
        ))
    } else {
        None
    };

    state
        .config
        .update("api:doh", |config| {
            config.encrypted_upstream_enabled = payload.encrypted_upstream_enabled;
            config.encrypted_upstream_allow_plaintext_fallback =
                payload.encrypted_upstream_allow_plaintext_fallback;
            config.encrypted_upstream_url = payload.encrypted_upstream_url;
            config.doh_upstreams = payload.doh_upstreams;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist DoH config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    state.doh_client.store(replacement);

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Serialize, Deserialize)]
struct SafeSearchConfigDto {
    pub enforce_safesearch: bool,
}

async fn get_safesearch_config(State(state): State<ApiState>) -> Json<SafeSearchConfigDto> {
    let config = state.config.load();
    Json(SafeSearchConfigDto {
        enforce_safesearch: config.enforce_safesearch,
    })
}

async fn update_safesearch_config(
    State(state): State<ApiState>,
    Json(payload): Json<SafeSearchConfigDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:safesearch", |config| {
            config.enforce_safesearch = payload.enforce_safesearch;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist SafeSearch config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn live_tail(State(state): State<ApiState>) -> impl IntoResponse {
    let logger = match state.logger {
        Some(ref l) => l.clone(),
        None => {
            return (StatusCode::BAD_REQUEST, "Logging is disabled").into_response();
        }
    };

    let broadcast_rx = logger.subscribe();

    let stream = tokio_stream::wrappers::BroadcastStream::new(broadcast_rx)
        .map(|item| -> Result<Event, std::convert::Infallible> {
            match item {
                Ok(entry) => {
                    let json = serde_json::json!({
                        "timestamp": entry.timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_millis(),
                        "client_ip": entry.client_ip.to_string(),
                        "name": entry.name,
                        "qtype": entry.qtype.to_string(),
                        "response_code": entry.response_code.to_string(),
                        "duration_ns": entry.duration_ns,
                        "verdict": format!("{:?}", entry.verdict),
                    });
                    Ok(Event::default().json_data(json).unwrap_or_else(|_| Event::default().data("error")))
                }
                Err(_) => {
                    Ok(Event::default().data("lag"))
                }
            }
        });

    // Flush a comment immediately so EventSource can report its connection
    // before the first DNS query or the periodic keep-alive arrives.
    let stream = tokio_stream::once(Ok(Event::default().comment("connected"))).chain(stream);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn get_auto_blocked(
    State(state): State<ApiState>,
) -> Result<Json<AutoBlockedResponse>, (StatusCode, Json<ErrorResponse>)> {
    let set = state.updater.auto_denies.lock().await;
    let mut domains: Vec<String> = set.iter().cloned().collect();
    domains.sort();
    Ok(Json(AutoBlockedResponse {
        count: domains.len(),
        domains,
    }))
}

async fn remove_auto_blocked(
    State(state): State<ApiState>,
    Json(payload): Json<LocalRuleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pattern = validate_local_pattern(&payload.pattern)?;
    if !state
        .updater
        .remove_auto_deny(&pattern)
        .await
        .map_err(rule_persistence_error)?
    {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Domain is not auto-blocked".to_string(),
            }),
        ));
    }

    if let Err(e) = state.updater.rebuild_snapshot().await {
        error!("Failed to reload engine after auto-block removal: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reload engine snapshot".to_string(),
            }),
        ));
    }

    if let Ok(name) = Name::from_str(&pattern) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

pub async fn start_admin_api(
    config: Arc<ConfigHandle>,
    updater: Arc<BlocklistUpdater>,
    l1_cache: Arc<L1Cache>,
    l2_cache: L2Cache,
    logger: Option<Arc<QueryLogger>>,
    network_tracker: Arc<core_dns::network::NetworkTracker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    start_admin_api_with_doh(
        config,
        updater,
        l1_cache,
        l2_cache,
        logger,
        network_tracker,
        Arc::new(ArcSwapOption::new(None)),
    )
    .await
}

/// The external JSON API under `/api/v1/*`, authenticated by
/// `auth_middleware` only; the dashboard and static assets merged
/// afterwards are unaffected.
#[cfg(feature = "feat-json-api")]
fn json_api_routes(state: ApiState) -> Router<ApiState> {
    Router::new()
        .route("/api/v1/stats", get(get_stats))
        .route("/api/v1/stats/top-blocked", get(get_top_blocked))
        .route("/api/v1/stats/top-clients", get(get_top_clients))
        .route(
            "/api/v1/stats/queries-over-time",
            get(get_queries_over_time),
        )
        .route("/api/v1/stats/query-types", get(get_query_types))
        .route("/api/v1/stats/upstreams", get(get_upstreams_analytics))
        .route(
            "/api/v1/lists/allow",
            get(get_allow).post(add_allow).delete(remove_allow),
        )
        .route(
            "/api/v1/lists/deny",
            get(get_deny).post(add_deny).delete(remove_deny),
        )
        .route(
            "/api/v1/lists/regex-allow",
            get(get_regex_allow)
                .post(add_regex_allow)
                .delete(remove_regex_allow),
        )
        .route(
            "/api/v1/lists/regex-deny",
            get(get_regex_deny)
                .post(add_regex_deny)
                .delete(remove_regex_deny),
        )
        .route(
            "/api/v1/lists/auto-blocked",
            get(get_auto_blocked).delete(remove_auto_blocked),
        )
        .route(
            "/api/v1/lists/malicious-ips",
            get(get_malicious_ips)
                .post(add_malicious_ip)
                .delete(remove_malicious_ip),
        )
        .route("/api/v1/lists/sources/status", get(get_sources_status))
        .route("/api/v1/lists/sources/sync", post(sync_sources))
        .route("/api/v1/lists/sources/invalidate", post(invalidate_source))
        .route("/api/v1/lists/summary", get(get_lists_summary))
        .route("/api/v1/config", get(get_config))
        .route("/api/v1/config/password", post(update_password))
        .route(
            "/api/v1/auth/token",
            post(create_api_token).delete(revoke_api_token),
        )
        .route(
            "/api/v1/config/doh",
            get(get_doh_config).post(update_doh_config),
        )
        .route(
            "/api/v1/config/safesearch",
            get(get_safesearch_config).post(update_safesearch_config),
        )
        .route(
            "/api/v1/config/services",
            get(get_blocked_services).post(update_blocked_services),
        )
        .route(
            "/api/v1/config/blocklist",
            get(get_blocklist_config).post(update_blocklist_config),
        )
        .route(
            "/api/v1/config/detection",
            get(get_detection_config).post(update_detection_config),
        )
        .route(
            "/api/v1/config/resolver",
            get(get_resolver_config).post(update_resolver_config),
        )
        .route(
            "/api/v1/config/upstreams",
            get(get_upstreams_config).post(update_upstreams_config),
        )
        .route(
            "/api/v1/protection/settings",
            get(get_protection_settings).post(update_protection_settings),
        )
        .route("/api/v1/protection/status", get(get_protection_status))
        .route("/api/v1/protection/pause", post(pause_protection))
        .route("/api/v1/protection/resume", post(resume_protection))
        .route("/api/v1/network/devices", get(get_network_devices))
        .route(
            "/api/v1/network/device-blocking",
            get(get_device_blocking_config).post(update_device_blocking_config),
        )
        .route("/api/v1/network/policy", post(set_device_policy))
        .route(
            "/api/v1/network/schedules",
            get(get_schedules).post(add_schedule),
        )
        .route("/api/v1/network/schedules/{ip}", delete(delete_schedule))
        .route("/api/v1/network/aliases", get(get_aliases).post(add_alias))
        .route("/api/v1/network/aliases/{identifier}", delete(delete_alias))
        .route("/api/v1/logs", get(get_logs))
        .route("/api/v1/logs/export", get(export_logs))
        .route(
            "/api/v1/local-dns",
            get(get_local_dns)
                .post(add_local_dns)
                .delete(delete_local_dns),
        )
        .route("/api/v1/diagnostics", get(get_diagnostics))
        .route("/api/v1/diagnostics/probe", get(probe_domain))
        .route("/api/v1/tail", get(live_tail))
        .route(
            "/api/v1/cache",
            get(get_cache_stats).delete(invalidate_caches),
        )
        .route("/api/v1/cache/stats", get(get_cache_stats))
        .route("/api/v1/cache/invalidate", post(invalidate_caches))
        .route("/api/v1/cache/clear", post(invalidate_caches))
        // route_layer, not layer: unmatched paths must 404 rather than run
        // auth, since in an API-only build this router's fallback is the
        // server's fallback.
        .route_layer(middleware::from_fn_with_state(state, auth_middleware))
}

pub async fn start_admin_api_with_doh(
    config: Arc<ConfigHandle>,
    updater: Arc<BlocklistUpdater>,
    l1_cache: Arc<L1Cache>,
    l2_cache: L2Cache,
    logger: Option<Arc<QueryLogger>>,
    network_tracker: Arc<core_dns::network::NetworkTracker>,
    doh_client: Arc<ArcSwapOption<core_dns::doh::DohClient>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (enabled, port, bind_addr_str, api_qps_limit, db_path_str) = {
        let c = config.load();
        (
            c.api_enabled,
            c.api_port,
            c.api_bind_address.clone(),
            c.api_ratelimit_qps,
            c.logging_db_path.clone(),
        )
    };

    if !enabled {
        return Ok(());
    }

    let rate_limiter = Arc::new(tokio::sync::Mutex::new(ApiRateLimiterState {
        hits: HashMap::new(),
        qps_limit: api_qps_limit,
        login_hits: HashMap::new(),
    }));

    let db_path = PathBuf::from(&db_path_str);

    // An explicit startup override lets existing state databases migrate to
    // an HTTPS proxy without temporarily enabling insecure administration.
    let proxy_cidrs = match std::env::var("DNS_API_TRUSTED_PROXY_CIDRS") {
        Ok(value) => value
            .split(',')
            .map(|cidr| cidr.trim().to_owned())
            .collect(),
        Err(std::env::VarError::NotPresent) => config.load().api_trusted_proxy_cidrs.clone(),
        Err(error) => return Err(error.into()),
    };
    let trusted_proxy_nets = Arc::new(
        proxy_cidrs
            .iter()
            .map(|cidr| cidr.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?,
    );

    updater.bind_config(config.clone()).await?;
    let api_state = ApiState {
        config,
        updater,
        l1_cache,
        l2_cache,
        logger,
        db_path,
        rate_limiter,
        network_tracker,
        sessions: Arc::new(SessionStore::default()),
        doh_client,
        stats_cache: Arc::new(StatsCache::default()),
        password_work: Arc::new(tokio::sync::Semaphore::new(2)),
        trusted_proxy_nets,
    };

    let app = Router::new();
    #[cfg(feature = "feat-json-api")]
    let app = app.merge(json_api_routes(api_state.clone()));
    // Browser rendering/actions have their own session-only guard. Static
    // assets exist only for the dashboard.
    #[cfg(feature = "feat-web-ui")]
    let app = app
        .merge(web::routes(api_state.clone()))
        .fallback_service(ServeDir::new(static_dir()));
    let app = app
        // Applied after the fallback is attached: Router::layer only wraps
        // the fallback set at the time it's called, and the static asset
        // tree must be throttled too.
        .layer(middleware::from_fn_with_state(
            api_state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            api_state.clone(),
            require_https_middleware,
        ))
        // Outermost so the headers land on every response -- API JSON, static
        // assets, and error responses generated by the layers below alike.
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(api_state);

    let listen_addr: SocketAddr = format!("{}:{}", bind_addr_str, port).parse()?;
    info!(
        "Starting Admin API server listening on http://{}",
        listen_addr
    );

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            error!("Admin API server serve error: {:?}", e);
        }
    });

    Ok(())
}

async fn get_malicious_ips(
    State(state): State<ApiState>,
) -> Result<Json<MaliciousIpsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let set = state.updater.malicious_ips.lock().await;
    let mut ips: Vec<String> = set.iter().map(|ip| ip.to_string()).collect();
    ips.sort();
    Ok(Json(MaliciousIpsResponse {
        count: ips.len(),
        ips,
    }))
}

#[derive(Deserialize)]
struct AddMaliciousIpRequest {
    ip: String,
}

async fn add_malicious_ip(
    State(state): State<ApiState>,
    Json(payload): Json<AddMaliciousIpRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    if let Ok(ip) = payload.ip.parse::<std::net::IpAddr>() {
        state
            .updater
            .add_malicious_ips(vec![ip])
            .await
            .map_err(rule_persistence_error)?;
        Ok(Json(()))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid IP address".to_string(),
            }),
        ))
    }
}

#[derive(Deserialize)]
struct RemoveMaliciousIpRequest {
    ip: String,
}

async fn remove_malicious_ip(
    State(state): State<ApiState>,
    Json(payload): Json<RemoveMaliciousIpRequest>,
) -> Result<Json<()>, (StatusCode, Json<ErrorResponse>)> {
    if let Ok(ip) = payload.ip.parse::<std::net::IpAddr>() {
        state
            .updater
            .remove_malicious_ip(&ip)
            .await
            .map_err(rule_persistence_error)?;
        Ok(Json(()))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid IP address".to_string(),
            }),
        ))
    }
}

async fn get_network_devices(
    State(state): State<ApiState>,
) -> Json<Vec<core_dns::network::DeviceInfo>> {
    let devices = state.network_tracker.get_devices().await;
    Json(devices)
}

#[derive(Serialize, Deserialize)]
struct DeviceBlockingConfigDto {
    pub device_blocking_enabled: bool,
}

async fn get_device_blocking_config(
    State(state): State<ApiState>,
) -> Json<DeviceBlockingConfigDto> {
    let conf = state.config.load();
    Json(DeviceBlockingConfigDto {
        device_blocking_enabled: conf.device_blocking_enabled,
    })
}

async fn update_device_blocking_config(
    State(state): State<ApiState>,
    Json(payload): Json<DeviceBlockingConfigDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:device-blocking", |conf| {
            conf.device_blocking_enabled = payload.device_blocking_enabled;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist device-blocking config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Deserialize)]
struct SetDevicePolicyRequest {
    ip: String,
    policy: String, // "block", "whitelist", or "default"
}

async fn set_device_policy(
    State(state): State<ApiState>,
    Json(payload): Json<SetDevicePolicyRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let policy = payload.policy.as_str();
    if policy != "block" && policy != "whitelist" && policy != "default" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Policy must be 'block', 'whitelist', or 'default'".to_string(),
            }),
        ));
    }

    let is_ip = payload.ip.parse::<std::net::IpAddr>().is_ok();
    let is_mac = MAC_ADDR_RE.is_match(&payload.ip);
    if !is_ip && !is_mac {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Identifier must be a valid IP or MAC address".to_string(),
            }),
        ));
    }

    // Store one canonical spelling (lowercase, `:`-separated MAC; standard
    // IP text) and drop any older entry for the same device spelled
    // differently, so there's never more than one policy per device.
    let identifier = core_dns::config::normalize_device_identifier(&payload.ip);
    state
        .config
        .update("api:device-policy", |cfg| {
            cfg.resume(&core_dns::config::PauseScope::Device(identifier.clone()));
            cfg.device_policies
                .retain(|id, _| core_dns::config::normalize_device_identifier(id) != identifier);
            cfg.device_policy_ip_overrides.remove(&identifier);
            if payload.policy == "whitelist" && identifier.parse::<std::net::IpAddr>().is_ok() {
                cfg.device_policy_ip_overrides
                    .insert(identifier.clone(), true);
            }
            if payload.policy != "default" {
                cfg.device_policies
                    .insert(identifier.clone(), payload.policy.clone());
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist device policy: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_schedules(
    State(state): State<ApiState>,
) -> Json<Vec<core_dns::config::DeviceSchedule>> {
    let cfg = state.config.load();
    Json(cfg.device_schedules.clone())
}

#[derive(Deserialize)]
struct AddScheduleRequest {
    ip: String,
    policy: String,
    days: Vec<String>,
    start_time: String,
    end_time: String,
}

async fn add_schedule(
    State(state): State<ApiState>,
    Json(payload): Json<AddScheduleRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.policy != "block" && payload.policy != "whitelist" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Policy must be 'block' or 'whitelist'".to_string(),
            }),
        ));
    }

    let is_ip = payload.ip.parse::<std::net::IpAddr>().is_ok();
    let is_mac = MAC_ADDR_RE.is_match(&payload.ip);
    if !is_ip && !is_mac {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Identifier must be a valid IP or MAC address".to_string(),
            }),
        ));
    }
    let validate_time = |s: &str| -> bool {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
        parts[0].parse::<u32>().map(|h| h < 24).unwrap_or(false)
            && parts[1].parse::<u32>().map(|m| m < 60).unwrap_or(false)
    };
    if !validate_time(&payload.start_time) || !validate_time(&payload.end_time) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Times must be in HH:MM 24-hour format".to_string(),
            }),
        ));
    }
    let valid_days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    for d in &payload.days {
        if !valid_days.contains(&d.to_lowercase().as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid day: '{d}'."),
                }),
            ));
        }
    }

    let schedule = core_dns::config::DeviceSchedule {
        ip: core_dns::config::normalize_device_identifier(&payload.ip),
        policy: payload.policy,
        days: payload.days,
        start_time: payload.start_time,
        end_time: payload.end_time,
    };

    state
        .config
        .update("api:device-schedule-add", |cfg| {
            cfg.device_schedules.push(schedule);
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist schedule: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn delete_schedule(
    State(state): State<ApiState>,
    axum::extract::Path(ip): axum::extract::Path<String>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:device-schedule-delete", |cfg| {
            let before = cfg.device_schedules.len();
            cfg.device_schedules
                .retain(|s| !core_dns::config::device_identifiers_match(&s.ip, &ip));
            let removed = before - cfg.device_schedules.len();
            if removed == 0 {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("No schedules found for IP '{ip}'"),
                ));
            }
            Ok::<(), (StatusCode, String)>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation((status, msg)) => {
                (status, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist schedule deletion: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Deserialize)]
struct AddAliasRequest {
    identifier: String, // IP or MAC address
    name: String,
}

async fn get_aliases(State(state): State<ApiState>) -> Json<Vec<core_dns::config::ClientAlias>> {
    let cfg = state.config.load();
    Json(cfg.client_aliases.clone())
}

async fn add_alias(
    State(state): State<ApiState>,
    Json(payload): Json<AddAliasRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Alias name cannot be empty".to_string(),
            }),
        ));
    }

    let is_ip = payload.identifier.parse::<std::net::IpAddr>().is_ok();
    let is_mac = MAC_ADDR_RE.is_match(&payload.identifier);
    if !is_ip && !is_mac {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Identifier must be a valid IP or MAC address".to_string(),
            }),
        ));
    }

    let identifier = core_dns::config::normalize_device_identifier(&payload.identifier);
    state
        .config
        .update("api:client-alias-add", |cfg| {
            cfg.client_aliases.retain(|a| {
                !core_dns::config::device_identifiers_match(&a.identifier, &identifier)
            });
            cfg.client_aliases.push(core_dns::config::ClientAlias {
                identifier: identifier.clone(),
                name: payload.name.trim().to_string(),
            });
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist client alias: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn delete_alias(
    State(state): State<ApiState>,
    axum::extract::Path(identifier): axum::extract::Path<String>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:client-alias-delete", |cfg| {
            let before = cfg.client_aliases.len();
            cfg.client_aliases.retain(|a| {
                !core_dns::config::device_identifiers_match(&a.identifier, &identifier)
            });
            let removed = before - cfg.client_aliases.len();
            if removed == 0 {
                return Err((
                    StatusCode::NOT_FOUND,
                    format!("No alias found for identifier '{identifier}'"),
                ));
            }
            Ok::<(), (StatusCode, String)>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation((status, msg)) => {
                (status, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist client alias deletion: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_local_dns(
    State(state): State<ApiState>,
) -> Json<Vec<core_dns::config::LocalDnsRecord>> {
    let config = state.config.load();
    Json(config.local_dns_records.clone())
}

#[derive(Deserialize)]
struct AddLocalDnsRequest {
    name: String,
    record_type: String,
    value: String,
}

async fn add_local_dns(
    State(state): State<ApiState>,
    Json(payload): Json<AddLocalDnsRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.name.trim().is_empty() || payload.value.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Name and value cannot be empty".to_string(),
            }),
        ));
    }

    let record_type = payload.record_type.to_uppercase();
    if record_type != "A" && record_type != "AAAA" && record_type != "CNAME" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid record type. Must be A, AAAA, or CNAME".to_string(),
            }),
        ));
    }

    if (record_type == "A"
        && <std::net::Ipv4Addr as std::str::FromStr>::from_str(&payload.value).is_err())
        || (record_type == "AAAA"
            && <std::net::Ipv6Addr as std::str::FromStr>::from_str(&payload.value).is_err())
        || (record_type == "CNAME" && hickory_proto::rr::Name::from_str(&payload.value).is_err())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid {} record value", record_type),
            }),
        ));
    }

    let new_rec = core_dns::config::LocalDnsRecord {
        name: payload.name.trim().to_string(),
        record_type,
        value: payload.value.clone(),
    };

    state
        .config
        .update("api:local-dns-add", |config| {
            if config
                .local_dns_records
                .iter()
                .any(|r| r.name == new_rec.name && r.record_type == new_rec.record_type)
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Record with this name and type already exists".to_string(),
                ));
            }
            config.local_dns_records.push(new_rec);
            if let Err(error) = config.validate_local_dns_records() {
                return Err((StatusCode::BAD_REQUEST, error));
            }
            Ok::<(), (StatusCode, String)>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation((status, msg)) => {
                (status, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist local DNS record: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    if let Ok(name) = Name::from_str(&payload.name) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Deserialize)]
struct DeleteLocalDnsRequest {
    name: String,
    record_type: String,
}

async fn delete_local_dns(
    State(state): State<ApiState>,
    Json(payload): Json<DeleteLocalDnsRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:local-dns-delete", |config| {
            let initial_len = config.local_dns_records.len();
            config.local_dns_records.retain(|r| {
                !(r.name.eq_ignore_ascii_case(&payload.name)
                    && r.record_type.eq_ignore_ascii_case(&payload.record_type))
            });
            if config.local_dns_records.len() == initial_len {
                return Err((StatusCode::NOT_FOUND, "Record not found".to_string()));
            }
            Ok::<(), (StatusCode, String)>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation((status, msg)) => {
                (status, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist local DNS deletion: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    if let Ok(name) = Name::from_str(&payload.name) {
        state.l1_cache.invalidate_by_name(&name);
        state.l2_cache.invalidate_by_name(&name);
    }

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}
async fn get_top_blocked(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::All)?;
    stats_response(&state, "top-blocked", window, move |conn, now| {
        let rows = log_stats::top(conn, window, log_stats::DIM_BLOCKED_DOMAIN, 20, now)?;
        Ok(TopBlockedResponse {
            domains: domain_counts(rows),
        })
    })
    .await
}

async fn get_top_clients(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::All)?;
    stats_response(&state, "top-clients", window, move |conn, now| {
        let rows = log_stats::top(conn, window, log_stats::DIM_CLIENT, 20, now)?;
        Ok(TopClientsResponse {
            clients: client_counts(rows),
        })
    })
    .await
}

// 24h/7d use hourly buckets; all retained history uses daily buckets.
async fn get_queries_over_time(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::Last24h)?;
    let label_format = if window == Window::All {
        "%Y-%m-%d"
    } else {
        "%Y-%m-%d %H:00"
    };
    stats_response(&state, "queries-over-time", window, move |conn, now| {
        let buckets = log_stats::buckets(conn, window, now)?
            .into_iter()
            .map(|bucket| QueryBucket {
                hour: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(bucket.start_ms)
                    .map(|dt| dt.format(label_format).to_string())
                    .unwrap_or_default(),
                start_ms: bucket.start_ms,
                total: bucket.total,
                blocked: bucket.blocked,
            })
            .collect();
        Ok(QueriesOverTimeResponse { buckets })
    })
    .await
}

#[derive(Deserialize)]
struct LogQueryRequest {
    q: Option<String>,
    verdict: Option<String>,
    client: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Clone, Serialize, Deserialize)]
struct HistoricalLogEntry {
    timestamp: i64,
    client_ip: String,
    name: String,
    qtype: String,
    response_code: String,
    duration_ns: u64,
    verdict: String,
    #[serde(default)]
    resolver: String,
}

#[derive(Serialize)]
struct HistoricalLogsResponse {
    count: usize,
    logs: Vec<HistoricalLogEntry>,
}

fn fetch_historical_logs_internal(
    db_path: &std::path::Path,
    filter: LogQueryRequest,
) -> Result<Vec<HistoricalLogEntry>, rusqlite::Error> {
    // Legacy schemas are migrated by the logger at startup; readers need no write access.
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut table_names: Vec<String> = rows
        .filter_map(Result::ok)
        .filter(|table| logger::stats::is_partition_name(table))
        .collect();
    // Newest partition first: each partition holds one UTC day, so once
    // enough rows have been collected no older partition can contribute a
    // newer one and the remaining partitions can be skipped entirely.
    // Only validated partition names can become SQL identifiers.
    table_names.sort_by_key(|table| std::cmp::Reverse(partition_date(table)));

    let mut skip = filter.offset.unwrap_or(0);
    // Bounds memory: at most `limit` rows are ever held.
    let limit = filter.limit.unwrap_or(100).min(50_000);

    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref search) = filter.q
        && !search.trim().is_empty()
    {
        conditions.push("name LIKE ?".to_string());
        params.push(Box::new(format!("%{}%", search.trim())));
    }

    if let Some(ref v) = filter.verdict {
        if v == "Block" {
            conditions.push("verdict = 'Block'".to_string());
        } else if v == "Pass" {
            conditions.push("verdict != 'Block'".to_string());
        }
    }

    if let Some(ref c) = filter.client
        && !c.trim().is_empty()
    {
        conditions.push("client_ip = ?".to_string());
        params.push(Box::new(c.trim().to_string()));
    }

    let where_clause = if conditions.is_empty() {
        "".to_string()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let filter_params: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    // Partitions are keyed by each entry's own UTC date, so they cover
    // disjoint time ranges and newest-first partition order is also global
    // timestamp order. Whole partitions inside the offset are skipped by
    // count, and the page is read with OFFSET from the partition it starts
    // in. That is exact at any depth, unlike merging per-table top-N windows.
    let mut logs = Vec::new();
    for table in table_names {
        if logs.len() >= limit {
            break;
        }
        if skip > 0 {
            let count: i64 = conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} {where_clause}"),
                &filter_params[..],
                |row| row.get(0),
            )?;
            let count = usize::try_from(count).unwrap_or(0);
            if count <= skip {
                skip -= count;
                continue;
            }
        }

        let remaining = (limit - logs.len()) as i64;
        let offset = i64::try_from(skip).unwrap_or(i64::MAX);
        skip = 0;
        let mut page_params = filter_params.clone();
        page_params.push(&remaining);
        page_params.push(&offset);

        let sql = format!(
            "SELECT timestamp, client_ip, name, qtype, response_code, duration_ns, verdict, resolver
             FROM {table} {where_clause}
             ORDER BY timestamp DESC, rowid DESC
             LIMIT ? OFFSET ?"
        );
        let mut query_stmt = conn.prepare(&sql)?;
        let log_rows = query_stmt.query_map(&page_params[..], |row| {
            Ok(HistoricalLogEntry {
                timestamp: row.get(0)?,
                client_ip: row.get(1)?,
                name: row.get(2)?,
                qtype: row.get(3)?,
                response_code: row.get(4)?,
                duration_ns: row.get::<_, i64>(5)? as u64,
                verdict: row.get(6)?,
                resolver: row.get(7)?,
            })
        })?;
        logs.extend(log_rows.flatten());
    }

    Ok(logs)
}

#[cfg(test)]
mod history_pagination_tests {
    use super::*;

    fn seed() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(file.path()).unwrap();
        // Two UTC days, five rows each. Odd rows are blocked.
        for (table, day_start) in [
            ("logs_2024_01_01", 1_704_067_200_000_i64),
            ("logs_2024_01_02", 1_704_153_600_000_i64),
        ] {
            conn.execute_batch(&format!(
                "CREATE TABLE {table} (timestamp INTEGER NOT NULL, client_ip TEXT NOT NULL,
                 name TEXT NOT NULL, qtype TEXT NOT NULL, response_code TEXT NOT NULL,
                 duration_ns INTEGER NOT NULL, verdict TEXT NOT NULL, resolver TEXT NOT NULL)"
            ))
            .unwrap();
            for index in 0..5_i64 {
                conn.execute(
                    &format!("INSERT INTO {table} VALUES (?1, '10.0.0.1', ?2, 'A', 'NoError', 1, ?3, 'up')"),
                    rusqlite::params![
                        day_start + index,
                        format!("{table}-{index}.test"),
                        if index % 2 == 1 { "Block" } else { "Pass" }
                    ],
                )
                .unwrap();
            }
        }
        file
    }

    fn page(
        file: &tempfile::NamedTempFile,
        verdict: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Vec<String> {
        fetch_historical_logs_internal(
            file.path(),
            LogQueryRequest {
                q: None,
                verdict: verdict.map(str::to_owned),
                client: None,
                limit: Some(limit),
                offset: Some(offset),
            },
        )
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect()
    }

    #[test]
    fn offsets_cross_partition_boundaries_in_timestamp_order() {
        let file = seed();
        assert_eq!(
            page(&file, None, 3, 4),
            [
                "logs_2024_01_02-1.test",
                "logs_2024_01_02-0.test",
                "logs_2024_01_01-4.test",
                "logs_2024_01_01-3.test"
            ]
        );
        assert_eq!(page(&file, None, 5, 1), ["logs_2024_01_01-4.test"]);
        assert!(page(&file, None, 10, 5).is_empty());
    }

    #[test]
    fn skipped_partitions_are_counted_with_the_active_filter() {
        let file = seed();
        // Two blocked rows per day: skipping two lands on the older day.
        assert_eq!(
            page(&file, Some("Block"), 2, 5),
            ["logs_2024_01_01-3.test", "logs_2024_01_01-1.test"]
        );
    }
}

async fn get_logs(
    State(state): State<ApiState>,
    axum::extract::Query(filter): axum::extract::Query<LogQueryRequest>,
) -> Result<Json<HistoricalLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Keep historical partition reads off runtime workers shared with DNS.
    let db_path = state.db_path.clone();
    let logs = db_blocking(move || fetch_historical_logs_internal(&db_path, filter)).await?;
    let count = logs.len();
    Ok(Json(HistoricalLogsResponse { count, logs }))
}

/// Escapes a CSV field: doubles embedded quotes, and neutralizes CSV/formula
/// injection by prefixing formula initiators and control/whitespace-prefixed
/// formulas with a single quote. Full-width initiators are included too.
/// Spreadsheet apps commonly treat this as text instead of a formula; CSV
/// consumers can vary and may remove the prefix when saving and reopening.
/// Query names are attacker-controlled — any device on the network
/// can cause an arbitrary name to be logged — so this must not be skipped.
fn csv_escape(field: &str) -> String {
    let escaped = field.replace('"', "\"\"");
    let first = escaped.chars().next();
    let meaningful = escaped.trim_start_matches(|ch: char| ch.is_whitespace() || ch.is_control());
    if matches!(first, Some('\t' | '\r' | '\n'))
        || matches!(
            meaningful.chars().next(),
            Some('=' | '+' | '-' | '@' | '＝' | '＋' | '－' | '＠')
        )
    {
        format!("'{escaped}")
    } else {
        escaped
    }
}

async fn export_logs(
    State(state): State<ApiState>,
    axum::extract::Query(filter): axum::extract::Query<LogQueryRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let export_filter = LogQueryRequest {
        q: filter.q,
        verdict: filter.verdict,
        client: filter.client,
        limit: Some(10000),
        offset: Some(0),
    };

    let db_path = state.db_path.clone();
    let logs = db_blocking(move || fetch_historical_logs_internal(&db_path, export_filter)).await?;

    let mut csv_data = String::from(
        "Timestamp,Client IP,Query Domain,Record Type,Response Code,Duration (ns),Verdict,Resolver / Upstream\n",
    );
    for log in logs {
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(log.timestamp / 1000, 0)
            .unwrap_or_else(chrono::Utc::now);
        let time_str = dt.to_rfc3339();

        csv_data.push_str(&format!(
            "{},{},\"{}\",{},{},{},{},\"{}\"\n",
            time_str,
            log.client_ip,
            csv_escape(&log.name),
            log.qtype,
            log.response_code,
            log.duration_ns,
            log.verdict,
            csv_escape(&log.resolver)
        ));
    }

    let headers = [
        (axum::http::header::CONTENT_TYPE, "text/csv"),
        (
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"dns-deny-logs.csv\"",
        ),
    ];

    Ok((headers, csv_data))
}

#[derive(Serialize)]
struct BlockedServiceInfo {
    id: String,
    name: String,
    description: String,
    blocked: bool,
    is_custom: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    wildcards: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct BlockedServicesUpdateRequest {
    blocked_services: Vec<String>,
    #[serde(default)]
    custom_services: Vec<core_dns::config::CustomService>,
}

async fn get_blocked_services(State(state): State<ApiState>) -> Json<Vec<BlockedServiceInfo>> {
    let conf = state.config.load();
    let mut list: Vec<BlockedServiceInfo> = core_dns::services::BLOCKED_SERVICES
        .iter()
        .map(|s| BlockedServiceInfo {
            id: s.id.to_string(),
            name: s.name.to_string(),
            description: s.description.to_string(),
            blocked: conf.blocked_services.contains(&s.id.to_string()),
            is_custom: false,
            wildcards: None,
        })
        .collect();

    for cs in &conf.custom_services {
        list.push(BlockedServiceInfo {
            id: cs.id.clone(),
            name: cs.name.clone(),
            description: cs.description.clone(),
            blocked: cs.enabled,
            is_custom: true,
            wildcards: Some(cs.wildcards.clone()),
        });
    }

    Json(list)
}

async fn update_blocked_services(
    State(state): State<ApiState>,
    Json(payload): Json<BlockedServicesUpdateRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:blocked-services", |conf| {
            conf.blocked_services = payload.blocked_services;
            conf.custom_services = payload.custom_services;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to save config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist service block state".to_string(),
                    }),
                )
            }
        })?;

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Serialize, Deserialize)]
struct BlocklistConfigDto {
    pub blocklist_urls: Vec<String>,
    pub blocklist_categories: Vec<core_dns::config::BlocklistCategory>,
}

async fn get_blocklist_config(State(state): State<ApiState>) -> Json<BlocklistConfigDto> {
    let conf = state.config.load();
    Json(BlocklistConfigDto {
        blocklist_urls: conf.blocklist_urls.clone(),
        blocklist_categories: conf.blocklist_categories.clone(),
    })
}

async fn update_blocklist_config(
    State(state): State<ApiState>,
    Json(payload): Json<BlocklistConfigDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let commit = state
        .config
        .update("api:blocklist", |conf| {
            conf.blocklist_urls = payload.blocklist_urls;
            conf.blocklist_categories = payload.blocklist_categories;
            let active_urls = conf.active_blocklist_urls(core_dns::config::now_epoch());
            Ok::<Vec<String>, String>(active_urls)
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist blocklist config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    let _active_urls = commit.output;
    state
        .updater
        .ensure_current_sources()
        .await
        .map_err(|error| {
            error!("Failed to reconcile sources: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to publish filtering sources".into(),
                }),
            )
        })?;

    let updater_clone = state.updater.clone();
    let l1_cache = state.l1_cache.clone();
    let l2_cache = state.l2_cache.clone();
    tokio::spawn(async move {
        if let Err(e) = updater_clone.refresh().await {
            error!("Failed to refresh blocklist after config update: {:?}", e);
        } else {
            l1_cache.clear();
            l2_cache.clear().await;
        }
    });

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Serialize, Deserialize)]
struct DetectionConfigDto {
    pub smart_ip_blocking: bool,
    pub auto_block_upstream_sinkholes: bool,
    pub ml_scoring_enabled: bool,
}

async fn get_detection_config(State(state): State<ApiState>) -> Json<DetectionConfigDto> {
    let conf = state.config.load();
    Json(DetectionConfigDto {
        smart_ip_blocking: conf.smart_ip_blocking,
        auto_block_upstream_sinkholes: conf.auto_block_upstream_sinkholes,
        ml_scoring_enabled: conf.ml_scoring_enabled,
    })
}

async fn update_detection_config(
    State(state): State<ApiState>,
    Json(payload): Json<DetectionConfigDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:detection", |conf| {
            conf.smart_ip_blocking = payload.smart_ip_blocking;
            conf.auto_block_upstream_sinkholes = payload.auto_block_upstream_sinkholes;
            conf.ml_scoring_enabled = payload.ml_scoring_enabled;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist detection config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

// The resolver pool is built at startup; persisted upstream edits take
// effect after restart. Validate with the same rules used at startup.
#[derive(Serialize, Deserialize)]
struct UpstreamsConfigDto {
    pub upstreams: Vec<core_dns::config::UpstreamConfig>,
}

async fn get_upstreams_config(State(state): State<ApiState>) -> Json<UpstreamsConfigDto> {
    let conf = state.config.load();
    Json(UpstreamsConfigDto {
        upstreams: conf.upstreams.clone(),
    })
}

async fn update_upstreams_config(
    State(state): State<ApiState>,
    Json(payload): Json<UpstreamsConfigDto>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.upstreams.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "at least one upstream is required".to_string(),
            }),
        ));
    }

    for (i, upstream) in payload.upstreams.iter().enumerate() {
        if core_dns::config::parse_upstream_ip(&upstream.address).is_none() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "upstream[{}]: address '{}' is not a valid IP address",
                        i, upstream.address
                    ),
                }),
            ));
        }
        match upstream.protocol.as_str() {
            "udp" | "tcp" => {}
            "dot" | "doh" => {
                if upstream
                    .tls_sni
                    .as_ref()
                    .is_none_or(|s| s.trim().is_empty())
                {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: format!(
                                "upstream[{}]: protocol '{}' requires tls_sni to be set",
                                i, upstream.protocol
                            ),
                        }),
                    ));
                }
            }
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!(
                            "upstream[{}]: unknown protocol '{}' -- must be udp, tcp, dot, or doh",
                            i, other
                        ),
                    }),
                ));
            }
        }
    }

    state
        .config
        .update("api:upstreams", |conf| {
            conf.upstreams = payload.upstreams;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist upstream config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(ConfigUpdateResponse {
        status: "success".to_string(),
        restart_required: true,
        message: "Primary upstream changes take effect after restarting the server".to_string(),
    }))
}

#[derive(Serialize, Deserialize)]
struct ResolverConfigDto {
    pub recursive_resolver_enabled: bool,
}

async fn get_resolver_config(State(state): State<ApiState>) -> Json<ResolverConfigDto> {
    let conf = state.config.load();
    Json(ResolverConfigDto {
        recursive_resolver_enabled: conf.recursive_resolver_enabled,
    })
}

async fn update_resolver_config(
    State(state): State<ApiState>,
    Json(payload): Json<ResolverConfigDto>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .config
        .update("api:resolver", |conf| {
            conf.recursive_resolver_enabled = payload.recursive_resolver_enabled;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist resolver config: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    state.l1_cache.clear();
    state.l2_cache.clear().await;

    Ok(Json(ConfigUpdateResponse {
        status: "success".to_string(),
        restart_required: true,
        message: "Resolver mode changes take effect after restarting the server".to_string(),
    }))
}

fn parse_pause_scope(req: &ProtectionScopeRequest) -> Result<core_dns::config::PauseScope, String> {
    match req.scope.as_str() {
        "global" => Ok(core_dns::config::PauseScope::Global),
        "category" => req
            .id
            .clone()
            .map(core_dns::config::PauseScope::Category)
            .ok_or_else(|| "scope \"category\" requires an \"id\"".to_string()),
        "service" => req
            .id
            .clone()
            .map(core_dns::config::PauseScope::Service)
            .ok_or_else(|| "scope \"service\" requires an \"id\"".to_string()),
        "device" => {
            let id = req
                .id
                .as_deref()
                .ok_or("scope \"device\" requires an \"id\"")?;
            if !core_dns::policy::valid_device_identifier(id) {
                return Err("Device pause requires a valid IP or MAC".into());
            }
            Ok(core_dns::config::PauseScope::Device(
                core_dns::config::normalize_device_identifier(id),
            ))
        }
        other => Err(format!(
            "unknown scope \"{}\" -- must be global, category, service, or device",
            other
        )),
    }
}

#[derive(Serialize, Deserialize)]
struct ProtectionSettingsDto {
    pub protection_pause_default_duration_secs: u64,
}

async fn get_protection_settings(State(state): State<ApiState>) -> Json<ProtectionSettingsDto> {
    let conf = state.config.load();
    Json(ProtectionSettingsDto {
        protection_pause_default_duration_secs: conf.protection_pause_default_duration_secs,
    })
}

async fn update_protection_settings(
    State(state): State<ApiState>,
    Json(payload): Json<ProtectionSettingsDto>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.protection_pause_default_duration_secs == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "protection_pause_default_duration_secs must be > 0".to_string(),
            }),
        ));
    }

    state
        .config
        .update("api:protection-settings", |conf| {
            conf.protection_pause_default_duration_secs =
                payload.protection_pause_default_duration_secs;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist protection settings: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

async fn get_protection_status(State(state): State<ApiState>) -> Json<ProtectionStatusResponse> {
    let conf = state.config.load();
    let status = core_dns::protection::live_status(&conf, core_dns::config::now_epoch());
    Json(ProtectionStatusResponse {
        default_duration_secs: status.default_duration_secs,
        global_paused_until: status.global_paused_until,
        category_pauses: status.category_pauses,
        service_pauses: status.service_pauses,
        device_pauses: status.device_pauses,
    })
}

async fn pause_protection(
    State(state): State<ApiState>,
    Json(payload): Json<ProtectionScopeRequest>,
) -> Result<Json<ProtectionPauseResponse>, (StatusCode, Json<ErrorResponse>)> {
    let scope = parse_pause_scope(&payload)
        .map_err(|msg| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })))?;

    if let Some(secs) = payload.duration_secs
        && !payload.indefinite
        && (secs == 0 || secs > MAX_PAUSE_DURATION_SECS)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "duration_secs must be between 1 and {} -- use \"indefinite\": true to pause until resumed",
                    MAX_PAUSE_DURATION_SECS
                ),
            }),
        ));
    }

    let payload_scope = payload.scope.clone();
    let payload_id = match &scope {
        core_dns::config::PauseScope::Device(id) => Some(id.clone()),
        _ => payload.id.clone(),
    };
    let indefinite = payload.indefinite;
    let duration_secs = payload.duration_secs;

    let commit = state
        .config
        .update("api:protection-pause", |conf| {
            let now = core_dns::config::now_epoch();
            if matches!(scope, core_dns::config::PauseScope::Device(_)) {
                let seconds = duration_secs.unwrap_or(conf.protection_pause_default_duration_secs);
                if indefinite || !(1..=core_dns::config::MAX_DEVICE_PAUSE_DURATION_SECS).contains(&seconds) {
                    return Err((StatusCode::BAD_REQUEST, "Device pauses require a duration between 1 and 172800 seconds and cannot be indefinite".into()));
                }
            }

            if conf.is_paused(&scope, now) {
                return Err((
                    StatusCode::CONFLICT,
                    "already paused -- resume it first, or wait for it to expire".to_string(),
                ));
            }

            let paused_until = if indefinite {
                conf.pause_indefinitely(&scope)
            } else {
                conf.pause_for(&scope, now, duration_secs)
            };

            let active_urls = conf.active_blocklist_urls(now);
            Ok::<(i64, Vec<String>), (StatusCode, String)>((paused_until, active_urls))
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation((status, msg)) => {
                (status, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist protection pause: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    let (paused_until, _active_urls) = commit.output;

    if !matches!(scope, core_dns::config::PauseScope::Device(_)) {
        state.l1_cache.clear();
        state.l2_cache.clear().await;
    }

    if matches!(scope, core_dns::config::PauseScope::Category(_)) {
        state
            .updater
            .ensure_current_sources()
            .await
            .map_err(|error| {
                error!("Failed to publish category transition: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to publish category rules".into(),
                    }),
                )
            })?;
    }

    Ok(Json(ProtectionPauseResponse {
        status: "paused".to_string(),
        scope: payload_scope,
        id: payload_id,
        paused_until,
    }))
}

async fn resume_protection(
    State(state): State<ApiState>,
    Json(payload): Json<ProtectionScopeRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    let scope = parse_pause_scope(&payload)
        .map_err(|msg| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })))?;

    let commit = state
        .config
        .update("api:protection-resume", |conf| {
            conf.resume(&scope);
            let active_urls = conf.active_blocklist_urls(core_dns::config::now_epoch());
            Ok::<Vec<String>, String>(active_urls)
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to persist protection resume: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    let _active_urls = commit.output;

    if !matches!(scope, core_dns::config::PauseScope::Device(_)) {
        state.l1_cache.clear();
        state.l2_cache.clear().await;
    }

    if matches!(scope, core_dns::config::PauseScope::Category(_)) {
        state
            .updater
            .ensure_current_sources()
            .await
            .map_err(|error| {
                error!("Failed to publish category transition: {error}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to publish category rules".into(),
                    }),
                )
            })?;
    }

    Ok(Json(SuccessResponse {
        status: "resumed".to_string(),
    }))
}

#[derive(Serialize)]
struct QueryTypeCount {
    qtype: String,
    count: u64,
}

#[derive(Serialize)]
struct QueryTypesResponse {
    types: Vec<QueryTypeCount>,
}

async fn get_query_types(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::All)?;
    stats_response(&state, "query-types", window, move |conn, now| {
        let rows = log_stats::top(conn, window, log_stats::DIM_QTYPE, usize::MAX, now)?;
        Ok(QueryTypesResponse {
            types: rows
                .into_iter()
                .map(|(qtype, count)| QueryTypeCount { qtype, count })
                .collect(),
        })
    })
    .await
}

#[derive(Serialize)]
struct UpstreamCount {
    upstream: String,
    count: u64,
}

#[derive(Serialize)]
struct UpstreamsResponse {
    upstreams: Vec<UpstreamCount>,
}

async fn get_upstreams_analytics(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<WindowQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let window = parse_window(&query, Window::All)?;
    stats_response(&state, "upstreams", window, move |conn, now| {
        let rows = log_stats::top(conn, window, log_stats::DIM_RESOLVER, usize::MAX, now)?;
        Ok(UpstreamsResponse {
            upstreams: rows
                .into_iter()
                .map(|(upstream, count)| UpstreamCount { upstream, count })
                .collect(),
        })
    })
    .await
}

#[derive(Deserialize)]
struct UpdatePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn update_password(
    State(state): State<ApiState>,
    Json(payload): Json<UpdatePasswordRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Run bcrypt off the DNS runtime and before taking the config write lock
    // so CPU-bound hashing cannot stall queries or other admin edits.
    let api_key = state.config.load().api_key.clone();
    if !verify_api_key(&state, &payload.current_password, &api_key)
        .await
        .map_err(|status| {
            (
                status,
                Json(ErrorResponse {
                    error: "Password verification is busy. Try again shortly.".into(),
                }),
            )
        })?
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Incorrect current password".to_string(),
            }),
        ));
    }

    if payload.new_password.chars().count() < 8 || payload.new_password.len() > 72 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "New password must contain at least 8 characters and at most 72 UTF-8 bytes"
                    .to_string(),
            }),
        ));
    }

    let new_password = payload.new_password.clone();
    let hash_result = password_work(state.password_work.clone(), move || {
        bcrypt::hash(&new_password, bcrypt::DEFAULT_COST)
    })
    .await;

    let hashed = match hash_result {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            error!("Failed to hash new password: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to encrypt new password".to_string(),
                }),
            ));
        }
        Err(e) => {
            error!("Password hashing task failed: {:?}", e);
            return Err((
                e,
                Json(ErrorResponse {
                    error: "Failed to encrypt new password".to_string(),
                }),
            ));
        }
    };

    state
        .config
        .update("api:password", |cfg| {
            if cfg.api_key != api_key {
                return Err(
                    "The admin credential changed during this request. Sign in again.".to_string(),
                );
            }
            cfg.api_key = hashed;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| match e {
            ConfigUpdateError::Mutation(msg) | ConfigUpdateError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
            }
            ConfigUpdateError::Persistence(e) => {
                error!("Failed to save config with new password: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Failed to persist configuration".to_string(),
                    }),
                )
            }
        })?;

    // Every session was authenticated against the *old* credential, so none
    // of them should outlive it. Revocation happens only after publication succeeds.
    state.sessions.revoke_all();

    Ok(Json(SuccessResponse {
        status: "success".to_string(),
    }))
}

#[derive(Serialize)]
struct DiagnosticComponent {
    name: String,
    status: String, // "pass", "warn", "fail", "info"
    message: String,
    details: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct DiagnosticsResponse {
    status: String,
    timestamp: u64,
    components: Vec<DiagnosticComponent>,
}

async fn get_diagnostics(
    State(state): State<ApiState>,
) -> Result<Json<DiagnosticsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let conf = state.config.load();
    let mut components = Vec::new();
    let mut overall_has_warning = false;
    let mut overall_has_failure = false;

    let mut core_details = HashMap::new();
    core_details.insert(
        "dnssec_validation".to_string(),
        serde_json::json!(conf.dnssec_validation),
    );
    core_details.insert(
        "ratelimit_qps_per_worker".to_string(),
        serde_json::json!(conf.ratelimit_qps_per_worker),
    );
    core_details.insert(
        "ratelimit_max_ips".to_string(),
        serde_json::json!(conf.ratelimit_max_ips),
    );
    components.push(DiagnosticComponent {
        name: "DNS Engine & Protocol Listener".to_string(),
        status: "pass".to_string(),
        message: format!(
            "DNS engine active. Rate limit configured for {} global QPS per client.",
            conf.ratelimit_qps_per_worker
        ),
        details: core_details,
    });

    let mut upstream_details = HashMap::new();
    let mut reachable_upstreams = 0;
    let mut upstream_list = Vec::new();

    for up in &conf.upstreams {
        let is_reachable = if let Ok(addr) = up.address.parse::<SocketAddr>() {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok()
        } else {
            true
        };
        if is_reachable {
            reachable_upstreams += 1;
        }
        upstream_list.push(serde_json::json!({
            "address": up.address,
            "protocol": up.protocol,
            "tls_sni": up.tls_sni,
            "reachable": is_reachable,
        }));
    }
    upstream_details.insert("upstreams".to_string(), serde_json::json!(upstream_list));

    let (up_status, up_msg) = if conf.upstreams.is_empty() {
        overall_has_failure = true;
        (
            "fail".to_string(),
            "No upstream resolvers configured!".to_string(),
        )
    } else if reachable_upstreams == 0 && !conf.upstreams.is_empty() {
        overall_has_warning = true;
        (
            "warn".to_string(),
            format!(
                "Configured {} upstreams, but probe timeout occurred.",
                conf.upstreams.len()
            ),
        )
    } else {
        (
            "pass".to_string(),
            format!(
                "{} of {} upstream resolvers responded.",
                reachable_upstreams,
                conf.upstreams.len()
            ),
        )
    };

    components.push(DiagnosticComponent {
        name: "Upstream Resolvers".to_string(),
        status: up_status,
        message: up_msg,
        details: upstream_details,
    });

    let loaded_rules = state.updater.total_rules_count().await;
    let mut filter_details = HashMap::new();
    filter_details.insert("total_rules".to_string(), serde_json::json!(loaded_rules));
    filter_details.insert(
        "blocklist_urls_count".to_string(),
        serde_json::json!(conf.blocklist_urls.len()),
    );
    filter_details.insert(
        "categories_count".to_string(),
        serde_json::json!(conf.blocklist_categories.len()),
    );
    let enabled_categories = conf
        .blocklist_categories
        .iter()
        .filter(|c| c.enabled)
        .count();
    filter_details.insert(
        "enabled_categories_count".to_string(),
        serde_json::json!(enabled_categories),
    );

    let (filter_status, filter_msg) = if loaded_rules == 0 {
        overall_has_warning = true;
        (
            "warn".to_string(),
            "Filter engine is active but 0 blocklist rules are loaded.".to_string(),
        )
    } else {
        (
            "pass".to_string(),
            format!(
                "Filter engine operational with {} active rules across {} categories.",
                loaded_rules, enabled_categories
            ),
        )
    };

    components.push(DiagnosticComponent {
        name: "Filter Engine & Blocklists".to_string(),
        status: filter_status,
        message: filter_msg,
        details: filter_details,
    });

    let mut cache_details = HashMap::new();
    cache_details.insert(
        "l1_max_entries".to_string(),
        serde_json::json!(conf.cache_l1_max_entries),
    );
    cache_details.insert(
        "l2_max_size_mb".to_string(),
        serde_json::json!(conf.cache_l2_max_size_mb),
    );
    cache_details.insert(
        "negative_ttl_fallback_secs".to_string(),
        serde_json::json!(conf.cache_negative_ttl_fallback_secs),
    );
    components.push(DiagnosticComponent {
        name: "Cache Subsystem (L1 & L2)".to_string(),
        status: "pass".to_string(),
        message: format!(
            "L1 & L2 memory caches active (L2 max: {} MB).",
            conf.cache_l2_max_size_mb
        ),
        details: cache_details,
    });

    let mut logger_details = HashMap::new();
    logger_details.insert(
        "logging_enabled".to_string(),
        serde_json::json!(conf.logging_enabled),
    );
    logger_details.insert(
        "db_path".to_string(),
        serde_json::json!(conf.logging_db_path),
    );
    logger_details.insert(
        "retention_days".to_string(),
        serde_json::json!(conf.logging_retention_days),
    );

    let (log_status, log_msg) = if conf.logging_enabled {
        let db_file = std::path::Path::new(&conf.logging_db_path);
        let db_size = db_file.metadata().map(|m| m.len()).unwrap_or(0);
        logger_details.insert("db_size_bytes".to_string(), serde_json::json!(db_size));
        (
            "pass".to_string(),
            format!(
                "Async SQLite logging active at '{}' (Retention: {} days).",
                conf.logging_db_path, conf.logging_retention_days
            ),
        )
    } else {
        (
            "info".to_string(),
            "Query logging is currently disabled.".to_string(),
        )
    };

    components.push(DiagnosticComponent {
        name: "Query Logging & SQLite Database".to_string(),
        status: log_status,
        message: log_msg,
        details: logger_details,
    });

    let mut ss_details = HashMap::new();
    ss_details.insert(
        "enforce_safesearch".to_string(),
        serde_json::json!(conf.enforce_safesearch),
    );
    components.push(DiagnosticComponent {
        name: "SafeSearch Enforcement".to_string(),
        status: if conf.enforce_safesearch {
            "pass".to_string()
        } else {
            "info".to_string()
        },
        message: if conf.enforce_safesearch {
            "Network-wide SafeSearch enforcement is ACTIVE for Google, YouTube, and Bing."
                .to_string()
        } else {
            "SafeSearch enforcement is currently disabled.".to_string()
        },
        details: ss_details,
    });

    let devices = state.network_tracker.get_devices().await;
    let mut dev_details = HashMap::new();
    dev_details.insert(
        "device_blocking_enabled".to_string(),
        serde_json::json!(conf.device_blocking_enabled),
    );
    dev_details.insert(
        "tracked_arp_devices".to_string(),
        serde_json::json!(devices.len()),
    );
    dev_details.insert(
        "active_schedules".to_string(),
        serde_json::json!(conf.device_schedules.len()),
    );
    components.push(DiagnosticComponent {
        name: "Network & Device Policy Manager".to_string(),
        status: "pass".to_string(),
        message: format!(
            "Device policy manager active. Tracking {} ARP network devices.",
            devices.len()
        ),
        details: dev_details,
    });

    let mut ip_details = HashMap::new();
    ip_details.insert(
        "smart_ip_blocking".to_string(),
        serde_json::json!(conf.smart_ip_blocking),
    );
    ip_details.insert(
        "auto_block_upstream_sinkholes".to_string(),
        serde_json::json!(conf.auto_block_upstream_sinkholes),
    );
    ip_details.insert(
        "auto_block_upstreams_count".to_string(),
        serde_json::json!(conf.auto_block_upstreams.len()),
    );
    components.push(DiagnosticComponent {
        name: "Smart IP & Auto-Block Sinkholes".to_string(),
        status: "pass".to_string(),
        message: format!(
            "Auto-block sinkhole tracking active with {} security discovery upstreams.",
            conf.auto_block_upstreams.len()
        ),
        details: ip_details,
    });

    let mut ml_details = HashMap::new();
    #[cfg(feature = "feat-scoring")]
    {
        ml_details.insert("compiled_in_build".to_string(), serde_json::json!(true));
        ml_details.insert(
            "ml_scoring_enabled".to_string(),
            serde_json::json!(conf.ml_scoring_enabled),
        );
        let ml_status = if conf.ml_scoring_enabled {
            "pass".to_string()
        } else {
            "info".to_string()
        };
        let ml_msg = if conf.ml_scoring_enabled {
            "ML & Heuristic Scoring Engine is ACTIVE (entropy, digit ratio, DGA detection)."
                .to_string()
        } else {
            "ML & Heuristic Scoring is compiled but disabled in configuration.".to_string()
        };
        components.push(DiagnosticComponent {
            name: "ML & Heuristic Scoring Engine".to_string(),
            status: ml_status,
            message: ml_msg,
            details: ml_details,
        });
    }
    #[cfg(not(feature = "feat-scoring"))]
    {
        ml_details.insert("compiled_in_build".to_string(), serde_json::json!(false));
        components.push(DiagnosticComponent {
            name: "ML & Heuristic Scoring Engine".to_string(),
            status: "info".to_string(),
            message: "ML & Heuristic Scoring module is omitted from this build (compile with '--features feat-scoring' to enable).".to_string(),
            details: ml_details,
        });
    }

    let overall_status = if overall_has_failure {
        "critical".to_string()
    } else if overall_has_warning {
        "warning".to_string()
    } else {
        "healthy".to_string()
    };

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(Json(DiagnosticsResponse {
        status: overall_status,
        timestamp: now_ts,
        components,
    }))
}

// Probe the live filter and service rules so diagnostics agree with DNS answers.
#[derive(Deserialize)]
struct ProbeQuery {
    domain: String,
}

#[derive(Serialize)]
struct ProbeResponse {
    domain: String,
    verdict: String, // "blocked" | "allowed"
    reason: String,
}

async fn probe_domain(
    State(state): State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<ProbeQuery>,
) -> Result<Json<ProbeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let normalized = rule_types::normalize_domain(&query.domain).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid domain".to_string(),
            }),
        )
    })?;
    let name = Name::from_str(&normalized).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid domain".to_string(),
            }),
        )
    })?;

    state
        .updater
        .ensure_current_sources()
        .await
        .map_err(|error| {
            error!("Probe source reconciliation failed: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Filtering rules are not ready".into(),
                }),
            )
        })?;
    let conf = state.config.load();
    let policy = core_dns::policy::domain_policy(
        &conf,
        &state.updater,
        &name,
        core_dns::config::now_epoch(),
        false,
    );
    use core_dns::policy::DomainPolicy;
    let (verdict, reason) = match policy {
        DomainPolicy::Bypass => ("allowed", "Protection is globally paused".into()),
        DomainPolicy::Service(service) => (
            "blocked",
            format!("Blocked by App Blocking service '{service}'"),
        ),
        DomainPolicy::Deny => ("blocked", "Matched a domain deny rule".into()),
        DomainPolicy::Allow => ("allowed", "Matched an explicit Allow list entry".into()),
        DomainPolicy::Pass
            if conf.enforce_safesearch
                && core_dns::safesearch::get_safesearch_target(&name).is_some() =>
        {
            (
                "allowed",
                "SafeSearch rewrite applies; no domain deny matched".into(),
            )
        }
        DomainPolicy::Pass => (
            "allowed",
            "No domain rule matched; device policies and upstream answer checks still apply".into(),
        ),
    };
    Ok(Json(ProbeResponse {
        domain: normalized,
        verdict: verdict.into(),
        reason,
    }))
}

#[cfg(test)]
mod password_work_tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_a_request_does_not_release_running_password_work() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker = tokio::spawn(password_work(slots.clone(), move || {
            let _ = started.send(());
            wait.recv().unwrap();
        }));
        running.await.unwrap();
        worker.abort();
        let _ = worker.await;
        assert_eq!(
            password_work(slots.clone(), || ()).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(password_work(slots, || true).await, Ok(true));
    }
}
