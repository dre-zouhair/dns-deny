use hickory_resolver::config::NameServerConfig;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::config_store::{ConfigStore, ConfigStoreError};
use crate::local_dns::LocalDnsIndex;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub address: String,
    pub protocol: String, // "udp", "tcp", "dot", "doh"
    pub tls_sni: Option<String>,
    pub doh_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ClientAlias {
    pub identifier: String, // IP or MAC address
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LocalDnsRecord {
    pub name: String,
    pub record_type: String, // "A", "AAAA", or "CNAME"
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CustomService {
    pub id: String,
    pub name: String,
    pub description: String,
    pub wildcards: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceSchedule {
    pub ip: String,
    pub policy: String,     // "block" or "whitelist"
    pub days: Vec<String>,  // e.g. ["mon", "tue", "wed"]
    pub start_time: String, // "HH:MM" in 24h format
    pub end_time: String,   // "HH:MM" in 24h format
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BlocklistCategory {
    pub id: String,
    pub name: String,
    pub urls: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub upstreams: Vec<UpstreamConfig>,
    pub dnssec_validation: bool,
    /// Global per-IP limit shared by all workers; the field name is retained
    /// for config/API compatibility.
    pub ratelimit_qps_per_worker: u32,
    pub ratelimit_window_duration_secs: u64,
    pub ratelimit_max_ips: usize,

    #[serde(default = "default_bind_addr")]
    pub bind_address: String,

    /// CIDR ranges permitted to submit DNS queries. An explicit empty list
    /// preserves legacy allow-all behavior; it is unsafe on a public bind.
    #[serde(default = "default_allowed_client_cidrs")]
    pub allowed_client_cidrs: Vec<String>,

    // Cache configuration
    pub cache_l1_max_entries: usize,
    pub cache_l2_max_size_mb: u64,
    #[serde(alias = "cache_negative_ttl_floor_secs")]
    pub cache_negative_ttl_fallback_secs: u32,

    // Blocklist configuration
    pub blocklist_urls: Vec<String>,
    #[serde(default)]
    pub blocklist_categories: Vec<BlocklistCategory>,
    /// Background blocklist refresh schedule: sec min hour day month day-of-week.
    #[serde(default = "default_blocklist_refresh_cron")]
    pub blocklist_refresh_cron: String,
    #[serde(default = "default_blocklist_fetch_concurrency")]
    pub blocklist_fetch_concurrency: usize,
    #[serde(default = "default_discovery_timeout_ms")]
    pub discovery_timeout_ms: u64,
    #[serde(default = "default_true")]
    pub auto_block_upstream_sinkholes: bool,
    #[serde(default = "default_auto_block_upstreams")]
    pub auto_block_upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    /// Check administrator-managed malicious IPs. Domain answers never
    /// automatically create global IP entries.
    pub smart_ip_blocking: bool,

    // Device policies (Network Overview)
    #[serde(default)]
    pub device_blocking_enabled: bool,
    #[serde(default)]
    pub device_policies: std::collections::HashMap<String, String>,
    /// true: explicitly confirmed IP whitelist; false: quarantined legacy
    /// IP/MAC pair. The marker survives deletion of the old MAC policy.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub device_policy_ip_overrides: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    pub device_schedules: Vec<DeviceSchedule>,
    #[serde(default)]
    pub local_dns_records: Vec<LocalDnsRecord>,
    #[serde(default)]
    pub client_aliases: Vec<ClientAlias>,
    #[serde(default)]
    pub blocked_services: Vec<String>,
    #[serde(default)]
    pub custom_services: Vec<CustomService>,

    // Temporary protection pause (global / category / service / device)
    #[serde(default = "default_pause_duration_secs")]
    pub protection_pause_default_duration_secs: u64,
    #[serde(default)]
    pub protection_paused_until: Option<i64>,
    #[serde(default)]
    pub category_pauses: std::collections::HashMap<String, i64>,
    #[serde(default)]
    pub service_pauses: std::collections::HashMap<String, i64>,
    /// Device IP or MAC -> absolute expiry. Timed bypass; static policies remain intact.
    #[serde(default)]
    pub device_pauses: std::collections::HashMap<String, i64>,

    #[serde(default)]
    pub ml_scoring_enabled: bool,
    #[serde(default)]
    pub enforce_safesearch: bool,
    #[serde(default)]
    pub recursive_resolver_enabled: bool,
    #[serde(default)]
    pub encrypted_upstream_enabled: bool,
    #[serde(default)]
    pub encrypted_upstream_allow_plaintext_fallback: bool,
    #[serde(default = "default_encrypted_upstream_url")]
    pub encrypted_upstream_url: String,
    #[serde(default = "default_doh_upstreams")]
    pub doh_upstreams: Vec<String>,

    // Logging configuration
    pub logging_enabled: bool,
    pub logging_db_path: String,
    pub logging_channel_capacity: usize,
    pub logging_retention_days: i64,

    // Admin API configuration
    pub api_enabled: bool,
    pub api_port: u16,
    #[serde(default = "default_bind_addr")]
    pub api_bind_address: String,
    /// Allow direct HTTP administration by default. Set false to require a
    /// trusted TLS terminator that overwrites X-Forwarded-Proto.
    #[serde(default = "default_true")]
    pub api_allow_insecure_http: bool,
    #[serde(default = "default_trusted_proxy_cidrs")]
    pub api_trusted_proxy_cidrs: Vec<String>,
    pub api_key: String,
    /// JSON API bearer token as written in the config file. `Config::load`
    /// replaces it with `api_token_sha256`; it is never serialized, so the
    /// plaintext does not reach the state database.
    #[serde(default, skip_serializing)]
    pub api_token: Option<String>,
    /// SHA-256 (lowercase hex) of the JSON API bearer token, if one is set.
    /// Tokens are long random or operator-chosen secrets, so a fast digest
    /// is sufficient and the API never pays bcrypt per request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token_sha256: Option<String>,
    pub api_ratelimit_qps: u64,
}

fn default_encrypted_upstream_url() -> String {
    "https://cloudflare-dns.com/dns-query".to_string()
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_trusted_proxy_cidrs() -> Vec<String> {
    vec!["127.0.0.1/32".into(), "::1/128".into()]
}

fn default_allowed_client_cidrs() -> Vec<String> {
    [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// API keys that appear in the shipped sample configs and docs. Anyone who
/// has read the README knows them, so a fresh install must not keep one.
pub const KNOWN_DEFAULT_API_KEYS: &[&str] = &[
    "my-secure-dashboard-key-123",
    "admin-secret-token",
    "changeme",
];

pub fn is_known_default_api_key(api_key: &str) -> bool {
    KNOWN_DEFAULT_API_KEYS.contains(&api_key)
}

/// The API token, unlike the admin password, is checked with a fast digest,
/// so a configured one must not be short enough to guess.
pub const MIN_API_TOKEN_CHARS: usize = 16;

/// Lowercase hex SHA-256, the stored form of a JSON API token.
pub fn api_token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A random 256-bit token, hex-encoded, for tokens issued from the dashboard
/// or `POST /api/v1/auth/token`.
pub fn generate_api_key() -> Result<String, getrandom::Error> {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw)?;
    Ok(raw.iter().map(|b| format!("{:02x}", b)).collect())
}

fn default_blocklist_fetch_concurrency() -> usize {
    4
}
fn default_discovery_timeout_ms() -> u64 {
    250
}

fn default_blocklist_refresh_cron() -> String {
    "0 0 3 * * *".to_string() // daily at 03:00
}

fn default_doh_upstreams() -> Vec<String> {
    vec![
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://dns.google/dns-query".to_string(),
        "https://dns.quad9.net/dns-query".to_string(),
    ]
}

fn default_auto_block_upstreams() -> Vec<UpstreamConfig> {
    vec![
        UpstreamConfig {
            address: "1.1.1.2".to_string(),
            protocol: "dot".to_string(),
            tls_sni: Some("security.cloudflare-dns.com".to_string()),
            doh_path: None,
        },
        UpstreamConfig {
            address: "1.0.0.2".to_string(),
            protocol: "dot".to_string(),
            tls_sni: Some("security.cloudflare-dns.com".to_string()),
            doh_path: None,
        },
    ]
}

fn default_true() -> bool {
    true
}

fn default_pause_duration_secs() -> u64 {
    172_800 // 48 hours
}

/// Current wall-clock time as unix epoch seconds, used for all pause/resume
/// expiry comparisons (handler.rs, api handlers, main.rs, the pause sweeper).
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `paused_until` value standing in for "no expiry" -- 9999-12-31T23:59:59Z.
/// Deliberately not `i64::MAX`: this round-trips exactly through a JSON
/// double, so the admin UI can compare it without precision loss.
pub const INDEFINITE_PAUSE_EPOCH: i64 = 253_402_300_799;
pub const MAX_DEVICE_PAUSE_DURATION_SECS: u64 = 48 * 60 * 60;

/// A single pausable unit of protection: the whole server, one blocklist
/// category, app/service, or device (IP or MAC identity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseScope {
    Global,
    Category(String),
    Service(String),
    Device(String),
}

/// Parses a bare IP or ip:port for both validation and resolver setup.
/// IPv6 with a port requires brackets, e.g. [::1]:53.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedUpstreamAddress {
    pub ip: IpAddr,
    pub port: Option<u16>,
}

pub fn parse_upstream_address(address: &str) -> Result<ParsedUpstreamAddress, String> {
    let address = address.trim();
    if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        if socket.port() == 0 {
            return Err("upstream port must be greater than zero".to_string());
        }
        return Ok(ParsedUpstreamAddress {
            ip: socket.ip(),
            port: Some(socket.port()),
        });
    }
    if address.starts_with('[') {
        return Err("bracketed IPv6 addresses must include a port, e.g. [::1]:5353".to_string());
    }
    address
        .parse::<IpAddr>()
        .map(|ip| ParsedUpstreamAddress { ip, port: None })
        .map_err(|_| {
            if address.matches(':').count() > 1 {
                "ambiguous IPv6 address with a port; use bracketed syntax [IPv6]:port".to_string()
            } else {
                "expected an IP address or IP:port".to_string()
            }
        })
}

pub fn parse_upstream_ip(address: &str) -> Option<IpAddr> {
    parse_upstream_address(address).ok().map(|parsed| parsed.ip)
}

pub fn build_name_server_config(upstream: &UpstreamConfig) -> Result<NameServerConfig, String> {
    let parsed = parse_upstream_address(&upstream.address)
        .map_err(|error| format!("invalid upstream address {:?}: {error}", upstream.address))?;
    let mut config = match upstream.protocol.as_str() {
        // Pair UDP with TCP: on a truncated response hickory sets
        // `disable_udp` and re-selects a connection, so a UDP-only list
        // leaves it with nothing to fall back to.
        "udp" => NameServerConfig::udp_and_tcp(parsed.ip),
        "tcp" => NameServerConfig::tcp(parsed.ip),
        "dot" => {
            let sni = upstream.tls_sni.as_deref().unwrap_or("cloudflare-dns.com");
            NameServerConfig::tls(parsed.ip, Arc::from(sni))
        }
        "doh" => {
            let sni = upstream.tls_sni.as_deref().unwrap_or("cloudflare-dns.com");
            let path = upstream.doh_path.as_deref().unwrap_or("/dns-query");
            NameServerConfig::https(parsed.ip, Arc::from(sni), Some(Arc::from(path)))
        }
        other => return Err(format!("unsupported upstream protocol: {other}")),
    };
    if let Some(port) = parsed.port {
        for connection in &mut config.connections {
            connection.port = port;
        }
    }
    Ok(config)
}

impl Config {
    pub fn allowed_client_nets(&self) -> Result<Vec<IpNet>, String> {
        self.allowed_client_cidrs
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNet>()
                    .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| {
                        format!(
                            "allowed_client_cidrs entry '{}' is not a valid CIDR or IP",
                            cidr
                        )
                    })
            })
            .collect()
    }

    /// Moves a plaintext `api_token` from the config file into
    /// `api_token_sha256`.
    pub fn hash_configured_api_token(&mut self) -> Result<(), String> {
        let Some(token) = self.api_token.take() else {
            return Ok(());
        };
        if self.api_token_sha256.is_some() {
            return Err("set either api_token or api_token_sha256, not both".into());
        }
        if token.chars().count() < MIN_API_TOKEN_CHARS {
            return Err(format!(
                "api_token must contain at least {MIN_API_TOKEN_CHARS} characters"
            ));
        }
        self.api_token_sha256 = Some(api_token_digest(&token));
        Ok(())
    }

    pub fn validate_local_dns_records(&self) -> Result<(), String> {
        LocalDnsIndex::build(&self.local_dns_records).map(|_| ())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&contents)?;
        for (id, policy) in &config.device_policies {
            if policy == "whitelist"
                && let Ok(ip) = id.trim().parse::<IpAddr>()
            {
                config
                    .device_policy_ip_overrides
                    .insert(ip.to_string(), true);
            }
        }
        config.hash_configured_api_token()?;
        Ok(config)
    }

    fn quarantine_legacy_ip_whitelists(&mut self) {
        if self.device_policies.iter().any(|(id, policy)| {
            policy == "whitelist" && normalize_device_identifier(id).parse::<IpAddr>().is_err()
        }) {
            for (id, policy) in &self.device_policies {
                if policy == "whitelist"
                    && let Ok(ip) = id.trim().parse::<IpAddr>()
                {
                    self.device_policy_ip_overrides
                        .entry(ip.to_string())
                        .or_insert(false);
                }
            }
        }
    }

    /// Validates upstreams, bind addresses, credentials, resource limits, and
    /// logging paths before startup or configuration publication.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=16).contains(&self.blocklist_fetch_concurrency) {
            return Err("blocklist_fetch_concurrency must be between 1 and 16".into());
        }
        if !(1..=5000).contains(&self.discovery_timeout_ms) {
            return Err("discovery_timeout_ms must be between 1 and 5000".into());
        }
        // ── Upstreams ──────────────────────────────────────────────────────
        if self.upstreams.is_empty() {
            return Err(
                "no upstream DNS servers configured — at least one is required".to_string(),
            );
        }

        for (i, upstream) in self.upstreams.iter().enumerate() {
            if let Err(error) = parse_upstream_address(&upstream.address) {
                return Err(format!(
                    "upstream[{}]: address '{}' is invalid: {}",
                    i, upstream.address, error
                ));
            }

            match upstream.protocol.as_str() {
                "udp" | "tcp" => {}
                "dot" | "doh" => {
                    if upstream.tls_sni.is_none() {
                        return Err(format!(
                            "upstream[{}]: protocol '{}' requires tls_sni to be set",
                            i, upstream.protocol
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "upstream[{}]: unknown protocol '{}' — must be udp, tcp, dot, or doh",
                        i, other
                    ));
                }
            }
        }

        for (i, upstream) in self.auto_block_upstreams.iter().enumerate() {
            if let Err(error) = parse_upstream_address(&upstream.address) {
                return Err(format!(
                    "auto_block_upstreams[{}]: address '{}' is invalid: {}",
                    i, upstream.address, error
                ));
            }
        }

        // ── Bind addresses ─────────────────────────────────────────────────
        // Never turn a misspelled interface address into a wildcard bind.
        if self.bind_address.parse::<IpAddr>().is_err() {
            return Err(format!(
                "bind_address '{}' is not a valid IP address",
                self.bind_address
            ));
        }
        if self.api_enabled && self.api_bind_address.parse::<IpAddr>().is_err() {
            return Err(format!(
                "api_bind_address '{}' is not a valid IP address",
                self.api_bind_address
            ));
        }

        self.allowed_client_nets()?;
        self.validate_local_dns_records()?;
        crate::policy::ScheduleIndex::build(&self.device_schedules)?;
        build_device_pause_index(&self.device_pauses)?;
        let mut normalized_devices = std::collections::HashSet::new();
        for (identifier, policy) in &self.device_policies {
            if !normalized_devices.insert(normalize_device_identifier(identifier)) {
                return Err("Duplicate policies for the same normalized device identifier".into());
            }
            if !crate::policy::valid_device_identifier(identifier) {
                return Err("Device policy requires a valid IP or MAC".into());
            }
            if !matches!(policy.as_str(), "block" | "whitelist") {
                return Err("Device policy must be block or whitelist".into());
            }
        }
        for cidr in &self.api_trusted_proxy_cidrs {
            cidr.parse::<IpNet>()
                .map_err(|_| format!("invalid api_trusted_proxy_cidrs entry: {cidr}"))?;
        }

        // ── Rate limiter ───────────────────────────────────────────────────
        if self.ratelimit_qps_per_worker == 0 {
            return Err("ratelimit_qps_per_worker must be > 0".to_string());
        }
        if self.ratelimit_window_duration_secs == 0 {
            return Err("ratelimit_window_duration_secs must be > 0".to_string());
        }
        if self.ratelimit_max_ips == 0 {
            return Err("ratelimit_max_ips must be > 0".to_string());
        }

        // ── Cache sizes ────────────────────────────────────────────────────
        if self.cache_l1_max_entries == 0 {
            return Err("cache_l1_max_entries must be > 0".to_string());
        }
        if self.cache_l2_max_size_mb == 0 {
            return Err("cache_l2_max_size_mb must be > 0".to_string());
        }

        let available_mb = available_memory_mb();
        if available_mb > 0 {
            let threshold_mb = (available_mb as f64 * 0.75) as u64;
            if self.cache_l2_max_size_mb > threshold_mb {
                return Err(format!(
                    "cache_l2_max_size_mb ({} MB) exceeds 75% of available system memory ({} MB). \
                     Reduce cache_l2_max_size_mb or increase available memory.",
                    self.cache_l2_max_size_mb, available_mb
                ));
            }
        }

        // ── Admin API ──────────────────────────────────────────────────────
        if let Some(digest) = &self.api_token_sha256
            && !(digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err("api_token_sha256 must be a lowercase hex SHA-256 digest".to_string());
        }
        if self.api_enabled {
            if self.api_port == 0 {
                return Err("api_port must be a non-zero port number".to_string());
            }
            if self.api_port == 53 {
                return Err(
                    "api_port cannot be 53 — that conflicts with the DNS listener".to_string(),
                );
            }
            if self.api_key.is_empty() {
                return Err("api_key must not be empty when API is enabled".to_string());
            }
            if self.api_key == "admin-secret-token" || self.api_key == "changeme" {
                return Err(
                    "api_key is set to a well-known default ('admin-secret-token' / 'changeme'). \
                     Set a strong, unique key before deploying."
                        .to_string(),
                );
            }
            if self.api_ratelimit_qps == 0 {
                return Err("api_ratelimit_qps must be > 0 when API is enabled".to_string());
            }
        }

        // ── Logging ────────────────────────────────────────────────────────
        if self.logging_enabled {
            if self.logging_db_path.is_empty() {
                return Err("logging_db_path must not be empty when logging is enabled".to_string());
            }
            if self.logging_retention_days <= 0 {
                return Err("logging_retention_days must be > 0".to_string());
            }
            if self.logging_channel_capacity == 0 {
                return Err("logging_channel_capacity must be > 0".to_string());
            }

            let db_path = Path::new(&self.logging_db_path);
            let mut parent = db_path.parent().unwrap_or(Path::new("."));
            if parent.as_os_str().is_empty() {
                parent = Path::new(".");
            }
            if !parent.exists() {
                return Err(format!(
                    "logging_db_path parent directory '{}' does not exist",
                    parent.display()
                ));
            }
            if db_path.exists() && db_path.is_dir() {
                return Err(format!(
                    "logging_db_path '{}' points to a directory, not a file",
                    self.logging_db_path
                ));
            }
        }

        if self.protection_pause_default_duration_secs == 0 {
            return Err("protection_pause_default_duration_secs must be > 0".to_string());
        }

        Ok(())
    }

    /// `blocklist_urls` plus every enabled category's urls, excluding
    /// categories with a live (non-expired) entry in `category_pauses`.
    /// Single source of truth for what `BlocklistUpdater::sync_sources()`
    /// should be called with.
    pub fn active_blocklist_urls(&self, now_epoch: i64) -> Vec<String> {
        let mut urls = self.blocklist_urls.clone();
        for cat in &self.blocklist_categories {
            if !cat.enabled {
                continue;
            }
            if self.is_paused(&PauseScope::Category(cat.id.clone()), now_epoch) {
                continue;
            }
            urls.extend(cat.urls.clone());
        }
        urls
    }

    /// Every blocklist URL the config knows about -- uncategorized plus all
    /// categories, whether enabled, disabled or paused. Used to decide which
    /// on-disk cached copies are still worth keeping.
    pub fn configured_blocklist_urls(&self) -> Vec<String> {
        let mut urls = self.blocklist_urls.clone();
        for cat in &self.blocklist_categories {
            urls.extend(cat.urls.iter().cloned());
        }
        urls
    }

    /// Whether `scope` currently has a live (non-expired) pause.
    pub fn is_paused(&self, scope: &PauseScope, now_epoch: i64) -> bool {
        let until = match scope {
            PauseScope::Global => self.protection_paused_until,
            PauseScope::Category(id) => self.category_pauses.get(id).copied(),
            PauseScope::Service(id) => self.service_pauses.get(id).copied(),
            PauseScope::Device(id) => self
                .device_pauses
                .iter()
                .find(|(key, _)| {
                    normalize_device_identifier(key) == normalize_device_identifier(id)
                })
                .map(|(_, until)| *until),
        };
        until.is_some_and(|t| t > now_epoch)
    }

    /// Sets `scope` paused until `now_epoch + protection_pause_default_duration_secs`,
    /// overwriting any existing pause on the same scope. Returns the new
    /// `paused_until` timestamp. Callers that want to reject re-pausing an
    /// already-live scope must check `is_paused()` first -- this method is a
    /// dumb setter.
    pub fn pause(&mut self, scope: &PauseScope, now_epoch: i64) -> i64 {
        self.pause_for(scope, now_epoch, None)
    }

    /// As `pause`, but with an explicit duration. `None` falls back to
    /// `protection_pause_default_duration_secs`; `Some(secs)` pauses for
    /// exactly that long. Pass `INDEFINITE_PAUSE_EPOCH` worth of seconds via
    /// `pause_indefinitely` rather than computing it here.
    pub fn pause_for(
        &mut self,
        scope: &PauseScope,
        now_epoch: i64,
        duration_secs: Option<u64>,
    ) -> i64 {
        let secs = duration_secs.unwrap_or(self.protection_pause_default_duration_secs);
        let until = now_epoch.saturating_add(secs as i64);
        self.set_paused_until(scope, until);
        until
    }

    /// Pauses `scope` with no expiry -- only an explicit `resume` clears it.
    /// Implemented as a far-future timestamp so every existing expiry check
    /// (`is_paused`, `live_status`, `PauseSweeper`) keeps working unchanged.
    pub fn pause_indefinitely(&mut self, scope: &PauseScope) -> i64 {
        self.set_paused_until(scope, INDEFINITE_PAUSE_EPOCH);
        INDEFINITE_PAUSE_EPOCH
    }

    fn set_paused_until(&mut self, scope: &PauseScope, until: i64) {
        match scope {
            PauseScope::Global => self.protection_paused_until = Some(until),
            PauseScope::Category(id) => {
                self.category_pauses.insert(id.clone(), until);
            }
            PauseScope::Service(id) => {
                self.service_pauses.insert(id.clone(), until);
            }
            PauseScope::Device(id) => {
                self.resume(scope);
                self.device_pauses
                    .insert(normalize_device_identifier(id), until);
            }
        }
    }

    /// Clears any pause on `scope`. Returns true if one was present.
    pub fn resume(&mut self, scope: &PauseScope) -> bool {
        match scope {
            PauseScope::Global => self.protection_paused_until.take().is_some(),
            PauseScope::Category(id) => self.category_pauses.remove(id).is_some(),
            PauseScope::Service(id) => self.service_pauses.remove(id).is_some(),
            PauseScope::Device(id) => {
                let before = self.device_pauses.len();
                self.device_pauses.retain(|key, _| {
                    normalize_device_identifier(key) != normalize_device_identifier(id)
                });
                before != self.device_pauses.len()
            }
        }
    }
}

/// Result of a persisted configuration edit and the snapshot it published.
#[derive(Debug)]
pub struct ConfigCommit<R> {
    pub output: R,
    pub config: Arc<Config>,
    pub revision: i64,
}

#[derive(Debug)]
pub enum ConfigUpdateError<E> {
    Mutation(E),
    Validation(String),
    Persistence(ConfigStoreError),
}

impl<E: std::fmt::Display> std::fmt::Display for ConfigUpdateError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mutation(e) => write!(f, "mutation error: {}", e),
            Self::Validation(msg) => write!(f, "validation error: {}", msg),
            Self::Persistence(e) => write!(f, "persistence error: {}", e),
        }
    }
}

impl<E: std::fmt::Display + std::fmt::Debug> std::error::Error for ConfigUpdateError<E> {}

/// Immutable config and precomputed indexes shared across a DNS request.
pub struct RuntimeConfigSnapshot {
    pub(crate) revision: i64,
    config: Arc<Config>,
    allowed_client_nets: Arc<[IpNet]>,
    local_dns: Arc<LocalDnsIndex>,
    /// `config.device_policies` keyed by `normalize_device_identifier`, so a
    /// policy saved as `AA-BB-…` still matches the `aa:bb:…` form the ARP
    /// table reports.
    device_policies: Arc<std::collections::HashMap<String, String>>,
    device_pauses: std::collections::HashMap<String, i64>,
    device_schedules: crate::policy::ScheduleIndex,
    mac_blocks: bool,
}

/// Canonical form of a device identifier: an IP in its standard textual form,
/// or a MAC address lowercased with `:` separators (the form
/// `/proc/net/arp` reports).
pub fn normalize_device_identifier(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ip.to_string();
    }
    trimmed.replace('-', ":").to_ascii_lowercase()
}

/// Whether two device identifiers name the same device, ignoring ASCII case
/// and treating `-` and `:` MAC separators as equal. Allocation-free, for the
/// per-query schedule check.
pub fn device_identifiers_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    let canon = |c: u8| {
        if c == b'-' {
            b':'
        } else {
            c.to_ascii_lowercase()
        }
    };
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| canon(x) == canon(y))
}

fn build_device_policy_index(
    policies: &std::collections::HashMap<String, String>,
) -> Arc<std::collections::HashMap<String, String>> {
    Arc::new(
        policies
            .iter()
            .map(|(id, policy)| (normalize_device_identifier(id), policy.clone()))
            .collect(),
    )
}

/// Validate and index pause identities once per configuration publication.
fn build_device_pause_index(
    pauses: &std::collections::HashMap<String, i64>,
) -> Result<std::collections::HashMap<String, i64>, String> {
    let mut index = std::collections::HashMap::new();
    for (id, &until) in pauses {
        if !crate::policy::valid_device_identifier(id) {
            return Err("Device pause requires a valid IP or MAC".into());
        }
        if until <= 0 || until >= INDEFINITE_PAUSE_EPOCH {
            return Err("Device pause requires a finite positive expiry".into());
        }
        if index
            .insert(normalize_device_identifier(id), until)
            .is_some()
        {
            return Err("Duplicate pauses for the same normalized device identifier".into());
        }
    }
    Ok(index)
}

impl RuntimeConfigSnapshot {
    pub fn try_from_config(mut config: Arc<Config>, revision: i64) -> Result<Self, String> {
        Arc::make_mut(&mut config).quarantine_legacy_ip_whitelists();
        let allowed_client_nets = config.allowed_client_nets()?;
        let local_dns = LocalDnsIndex::build(&config.local_dns_records)?;
        let device_policies = build_device_policy_index(&config.device_policies);
        Ok(Self {
            revision,
            device_schedules: crate::policy::ScheduleIndex::build(&config.device_schedules)?,
            device_pauses: build_device_pause_index(&config.device_pauses)?,
            mac_blocks: config.device_policies.iter().any(|(id, policy)| {
                policy == "block" && normalize_device_identifier(id).parse::<IpAddr>().is_err()
            }),
            config,
            allowed_client_nets: allowed_client_nets.into(),
            local_dns: Arc::new(local_dns),
            device_policies,
        })
    }

    fn from_config(config: Arc<Config>) -> Self {
        Self::try_from_config(config, 1).expect("ConfigHandle received invalid configuration")
    }

    pub fn revision(&self) -> i64 {
        self.revision
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) fn local_dns(&self) -> &LocalDnsIndex {
        &self.local_dns
    }

    /// The static device policy for an already-normalized identifier (see
    /// `normalize_device_identifier`).
    pub fn device_policy(&self, normalized_identifier: &str) -> Option<&str> {
        self.device_policies
            .get(normalized_identifier)
            .map(String::as_str)
    }

    /// Active pause for normalized identities, preferring a stable MAC binding.
    pub fn device_pause(&self, ip: &str, mac: Option<&str>, now: i64) -> Option<(&str, i64)> {
        mac.and_then(|id| self.device_pauses.get_key_value(id))
            .filter(|(_, until)| **until > now)
            .or_else(|| {
                self.device_pauses
                    .get_key_value(ip)
                    .filter(|(_, until)| **until > now)
            })
            .map(|(id, until)| (id.as_str(), *until))
    }

    pub fn effective_device_policy(
        &self,
        ip: IpAddr,
        mac: Option<&str>,
        now: chrono::DateTime<chrono::Local>,
    ) -> crate::policy::DevicePolicy {
        use crate::policy::DevicePolicy;
        if !self.config.device_blocking_enabled
            || self.config.is_paused(&PauseScope::Global, now.timestamp())
        {
            return DevicePolicy::Filtered;
        }
        let ip = ip.to_string();
        let mac = mac.map(normalize_device_identifier);
        if mac.is_none() && (self.mac_blocks || self.device_schedules.blocks_unknown(now)) {
            // An unknown identity must not evade a MAC restriction or inherit
            // a whitelisted address before neighbor discovery completes.
            return DevicePolicy::IdentityUnknown;
        }
        if self
            .device_pause(&ip, mac.as_deref(), now.timestamp())
            .is_some()
        {
            return DevicePolicy::Whitelist;
        }
        let scheduled = self.device_schedules.evaluate(now, &ip, mac.as_deref());
        let by_mac = mac.as_deref().and_then(|id| self.device_policy(id));
        let by_ip = self.device_policy(&ip).filter(|policy| {
            // Old dashboard versions wrote both IP and MAC whitelist entries.
            // Such an unbound IP must not transfer bypass to a new MAC.
            *policy != "whitelist"
                || self.config.device_policy_ip_overrides.get(&ip) != Some(&false)
        });
        match scheduled.or(by_mac).or(by_ip) {
            Some("block") => DevicePolicy::Block,
            Some("whitelist") => DevicePolicy::Whitelist,
            _ => DevicePolicy::Filtered,
        }
    }

    pub fn allows_client(&self, ip: IpAddr) -> bool {
        self.allowed_client_nets.is_empty()
            || self
                .allowed_client_nets
                .iter()
                .any(|network| network.contains(&ip))
    }
}

/// Publishes immutable snapshots that readers can hold across awaits without
/// cloning config collections. Copy-on-write edits are serialized so concurrent
/// writers cannot overwrite changes made from a newer snapshot.
pub struct ConfigHandle {
    current: arc_swap::ArcSwap<RuntimeConfigSnapshot>,
    write_lock: tokio::sync::Mutex<()>,
    store: Option<ConfigStore>,
}

impl ConfigHandle {
    pub fn new_persistent(
        store: ConfigStore,
        config: Config,
        revision: i64,
    ) -> Result<Self, String> {
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(config), revision)?;
        Ok(Self {
            current: arc_swap::ArcSwap::from_pointee(snapshot),
            write_lock: tokio::sync::Mutex::new(()),
            store: Some(store),
        })
    }

    pub fn new_ephemeral(config: Config) -> Self {
        let snapshot = RuntimeConfigSnapshot::from_config(Arc::new(config));
        Self {
            current: arc_swap::ArcSwap::from_pointee(snapshot),
            write_lock: tokio::sync::Mutex::new(()),
            store: None,
        }
    }

    pub fn new(config: Config) -> Self {
        Self::new_ephemeral(config)
    }

    pub fn store(&self) -> Option<&ConfigStore> {
        self.store.as_ref()
    }

    pub fn revision(&self) -> i64 {
        self.current.load().revision
    }

    /// Current config snapshot. Cheap (atomic load + refcount bump) and safe
    /// to hold across `.await`; the returned snapshot is immutable, so a
    /// concurrent write simply means later readers see the newer value.
    pub fn load(&self) -> std::sync::Arc<Config> {
        self.current.load_full().config.clone()
    }

    pub fn load_runtime(&self) -> Arc<RuntimeConfigSnapshot> {
        self.current.load_full()
    }

    pub async fn update<R, E, F>(
        &self,
        reason: &'static str,
        mutate: F,
    ) -> Result<ConfigCommit<R>, ConfigUpdateError<E>>
    where
        F: FnOnce(&mut Config) -> Result<R, E>,
    {
        let _guard = self.write_lock.lock().await;

        let current_snapshot = self.current.load();
        let expected_revision = current_snapshot.revision;
        let mut candidate = (*current_snapshot.config).clone();

        let output = mutate(&mut candidate).map_err(ConfigUpdateError::Mutation)?;
        candidate.quarantine_legacy_ip_whitelists();

        candidate
            .validate()
            .map_err(ConfigUpdateError::Validation)?;

        let allowed_client_nets = candidate
            .allowed_client_nets()
            .map_err(ConfigUpdateError::Validation)?;
        let local_dns = LocalDnsIndex::build(&candidate.local_dns_records)
            .map_err(ConfigUpdateError::Validation)?;

        let device_pauses = build_device_pause_index(&candidate.device_pauses)
            .map_err(ConfigUpdateError::Validation)?;

        let new_revision = if let Some(ref store) = self.store {
            store
                .update_config_async(&candidate, expected_revision, reason)
                .await
                .map_err(ConfigUpdateError::Persistence)?
        } else {
            expected_revision + 1
        };

        let candidate_arc = Arc::new(candidate);
        let new_snapshot = RuntimeConfigSnapshot {
            revision: new_revision,
            config: candidate_arc.clone(),
            allowed_client_nets: allowed_client_nets.into(),
            local_dns: Arc::new(local_dns),
            device_policies: build_device_policy_index(&candidate_arc.device_policies),
            device_pauses,
            device_schedules: crate::policy::ScheduleIndex::build(&candidate_arc.device_schedules)
                .map_err(ConfigUpdateError::Validation)?,
            mac_blocks: candidate_arc.device_policies.iter().any(|(id, policy)| {
                policy == "block" && normalize_device_identifier(id).parse::<IpAddr>().is_err()
            }),
        };

        self.current.store(Arc::new(new_snapshot));

        Ok(ConfigCommit {
            output,
            config: candidate_arc,
            revision: new_revision,
        })
    }
}

impl From<Config> for ConfigHandle {
    fn from(config: Config) -> Self {
        Self::new(config)
    }
}

/// Returns total available system memory in MB, or 0 if not determinable.
/// Reads /proc/meminfo on Linux; returns 0 on other platforms.
fn available_memory_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
            for line in contents.lines() {
                // "MemAvailable:   12345678 kB"
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    return kb / 1024;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod config_handle_tests {
    use super::tests::base_config;
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_snapshot_held_across_await_is_not_mutated_by_a_writer() {
        // The whole point of handing out an immutable snapshot: the DNS query
        // path holds one across upstream `.await`s, and a concurrent admin
        // write must neither block it nor change what it already read.
        let handle = Arc::new(ConfigHandle::new(base_config()));
        let snapshot = handle.load();
        assert!(!snapshot.enforce_safesearch);

        handle
            .update("test:safesearch", |cfg| {
                cfg.enforce_safesearch = true;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();

        tokio::task::yield_now().await;

        assert!(!snapshot.enforce_safesearch);
        assert!(handle.load().enforce_safesearch);
    }

    #[tokio::test]
    async fn test_successful_update_persists_and_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = ConfigHandle::new_persistent(store.clone(), config, 1).unwrap();
        assert_eq!(handle.revision(), 1);

        let commit = handle
            .update("test:update", |c| {
                c.enforce_safesearch = true;
                Ok::<_, String>("output_123")
            })
            .await
            .unwrap();

        assert_eq!(commit.output, "output_123");
        assert_eq!(commit.revision, 2);
        assert!(commit.config.enforce_safesearch);
        assert_eq!(handle.revision(), 2);
        assert!(handle.load().enforce_safesearch);
        assert_eq!(handle.load_runtime().revision(), 2);

        let (stored_cfg, stored_rev) = store.load_current().unwrap().unwrap();
        assert_eq!(stored_rev, 2);
        assert!(stored_cfg.enforce_safesearch);
    }

    #[tokio::test]
    async fn test_mutation_error_creates_no_write_or_publication() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = ConfigHandle::new_persistent(store.clone(), config, 1).unwrap();

        let result = handle
            .update("test:mut_err", |_| Err::<(), _>("explicit failure"))
            .await;

        match result {
            Err(ConfigUpdateError::Mutation(err)) => assert_eq!(err, "explicit failure"),
            other => panic!("expected mutation error, got {:?}", other),
        }

        assert_eq!(handle.revision(), 1);
        assert_eq!(store.load_current().unwrap().unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_validation_error_creates_no_write_or_publication() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = ConfigHandle::new_persistent(store.clone(), config, 1).unwrap();

        let result = handle
            .update("test:val_err", |c| {
                c.upstreams.clear();
                Ok::<_, ()>(())
            })
            .await;

        assert!(matches!(result, Err(ConfigUpdateError::Validation(_))));
        assert_eq!(handle.revision(), 1);
        assert_eq!(store.load_current().unwrap().unwrap().1, 1);
    }

    #[tokio::test]
    async fn test_database_failure_creates_no_publication() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = ConfigHandle::new_persistent(store.clone(), config, 1).unwrap();

        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DROP TABLE config_state;", []).unwrap();
        }

        let result = handle
            .update("test:db_err", |c| {
                c.enforce_safesearch = true;
                Ok::<_, ()>(())
            })
            .await;

        assert!(matches!(result, Err(ConfigUpdateError::Persistence(_))));
        assert_eq!(handle.revision(), 1);
        assert!(!handle.load().enforce_safesearch);
    }

    #[tokio::test]
    async fn test_two_concurrent_updates_preserve_both_changes() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = Arc::new(ConfigHandle::new_persistent(store.clone(), config, 1).unwrap());

        let h1 = handle.clone();
        let t1 = tokio::spawn(async move {
            h1.update("test:t1", |c| {
                c.enforce_safesearch = true;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        });

        let h2 = handle.clone();
        let t2 = tokio::spawn(async move {
            h2.update("test:t2", |c| {
                c.smart_ip_blocking = true;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        });

        t1.await.unwrap();
        t2.await.unwrap();

        assert_eq!(handle.revision(), 3);
        let final_cfg = handle.load();
        assert!(final_cfg.enforce_safesearch);
        assert!(final_cfg.smart_ip_blocking);

        let (stored_cfg, stored_rev) = store.load_current().unwrap().unwrap();
        assert_eq!(stored_rev, 3);
        assert!(stored_cfg.enforce_safesearch);
        assert!(stored_cfg.smart_ip_blocking);
    }

    #[tokio::test]
    async fn test_old_snapshots_remain_immutable_while_new_readers_see_new_revision() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        let config = base_config();
        store.insert_seed(&config).unwrap();

        let handle = ConfigHandle::new_persistent(store, config, 1).unwrap();
        let snap1 = handle.load_runtime();
        assert_eq!(snap1.revision(), 1);
        assert!(!snap1.config().enforce_safesearch);

        handle
            .update("test:immutable", |c| {
                c.enforce_safesearch = true;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();

        assert_eq!(snap1.revision(), 1);
        assert!(!snap1.config().enforce_safesearch);

        let snap2 = handle.load_runtime();
        assert_eq!(snap2.revision(), 2);
        assert!(snap2.config().enforce_safesearch);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_normalize_device_identifier() {
        assert_eq!(
            normalize_device_identifier(" AA-BB-CC-dd-ee-FF "),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(
            normalize_device_identifier("AA:BB:CC:DD:EE:FF"),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(normalize_device_identifier("192.168.1.5"), "192.168.1.5");
        assert_eq!(
            normalize_device_identifier("2001:0DB8:0000::0001"),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_device_identifiers_match() {
        assert!(device_identifiers_match(
            "AA-BB-CC-DD-EE-FF",
            "aa:bb:cc:dd:ee:ff"
        ));
        assert!(device_identifiers_match("192.168.1.5", "192.168.1.5"));
        assert!(!device_identifiers_match(
            "aa:bb:cc:dd:ee:ff",
            "aa:bb:cc:dd:ee:00"
        ));
        assert!(!device_identifiers_match("192.168.1.5", "192.168.1.50"));
    }

    #[test]
    fn test_snapshot_device_policy_matches_legacy_mac_spelling() {
        let mut cfg = base_config();
        cfg.device_policies
            .insert("AA-BB-CC-DD-EE-FF".to_string(), "block".to_string());
        cfg.device_policies
            .insert("192.168.1.9".to_string(), "whitelist".to_string());
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(cfg), 1).unwrap();

        assert_eq!(snapshot.device_policy("aa:bb:cc:dd:ee:ff"), Some("block"));
        assert_eq!(snapshot.device_policy("192.168.1.9"), Some("whitelist"));
        assert_eq!(snapshot.device_policy("aa:bb:cc:dd:ee:00"), None);
    }

    #[test]
    fn test_device_identity_precedence_and_legacy_whitelist_isolation() {
        use crate::policy::DevicePolicy;
        let mut config = base_config();
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("192.0.2.1".into(), "whitelist".into());
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:01".into(), "whitelist".into());
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:02".into(), "block".into());
        let handle = ConfigHandle::new_ephemeral(config);
        let snapshot = handle.load_runtime();
        let ip = "192.0.2.1".parse().unwrap();
        let now = chrono::Local::now();
        assert_eq!(
            snapshot.effective_device_policy(ip, None, now),
            DevicePolicy::IdentityUnknown
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:01"), now),
            DevicePolicy::Whitelist
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:02"), now),
            DevicePolicy::Block
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:03"), now),
            DevicePolicy::Filtered
        );
    }

    #[test]
    fn test_device_master_switch_and_pause_disable_all_device_policies() {
        use crate::policy::DevicePolicy;
        let mut config = base_config();
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:02".into(), "block".into());
        let ip = "192.0.2.2".parse().unwrap();
        let now = chrono::Local::now();
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(config.clone()), 1).unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, None, now),
            DevicePolicy::Filtered
        );
        config.device_blocking_enabled = true;
        config.protection_paused_until = Some(now.timestamp() + 300);
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(config), 2).unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, None, now),
            DevicePolicy::Filtered
        );
    }

    #[test]
    fn test_confirmed_ip_whitelist_and_mac_precedence_can_coexist() {
        use crate::policy::DevicePolicy;
        let mut config = base_config();
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("192.0.2.1".into(), "whitelist".into());
        config
            .device_policy_ip_overrides
            .insert("192.0.2.1".into(), true);
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:01".into(), "whitelist".into());
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:02".into(), "block".into());
        let value = toml::to_string(&config).unwrap();
        let restored: Config = toml::from_str(&value).unwrap();
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(restored), 1).unwrap();
        let now = chrono::Local::now();
        let ip = "192.0.2.1".parse().unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:03"), now),
            DevicePolicy::Whitelist
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:02"), now),
            DevicePolicy::Block
        );
    }

    #[test]
    fn test_unknown_identity_is_refused_only_while_a_mac_block_is_active() {
        use crate::policy::DevicePolicy;
        use chrono::TimeZone;
        let mut config = base_config();
        config.device_blocking_enabled = true;
        config.device_schedules.push(DeviceSchedule {
            ip: "AA-BB-CC-DD-EE-02".into(),
            policy: "block".into(),
            days: vec!["sat".into()],
            start_time: "10:00".into(),
            end_time: "14:00".into(),
        });
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(config), 1).unwrap();
        let noon = chrono::Local
            .with_ymd_and_hms(2024, 1, 6, 12, 0, 0)
            .unwrap();
        let later = chrono::Local
            .with_ymd_and_hms(2024, 1, 6, 15, 0, 0)
            .unwrap();
        let ip = "2001:db8::1".parse().unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, None, noon),
            DevicePolicy::IdentityUnknown
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, None, later),
            DevicePolicy::Filtered
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:02"), noon),
            DevicePolicy::Block
        );
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:03"), noon),
            DevicePolicy::Filtered
        );
    }

    #[tokio::test]
    async fn test_legacy_ip_whitelist_stays_quarantined_after_mac_deletion() {
        use crate::policy::DevicePolicy;
        let mut config = base_config();
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("192.0.2.1".into(), "whitelist".into());
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:01".into(), "whitelist".into());
        let handle = ConfigHandle::new_ephemeral(config);
        handle
            .update("test:remove-mac", |config| {
                config.device_policies.remove("aa:bb:cc:dd:ee:01");
                Ok::<_, String>(())
            })
            .await
            .unwrap();
        let snapshot = handle.load_runtime();
        let ip = "192.0.2.1".parse().unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:02"), chrono::Local::now()),
            DevicePolicy::Filtered
        );
        assert_eq!(
            snapshot
                .config()
                .device_policy_ip_overrides
                .get("192.0.2.1"),
            Some(&false)
        );
        let serialized = toml::to_string(snapshot.config()).unwrap();
        let restored: Config = toml::from_str(&serialized).unwrap();
        let snapshot = RuntimeConfigSnapshot::try_from_config(Arc::new(restored), 3).unwrap();
        assert_eq!(
            snapshot.effective_device_policy(ip, None, chrono::Local::now()),
            DevicePolicy::Filtered
        );
    }

    pub(crate) fn base_config() -> Config {
        Config {
            upstreams: vec![UpstreamConfig {
                address: "1.1.1.2".to_string(),
                protocol: "udp".to_string(),
                tls_sni: None,
                doh_path: None,
            }],
            dnssec_validation: false,
            ratelimit_qps_per_worker: 1000,
            ratelimit_window_duration_secs: 1,
            ratelimit_max_ips: 10000,
            allowed_client_cidrs: vec![],
            cache_l1_max_entries: 10000,
            cache_l2_max_size_mb: 64,
            cache_negative_ttl_fallback_secs: 60,
            blocklist_urls: vec![
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
            ],
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
            protection_pause_default_duration_secs: default_pause_duration_secs(),
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
            logging_enabled: true,
            logging_db_path: ":memory:".to_string(),
            logging_channel_capacity: 1000,
            logging_retention_days: 90,
            bind_address: "127.0.0.1".to_string(),
            api_enabled: false,
            api_port: 8080,
            api_bind_address: "127.0.0.1".to_string(),
            api_allow_insecure_http: true,
            api_trusted_proxy_cidrs: default_trusted_proxy_cidrs(),
            api_key: "strong-unique-secret".to_string(),
            api_token: None,
            api_token_sha256: None,
            api_ratelimit_qps: 10,
        }
    }

    #[test]
    fn test_http_is_allowed_by_default_and_https_can_be_required() {
        let mut value = toml::Value::try_from(base_config()).unwrap();
        value
            .as_table_mut()
            .unwrap()
            .remove("api_allow_insecure_http");
        let config: Config = value.clone().try_into().unwrap();
        assert!(config.api_allow_insecure_http);

        value.as_table_mut().unwrap().insert(
            "api_allow_insecure_http".into(),
            toml::Value::Boolean(false),
        );
        let config: Config = value.try_into().unwrap();
        assert!(!config.api_allow_insecure_http);
    }

    #[test]
    fn custom_doh_with_dnssec_is_supported_and_proxy_cidrs_are_validated() {
        let mut config = base_config();
        config.encrypted_upstream_enabled = true;
        config.dnssec_validation = true;
        assert!(config.validate().is_ok());
        config.encrypted_upstream_enabled = false;
        assert!(config.validate().is_ok());
        config.api_trusted_proxy_cidrs = vec!["not-a-network".into()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("api_trusted_proxy_cidrs")
        );
    }

    #[test]
    fn test_valid_config_passes() {
        assert!(base_config().validate().is_ok());
    }

    #[test]
    fn test_allowed_client_cidr_membership_and_empty_allow_all() {
        let mut config = base_config();
        config.allowed_client_cidrs =
            vec!["192.168.1.0/24".to_string(), "2001:db8::/32".to_string()];
        let handle = ConfigHandle::new(config);
        let runtime = handle.load_runtime();
        assert!(runtime.allows_client("192.168.1.1".parse().unwrap()));
        assert!(!runtime.allows_client("192.168.2.1".parse().unwrap()));
        assert!(runtime.allows_client("2001:db8::1".parse().unwrap()));
        assert!(!runtime.allows_client("2001:db9::1".parse().unwrap()));

        let mut config = base_config();
        config.allowed_client_cidrs.clear();
        let runtime = ConfigHandle::new(config).load_runtime();
        assert!(runtime.allows_client("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_invalid_allowed_client_cidr_fails_validation() {
        let mut config = base_config();
        config.allowed_client_cidrs = vec!["192.168.1.0/not-a-prefix".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_no_upstreams_fails() {
        let mut c = base_config();
        c.upstreams.clear();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_invalid_bind_address_fails() {
        let mut c = base_config();
        c.bind_address = "not-an-ip".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_invalid_api_bind_address_fails_when_api_enabled() {
        let mut c = base_config();
        c.api_enabled = true;
        c.api_bind_address = "not-an-ip".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_invalid_upstream_ip_fails() {
        let mut c = base_config();
        c.upstreams[0].address = "not-an-ip".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_bare_ipv6_upstream_passes() {
        let mut c = base_config();
        c.upstreams[0].address = "2001:4860:4860::8888".to_string();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_ipv4_with_port_upstream_passes() {
        let mut c = base_config();
        c.upstreams[0].address = "1.1.1.1:53".to_string();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_bracketed_ipv6_with_port_upstream_passes() {
        let mut c = base_config();
        c.upstreams[0].address = "[2001:4860:4860::8888]:53".to_string();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_parse_upstream_ip_agrees_with_validate() {
        // Validation and resolver setup must accept the same upstream addresses.
        for addr in [
            "1.1.1.1",
            "1.1.1.1:53",
            "2001:4860:4860::8888",
            "[2001:4860:4860::8888]:53",
        ] {
            assert!(
                parse_upstream_ip(addr).is_some(),
                "expected '{addr}' to parse"
            );
        }
        assert!(parse_upstream_ip("not-an-ip").is_none());
    }

    #[test]
    fn test_upstream_address_parser_preserves_ports() {
        assert_eq!(
            parse_upstream_address("1.1.1.1:5353").unwrap(),
            ParsedUpstreamAddress {
                ip: "1.1.1.1".parse().unwrap(),
                port: Some(5353),
            }
        );
        assert_eq!(
            parse_upstream_address("[2001:db8::1]:5353").unwrap().port,
            Some(5353)
        );
        assert_eq!(parse_upstream_address("2001:db8::1").unwrap().port, None);
        assert!(parse_upstream_address("1.1.1.1:0").is_err());
        assert!(parse_upstream_address("[2001:db8::1]").is_err());
    }

    #[test]
    fn test_name_server_config_uses_explicit_port() {
        let upstream = UpstreamConfig {
            address: "127.0.0.1:5353".to_string(),
            protocol: "udp".to_string(),
            tls_sni: None,
            doh_path: None,
        };
        let config = build_name_server_config(&upstream).unwrap();
        assert_eq!(config.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.connections[0].port, 5353);

        let upstream = UpstreamConfig {
            address: "127.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            tls_sni: None,
            doh_path: None,
        };
        let config = build_name_server_config(&upstream).unwrap();
        assert_eq!(config.connections[0].port, 53);

        let upstream = UpstreamConfig {
            address: "127.0.0.1:8853".to_string(),
            protocol: "dot".to_string(),
            tls_sni: Some("resolver.example".to_string()),
            doh_path: None,
        };
        let config = build_name_server_config(&upstream).unwrap();
        assert_eq!(config.connections[0].port, 8853);

        let upstream = UpstreamConfig {
            address: "127.0.0.1:8443".to_string(),
            protocol: "doh".to_string(),
            tls_sni: Some("resolver.example".to_string()),
            doh_path: Some("/dns-query".to_string()),
        };
        let config = build_name_server_config(&upstream).unwrap();
        assert_eq!(config.connections[0].port, 8443);
    }

    #[test]
    fn test_dot_without_sni_fails() {
        let mut c = base_config();
        c.upstreams[0].protocol = "dot".to_string();
        c.upstreams[0].tls_sni = None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_iterative_resolver_with_dnssec_passes() {
        let mut c = base_config();
        c.recursive_resolver_enabled = true;
        c.dnssec_validation = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_iterative_resolver_without_dnssec_passes() {
        let mut c = base_config();
        c.recursive_resolver_enabled = true;
        c.dnssec_validation = false;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_unknown_protocol_fails() {
        let mut c = base_config();
        c.upstreams[0].protocol = "quic".to_string();
        let err = c.validate().unwrap_err();
        assert!(err.contains("quic"));
    }

    #[test]
    fn test_zero_ratelimit_fails() {
        let mut c = base_config();
        c.ratelimit_qps_per_worker = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_api_port_53_conflict_fails() {
        let mut c = base_config();
        c.api_enabled = true;
        c.api_port = 53;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_default_api_key_fails() {
        let mut c = base_config();
        c.api_enabled = true;
        c.api_key = "admin-secret-token".to_string();
        let err = c.validate().unwrap_err();
        assert!(err.contains("well-known default"));
    }

    #[test]
    fn test_configured_api_token_is_stored_only_as_a_digest() {
        let mut c = base_config();
        c.api_token = Some("operator-chosen-token".to_string());
        c.hash_configured_api_token().unwrap();
        assert_eq!(c.api_token, None);
        assert_eq!(
            c.api_token_sha256.as_deref(),
            Some(api_token_digest("operator-chosen-token").as_str())
        );
        assert!(
            !toml::to_string(&c)
                .unwrap()
                .contains("operator-chosen-token")
        );

        let mut short = base_config();
        short.api_token = Some("too-short".to_string());
        assert!(short.hash_configured_api_token().is_err());

        let mut both = base_config();
        both.api_token = Some("operator-chosen-token".to_string());
        both.api_token_sha256 = Some("a".repeat(64));
        assert!(both.hash_configured_api_token().is_err());
    }

    #[test]
    fn test_malformed_api_token_digest_fails() {
        let mut c = base_config();
        c.api_token_sha256 = Some("not-a-digest".to_string());
        assert!(c.validate().is_err());
        c.api_token_sha256 = Some("A".repeat(64));
        assert!(c.validate().is_err());
        c.api_token_sha256 = Some("a".repeat(64));
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_empty_api_key_fails() {
        let mut c = base_config();
        c.api_enabled = true;
        c.api_key = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_logging_nonexistent_parent_fails() {
        let mut c = base_config();
        c.logging_enabled = true;
        c.logging_db_path = "/nonexistent/path/dns.db".to_string();
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_default_toml_parsing() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
        let loaded = Config::load(&path).expect("Failed to parse config/default.toml");
        loaded
            .validate()
            .expect("config/default.toml must validate");
    }

    #[test]
    fn test_deploy_toml_parsing() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/config.toml");
        let loaded = Config::load(&path).expect("Failed to parse deploy/config.toml");
        loaded.validate().expect("deploy/config.toml must validate");
    }

    #[test]
    fn performance_limits_have_compatible_defaults_and_validate_bounds() {
        let mut config = base_config();
        for concurrency in [0, 17] {
            config.blocklist_fetch_concurrency = concurrency;
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .contains("blocklist_fetch_concurrency")
            );
        }
        config.blocklist_fetch_concurrency = 4;
        for timeout in [0, 5001] {
            config.discovery_timeout_ms = timeout;
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .contains("discovery_timeout_ms")
            );
        }
        let mut value = toml::Value::try_from(base_config()).unwrap();
        value
            .as_table_mut()
            .unwrap()
            .remove("blocklist_fetch_concurrency");
        value.as_table_mut().unwrap().remove("discovery_timeout_ms");
        let restored: Config = value.try_into().unwrap();
        assert_eq!(restored.blocklist_fetch_concurrency, 4);
        assert_eq!(restored.discovery_timeout_ms, 250);
    }

    #[test]
    fn test_pi_zero_toml_parsing() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/pi-zero.toml");
        let config = Config::load(&path).expect("Pi Zero configuration must load");
        assert_eq!(config.blocklist_fetch_concurrency, 1);
        assert_eq!(config.cache_l2_max_size_mb, 16);
        assert_eq!(config.cache_l1_max_entries, 5000);
        assert_eq!(config.ratelimit_max_ips, 1000);
        assert!(!config.dnssec_validation);
        assert!(!config.auto_block_upstream_sinkholes);
    }

    #[test]
    fn test_active_blocklist_urls_excludes_paused_category() {
        let mut c = base_config();
        c.blocklist_categories.push(BlocklistCategory {
            id: "gambling".to_string(),
            name: "Gambling".to_string(),
            urls: vec!["https://example.com/gambling.txt".to_string()],
            enabled: true,
        });
        let now = 1_000_000;
        c.category_pauses.insert("gambling".to_string(), now + 3600);
        let urls = c.active_blocklist_urls(now);
        assert!(!urls.contains(&"https://example.com/gambling.txt".to_string()));
    }

    #[test]
    fn test_active_blocklist_urls_includes_expired_pause() {
        let mut c = base_config();
        c.blocklist_categories.push(BlocklistCategory {
            id: "gambling".to_string(),
            name: "Gambling".to_string(),
            urls: vec!["https://example.com/gambling.txt".to_string()],
            enabled: true,
        });
        let now = 1_000_000;
        c.category_pauses.insert("gambling".to_string(), now - 10); // already expired
        let urls = c.active_blocklist_urls(now);
        assert!(urls.contains(&"https://example.com/gambling.txt".to_string()));
    }

    #[test]
    fn test_active_blocklist_urls_excludes_disabled_category_regardless_of_pause() {
        let mut c = base_config();
        c.blocklist_categories.push(BlocklistCategory {
            id: "gambling".to_string(),
            name: "Gambling".to_string(),
            urls: vec!["https://example.com/gambling.txt".to_string()],
            enabled: false,
        });
        let now = 1_000_000;
        // No pause entry at all -- merely-disabled must still be excluded.
        let urls = c.active_blocklist_urls(now);
        assert!(!urls.contains(&"https://example.com/gambling.txt".to_string()));
    }

    #[test]
    fn test_pause_sets_paused_until_from_default_duration() {
        let mut c = base_config();
        c.protection_pause_default_duration_secs = 100;
        let now = 1_000_000;
        let until = c.pause(&PauseScope::Global, now);
        assert_eq!(until, now + 100);
        assert_eq!(c.protection_paused_until, Some(now + 100));
    }

    #[test]
    fn test_pause_category_scope_sets_map_entry() {
        let mut c = base_config();
        c.protection_pause_default_duration_secs = 50;
        let now = 1_000_000;
        c.pause(&PauseScope::Category("gambling".to_string()), now);
        assert_eq!(c.category_pauses.get("gambling"), Some(&(now + 50)));
    }

    #[test]
    fn test_pause_service_scope_sets_map_entry() {
        let mut c = base_config();
        c.protection_pause_default_duration_secs = 50;
        let now = 1_000_000;
        c.pause(&PauseScope::Service("tiktok".to_string()), now);
        assert_eq!(c.service_pauses.get("tiktok"), Some(&(now + 50)));
    }

    #[test]
    fn test_resume_clears_and_reports_presence() {
        let mut c = base_config();
        let now = 1_000_000;
        c.pause(&PauseScope::Global, now);
        assert!(c.resume(&PauseScope::Global));
        assert_eq!(c.protection_paused_until, None);
    }

    #[test]
    fn test_resume_noop_returns_false() {
        let mut c = base_config();
        assert!(!c.resume(&PauseScope::Global));
        assert!(!c.resume(&PauseScope::Category("gambling".to_string())));
    }

    #[test]
    fn test_is_paused_true_only_while_live() {
        let mut c = base_config();
        let now = 1_000_000;
        c.protection_paused_until = Some(now + 10);
        assert!(c.is_paused(&PauseScope::Global, now));
        assert!(!c.is_paused(&PauseScope::Global, now + 20));
    }

    #[test]
    fn test_zero_pause_duration_fails_validate() {
        let mut c = base_config();
        c.protection_pause_default_duration_secs = 0;
        let err = c.validate().unwrap_err();
        assert!(err.contains("protection_pause_default_duration_secs"));
    }

    #[tokio::test]
    async fn runtime_snapshot_rebuilds_local_dns_index_on_write() {
        let handle = ConfigHandle::new(base_config());
        handle
            .update("test:local_dns", |config| {
                config.local_dns_records.push(LocalDnsRecord {
                    name: "Example.COM".to_string(),
                    record_type: "A".to_string(),
                    value: "192.0.2.1".to_string(),
                });
                Ok::<_, ()>(())
            })
            .await
            .unwrap();

        let runtime = handle.load_runtime();
        let query = hickory_proto::rr::LowerName::from(
            hickory_proto::rr::Name::from_ascii("example.com.").unwrap(),
        );
        let entry = runtime.local_dns().lookup(&query).unwrap();
        assert_eq!(entry.a, [std::net::Ipv4Addr::new(192, 0, 2, 1)]);
    }
}

#[cfg(test)]
mod device_pause_tests {
    use super::*;
    use crate::policy::DevicePolicy;
    use chrono::TimeZone;

    #[test]
    fn timed_mac_pause_overrides_schedules_then_expires_without_a_sweep() {
        let mut config = tests::base_config();
        config.device_blocking_enabled = true;
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:01".into(), "whitelist".into());
        config.device_schedules.push(DeviceSchedule {
            ip: "AA-BB-CC-DD-EE-01".into(),
            policy: "block".into(),
            days: vec!["sat".into()],
            start_time: "00:00".into(),
            end_time: "23:59".into(),
        });
        let now = chrono::Local
            .with_ymd_and_hms(2024, 1, 6, 12, 0, 0)
            .unwrap();
        config.pause_for(
            &PauseScope::Device("AA-BB-CC-DD-EE-01".into()),
            now.timestamp(),
            Some(300),
        );
        let runtime = ConfigHandle::new_ephemeral(config).load_runtime();
        for ip in ["192.0.2.1", "192.0.2.2"] {
            assert_eq!(
                runtime.effective_device_policy(
                    ip.parse().unwrap(),
                    Some("aa:bb:cc:dd:ee:01"),
                    now
                ),
                DevicePolicy::Whitelist
            );
        }
        assert_eq!(
            runtime.effective_device_policy(
                "192.0.2.1".parse().unwrap(),
                Some("aa:bb:cc:dd:ee:02"),
                now
            ),
            DevicePolicy::Filtered
        );
        assert_eq!(
            runtime.effective_device_policy("192.0.2.1".parse().unwrap(), None, now),
            DevicePolicy::IdentityUnknown
        );
        assert_eq!(
            runtime.effective_device_policy(
                "192.0.2.1".parse().unwrap(),
                Some("aa:bb:cc:dd:ee:01"),
                now + chrono::Duration::seconds(300)
            ),
            DevicePolicy::Block
        );
    }

    #[test]
    fn timed_pause_respects_master_switch_and_unknown_mac_restrictions() {
        let mut config = tests::base_config();
        let now = chrono::Local::now();
        config
            .device_policies
            .insert("aa:bb:cc:dd:ee:01".into(), "block".into());
        config.pause_for(
            &PauseScope::Device("192.0.2.1".into()),
            now.timestamp(),
            Some(300),
        );
        let ip = "192.0.2.1".parse().unwrap();
        let runtime = ConfigHandle::new_ephemeral(config.clone()).load_runtime();
        assert_eq!(
            runtime.effective_device_policy(ip, None, now),
            DevicePolicy::Filtered
        );
        config.device_blocking_enabled = true;
        let runtime = ConfigHandle::new_ephemeral(config).load_runtime();
        assert_eq!(
            runtime.effective_device_policy(ip, None, now),
            DevicePolicy::IdentityUnknown
        );
        assert_eq!(
            runtime.effective_device_policy(ip, Some("aa:bb:cc:dd:ee:01"), now),
            DevicePolicy::Whitelist
        );
        assert_eq!(
            runtime.effective_device_policy(
                "192.0.2.2".parse().unwrap(),
                Some("aa:bb:cc:dd:ee:01"),
                now
            ),
            DevicePolicy::Block
        );
    }

    #[test]
    fn device_pause_validation_and_normalized_resume_are_consistent() {
        let mut config = tests::base_config();
        for (id, until) in [
            ("invalid", 1000),
            ("192.0.2.1", 0),
            ("192.0.2.1", INDEFINITE_PAUSE_EPOCH),
        ] {
            config.device_pauses = std::collections::HashMap::from([(id.into(), until)]);
            assert!(config.validate().is_err());
        }
        config.device_pauses = std::collections::HashMap::from([
            ("AA-BB-CC-DD-EE-01".into(), 1000),
            ("aa:bb:cc:dd:ee:01".into(), 1001),
        ]);
        assert!(config.validate().is_err());
        config.device_pauses.remove("aa:bb:cc:dd:ee:01");
        assert!(config.validate().is_ok());
        assert!(config.is_paused(&PauseScope::Device("aa:bb:cc:dd:ee:01".into()), 999));
        assert!(config.resume(&PauseScope::Device("aa:bb:cc:dd:ee:01".into())));
        assert!(config.device_pauses.is_empty());
        let mut old_seed = toml::Value::try_from(config).unwrap();
        old_seed.as_table_mut().unwrap().remove("device_pauses");
        assert!(
            old_seed
                .try_into::<Config>()
                .unwrap()
                .device_pauses
                .is_empty()
        );
    }
}
