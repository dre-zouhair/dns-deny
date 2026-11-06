use super::*;
use minijinja::{Environment, context};
use std::sync::LazyLock;

static TEMPLATES: LazyLock<Environment<'static>> = LazyLock::new(|| {
    let mut env = Environment::new();
    env.set_debug(false);
    env.add_filter("truncate", |value: String, length: usize| {
        if value.chars().count() > length {
            format!("{}…", value.chars().take(length).collect::<String>())
        } else {
            value
        }
    });
    env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
    for (name, template) in [
        ("base.html", include_str!("../../templates/base.html")),
        ("forms.html", include_str!("../../templates/forms.html")),
        ("page.html", include_str!("../../templates/page.html")),
        ("login.html", include_str!("../../templates/login.html")),
        (
            "protection.html",
            include_str!("../../templates/protection.html"),
        ),
        ("lists.html", include_str!("../../templates/lists.html")),
        (
            "services.html",
            include_str!("../../templates/services.html"),
        ),
        ("network.html", include_str!("../../templates/network.html")),
        ("config.html", include_str!("../../templates/config.html")),
        ("doh.html", include_str!("../../templates/doh.html")),
        (
            "overview.html",
            include_str!("../../templates/overview.html"),
        ),
        ("queries.html", include_str!("../../templates/queries.html")),
        ("row.html", include_str!("../../templates/row.html")),
        ("error.html", include_str!("../../templates/error.html")),
    ] {
        env.add_template(name, template)
            .expect("valid embedded dashboard template");
    }
    env.add_global("asset_version", asset_version());
    env.add_filter("urlencode", |value: String| {
        percent_encoding::utf8_percent_encode(&value, percent_encoding::NON_ALPHANUMERIC)
            .to_string()
    });
    env.add_filter("number", |value: u64| {
        let digits = value.to_string();
        let mut output = String::new();
        for (index, digit) in digits.chars().enumerate() {
            if index > 0 && (digits.len() - index).is_multiple_of(3) {
                output.push(',');
            }
            output.push(digit);
        }
        output
    });
    env
});

/// Short content hash of the stylesheet and script, appended to their URLs
/// so an upgrade reaches browsers that still cache the previous files.
fn asset_version() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for file in ["styles.css", "ui.js"] {
        if let Ok(bytes) = std::fs::read(super::super::static_dir().join(file)) {
            hasher.update(&bytes);
        }
    }
    hasher.finalize()[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn template(name: &str, values: Value) -> WebResult<String> {
    TEMPLATES
        .get_template(name)
        .and_then(|template| template.render(values))
        .map_err(|error| {
            error!("Dashboard render failed: {error:#}");
            "Could not render dashboard section".into()
        })
}

pub(super) fn failure(message: &str) -> Response {
    // Error messages are escaped, never treated as template source.
    let message = minijinja::value::Value::from_serialize(message);
    let html = TEMPLATES
        .render_str(
            "<div id=\"ui-error\" class=\"rules-error\" role=\"alert\">{{ error }}</div>",
            context!(error => message),
        )
        .unwrap_or_default();
    Html(html).into_response()
}

pub(super) fn page_path(page: &str) -> &'static str {
    match page {
        "overview" => "/",
        "queries" => "/livetail.html",
        "lists" => "/lists.html",
        "services" => "/services.html",
        "network" => "/network.html",
        "config" => "/config.html",
        "doh" => "/doh.html",
        _ => "/",
    }
}

fn metadata(
    page: &str,
) -> (
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
) {
    match page {
        "lists" => (
            "Filtering Rule Manager",
            "Manage subscriptions, exact rules and regex patterns.",
            vec![
                ("blocklists", "Remote Blocklists"),
                ("allowdeny", "Allow / Deny Exact Lists"),
                ("regex", "Regex Rules"),
                ("overview", "Lists Summary"),
            ],
        ),
        "services" => (
            "Threat Defense & Service Control",
            "Control app access, malware detection and SafeSearch.",
            vec![
                ("services", "App Blocking"),
                ("autoblock", "Malware Auto-Block"),
                ("smartip", "Smart IP Blocking"),
                ("safesearch", "SafeSearch"),
            ],
        ),
        "network" => (
            "Network Devices & Local DNS",
            "Device policies, schedules, friendly names and local records.",
            vec![
                ("network", "Devices & Schedules"),
                ("aliases", "Client Aliases"),
                ("localdns", "Local DNS Records"),
            ],
        ),
        "config" => (
            "System Settings & Diagnostics",
            "Resolver configuration, maintenance and admin security.",
            vec![
                ("settings", "System Settings"),
                ("diagnostics", "Diagnostics & Probe"),
                ("security", "Admin Security"),
            ],
        ),
        "doh" => (
            "Upstream DNS Engine",
            "Configure encrypted DNS and primary upstream resolvers.",
            vec![
                ("doh", "Encrypted Upstreams (DoH)"),
                ("primary", "Primary Upstreams"),
            ],
        ),
        "queries" => (
            "Live Query Log & Audit Trail",
            "Inspect live traffic and search saved query logs.",
            vec![],
        ),
        _ => (
            "System Overview",
            "DNS query metrics, blocking statistics and resolver performance.",
            vec![],
        ),
    }
}

pub(super) fn section_tab(page: &str, section: &str) -> &'static str {
    match (page, section) {
        ("lists", "allow" | "deny") => "allowdeny",
        ("lists", "regex-allow" | "regex-deny") => "regex",
        ("lists", "summary") => "overview",
        ("lists", _) => "blocklists",
        ("services", "apps" | "logs") => "services",
        ("services", "autoblock") => "autoblock",
        ("services", "safesearch") => "safesearch",
        ("services", _) => "smartip",
        ("network", "aliases") => "aliases",
        ("network", "records") => "localdns",
        ("network", _) => "network",
        ("config", "security" | "api-token") => "security",
        ("config", "diagnostics" | "probe") => "diagnostics",
        ("config", _) => "settings",
        ("doh", "primary") => "primary",
        ("doh", _) => "doh",
        _ => "",
    }
}

pub(super) fn valid_section(page: &str, section: &str) -> bool {
    matches!(
        (page, section),
        (
            "lists",
            "remote" | "allow" | "deny" | "regex-allow" | "regex-deny" | "summary"
        ) | (
            "services",
            "apps" | "logs" | "detection" | "autoblock" | "ips" | "safesearch"
        ) | ("network", "devices" | "schedules" | "aliases" | "records")
            | (
                "config",
                "main"
                    | "startup"
                    | "cache"
                    | "pause"
                    | "diagnostics"
                    | "probe"
                    | "security"
                    | "api-token"
            )
            | ("doh", "encrypted" | "primary")
            | ("overview", "stats")
            | ("queries", "feed")
            | ("shell", "protection")
    ) && (section != "api-token" || cfg!(feature = "feat-json-api"))
}

pub(super) async fn page_context(
    state: &ApiState,
    page: &str,
    fields: &Fields,
) -> WebResult<Value> {
    let (title, description, tabs) = metadata(page);
    let tab = if tabs.iter().any(|(key, _)| key == &fields.get("tab")) {
        fields.get("tab")
    } else {
        tabs.first().map_or("", |(key, _)| *key)
    };
    let sections = match (page, tab) {
        ("lists", "allowdeny") => vec!["allow", "deny"],
        ("lists", "regex") => vec!["regex-deny", "regex-allow"],
        ("lists", "overview") => vec!["summary"],
        ("lists", _) => vec!["remote"],
        ("services", "autoblock") => vec!["detection", "autoblock"],
        ("services", "smartip") => vec!["detection", "ips"],
        ("services", "safesearch") => vec!["safesearch"],
        ("services", _) => vec!["apps", "logs"],
        ("network", "aliases") => vec!["aliases"],
        ("network", "localdns") => vec!["records"],
        ("network", _) => vec!["devices", "schedules"],
        // The token card only exists in builds that serve the JSON API.
        ("config", "security") if cfg!(feature = "feat-json-api") => {
            vec!["security", "api-token"]
        }
        ("config", "security") => vec!["security"],
        ("config", "diagnostics") => vec!["diagnostics", "probe"],
        ("config", _) => vec!["main", "cache", "pause", "startup"],
        ("doh", "primary") => vec!["primary"],
        ("doh", _) => vec!["encrypted"],
        ("queries", _) => vec!["feed"],
        _ => vec!["stats"],
    };
    let mut rendered = Vec::new();
    for name in sections {
        let html = match section(state, page, name, fields, "", "").await {
            Ok(html) => html,
            Err(error) => TEMPLATES.render_str(
                "<section id=\"section-{{ page }}-{{ name }}\" class=\"card\"><p class=\"rules-error\" role=\"alert\">{{ error }}</p><a href=\"{{ path }}?tab={{ tab }}\">Reload this page</a></section>",
                context!(page => page, name => name, error => error, path => page_path(page), tab => tab),
            ).map_err(|_| "Could not render dashboard error".to_string())?,
        };
        rendered.push(json!({"name": name, "html": html}));
    }
    Ok(
        json!({"page": page, "path": page_path(page), "title": title, "description": description, "tab": tab, "tabs": tabs, "sections": rendered, "protection": protection_html(state), "overrides": {}}),
    )
}

pub(super) fn full(page: &str, context: Value) -> Response {
    match template(
        if page == "login" {
            "login.html"
        } else {
            "page.html"
        },
        context,
    ) {
        Ok(html) => super::super::reactive_page(&html),
        Err(error) => failure_page(&error),
    }
}

/// A complete error document for navigations; `failure` is the fragment
/// patched into an already-loaded page.
pub(super) fn failure_page(message: &str) -> Response {
    let mut response = match template("error.html", json!({"title": "Error", "error": message})) {
        Ok(html) => super::super::reactive_page(&html),
        Err(_) => message.to_owned().into_response(),
    };
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

fn protection_html(state: &ApiState) -> String {
    let config = state.config.load();
    let status = core_dns::protection::live_status(&config, core_dns::config::now_epoch());
    template("protection.html", json!({"status": status.global_paused_until.is_some(), "until": status.global_paused_until})).unwrap_or_default()
}
pub(super) fn protection(state: &ApiState) -> Response {
    Html(protection_html(state)).into_response()
}

pub(super) async fn section(
    state: &ApiState,
    page: &str,
    name: &str,
    fields: &Fields,
    notice: &str,
    error: &str,
) -> WebResult<String> {
    section_revealing(state, page, name, fields, notice, error, "").await
}

/// Renders a section that may display a one-time `secret` (a newly issued
/// API token). Secrets come only from an action's outcome, never from
/// request fields, so a crafted URL cannot make the page present one.
pub(super) async fn section_revealing(
    state: &ApiState,
    page: &str,
    name: &str,
    fields: &Fields,
    notice: &str,
    error: &str,
    secret: &str,
) -> WebResult<String> {
    if !valid_section(page, name) {
        return Err("Unknown dashboard section".into());
    }
    if page == "shell" {
        let config = state.config.load();
        let status = core_dns::protection::live_status(&config, core_dns::config::now_epoch());
        return template(
            "protection.html",
            json!({"status": status.global_paused_until.is_some(), "until": status.global_paused_until, "notice": notice, "error": error}),
        );
    }
    let mut context = json!({"page": page, "path": page_path(page), "section": name, "form": fields.values(), "form_id": fields.get("_form"), "notice": notice, "error": error, "secret": secret, "query": fields.get("q")});
    // A submitted form gets fresh controls after success, including when its
    // default attributes match the old defaults. Unsubmitted drafts stay put.
    context["form_version"] = if !error.is_empty() {
        json!(fields.get("_version"))
    } else {
        json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_string()
        )
    };
    let config = state.config.load();
    match (page, name) {
        ("lists", "allow" | "deny" | "regex-allow" | "regex-deny") => {
            let Json(entries) = match name {
                "allow" => get_allow(State(state.clone())).await,
                "deny" => get_deny(State(state.clone())).await,
                "regex-allow" => get_regex_allow(State(state.clone())).await,
                _ => get_regex_deny(State(state.clone())).await,
            };
            context["total"] = json!(entries.len());
            context["entries"] = json!(
                entries
                    .into_iter()
                    .filter(|entry| entry
                        .to_lowercase()
                        .contains(&fields.get("q").to_lowercase()))
                    .collect::<Vec<_>>()
            );
            context["title"] = json!(match name {
                "allow" => "Allow List",
                "deny" => "Deny List",
                "regex-allow" => "Regex Allowlist",
                _ => "Regex Blocklist",
            });
        }
        ("lists", "remote" | "summary") => {
            context["summary"] = serialize(get_lists_summary(State(state.clone())).await.0)?;
            context["sources"] = json!(config.blocklist_urls);
        }
        ("services", "apps") => {
            context["services"] = serialize(
                get_blocked_services(State(state.clone()))
                    .await
                    .0
                    .into_iter()
                    .filter(|service| {
                        format!("{} {}", service.name, service.description)
                            .to_lowercase()
                            .contains(&fields.get("q").to_lowercase())
                    })
                    .collect::<Vec<_>>(),
            )?;
            context["pauses"] = json!(
                core_dns::protection::live_status(&config, core_dns::config::now_epoch())
                    .service_pauses
            );
        }
        ("services", "logs") => {
            if !fields.get("q").is_empty() {
                let logs = get_logs(
                    State(state.clone()),
                    Query(LogQueryRequest {
                        q: Some(fields.get("q").into()),
                        verdict: None,
                        client: None,
                        limit: Some(100),
                        offset: Some(0),
                    }),
                )
                .await
                .map_err(api_error)?
                .0;
                let mut names: Vec<String> = logs
                    .logs
                    .into_iter()
                    .map(|entry| entry.name.trim_end_matches('.').into())
                    .collect();
                names.sort();
                names.dedup();
                context["domains"] = json!(names);
            }
        }
        ("services", "detection") => {
            context["auto"] = json!(config.auto_block_upstream_sinkholes);
            context["smart"] = json!(config.smart_ip_blocking);
        }
        ("services", "autoblock") => {
            context["data"] = serialize(
                get_auto_blocked(State(state.clone()))
                    .await
                    .map_err(api_error)?
                    .0,
            )?;
        }
        ("services", "ips") => {
            let data = get_malicious_ips(State(state.clone()))
                .await
                .map_err(api_error)?
                .0;
            context["total"] = json!(data.count);
            context["ips"] = json!(
                data.ips
                    .into_iter()
                    .filter(|ip| ip.contains(fields.get("q")))
                    .collect::<Vec<_>>()
            );
        }
        ("services", "safesearch") => {
            context["enabled"] = json!(if error.is_empty() {
                config.enforce_safesearch
            } else {
                fields.checked("enabled")
            });
        }
        ("network", "devices") => {
            let runtime = state.config.load_runtime();
            let now = core_dns::config::now_epoch();
            let format_until = |until| {
                chrono::DateTime::from_timestamp(until, 0)
                    .map(|date| date.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| until.to_string())
            };
            let pauses = core_dns::protection::live_status(&config, now).device_pauses;
            let mut active: Vec<_> = pauses.into_iter().collect();
            active.sort_by(|a, b| a.0.cmp(&b.0));
            context["device_pauses"] = json!(
                active
                    .into_iter()
                    .map(|(id, until)| json!({"id":id, "until":format_until(until)}))
                    .collect::<Vec<_>>()
            );
            let devices = state.network_tracker.get_devices().await;
            let mut rows = Vec::new();
            for device in devices {
                let ip = device.ip.to_string();
                let mac = device.mac.unwrap_or_default();
                let lookup = |identifier: &str| {
                    config
                        .device_policies
                        .iter()
                        .find(|(key, _)| {
                            core_dns::config::normalize_device_identifier(key)
                                == core_dns::config::normalize_device_identifier(identifier)
                        })
                        .map(|(_, value)| value.clone())
                };
                let policy = lookup(&mac)
                    .or_else(|| lookup(&ip))
                    .unwrap_or_else(|| "default".into());
                let alias = config
                    .client_aliases
                    .iter()
                    .find(|alias| {
                        core_dns::config::normalize_device_identifier(&alias.identifier) == ip
                            || (!mac.is_empty()
                                && core_dns::config::normalize_device_identifier(&alias.identifier)
                                    == core_dns::config::normalize_device_identifier(&mac))
                    })
                    .map(|alias| alias.name.clone())
                    .unwrap_or_default();
                if format!("{ip} {mac} {alias}")
                    .to_lowercase()
                    .contains(&fields.get("q").to_lowercase())
                {
                    let normalized_mac = core_dns::config::normalize_device_identifier(&mac);
                    let pause = runtime.device_pause(
                        &ip,
                        (!mac.is_empty()).then_some(normalized_mac.as_str()),
                        now,
                    );
                    let pause_id = pause.map(|(id, _)| id.to_owned()).unwrap_or_else(|| {
                        if mac.is_empty() {
                            ip.clone()
                        } else {
                            normalized_mac.clone()
                        }
                    });
                    let effective = runtime.effective_device_policy(
                        device.ip,
                        (!mac.is_empty()).then_some(mac.as_str()),
                        chrono::Local::now(),
                    );
                    let policy_status = if config.is_paused(
                        &core_dns::config::PauseScope::Global,
                        core_dns::config::now_epoch(),
                    ) {
                        "Protection paused"
                    } else if !config.device_blocking_enabled {
                        "Device policies disabled"
                    } else if pause.is_some()
                        && effective == core_dns::policy::DevicePolicy::Whitelist
                    {
                        "Protection paused for this device"
                    } else if effective == core_dns::policy::DevicePolicy::Filtered
                        && policy == "whitelist"
                        && config.device_policy_ip_overrides.get(&ip) == Some(&false)
                    {
                        "Whitelist needs confirmation for this device"
                    } else {
                        match effective {
                            core_dns::policy::DevicePolicy::Block => "Currently blocked",
                            core_dns::policy::DevicePolicy::Whitelist => {
                                "Currently bypassing protection"
                            }
                            core_dns::policy::DevicePolicy::Filtered => "Currently filtered",
                            core_dns::policy::DevicePolicy::IdentityUnknown => {
                                "Waiting for device identity; DNS refused"
                            }
                        }
                    };
                    rows.push(json!({"ip": ip, "mac": mac, "alias": alias, "policy": policy, "policy_status": policy_status, "count": device.query_count, "paused": pause.is_some(), "pause_id": pause_id, "pause_until": pause.map(|(_, until)| format_until(until))}));
                }
            }
            context["devices"] = json!(rows);
            context["enabled"] = json!(config.device_blocking_enabled);
        }
        ("network", "schedules") => {
            context["entries"] = json!(config.device_schedules);
            context["selected_days"] = json!(fields.all("days"));
        }
        ("network", "aliases") => {
            context["entries"] = json!(config.client_aliases);
        }
        ("network", "records") => {
            context["entries"] = json!(
                config
                    .local_dns_records
                    .iter()
                    .filter(|record| format!(
                        "{} {} {}",
                        record.name, record.record_type, record.value
                    )
                    .to_lowercase()
                    .contains(&fields.get("q").to_lowercase()))
                    .collect::<Vec<_>>()
            );
        }
        ("config", "main") | ("doh", "primary") => {
            let upstreams = if fields.get("_upstreams_present") == "1" {
                actions::upstreams(fields)?
            } else {
                config.upstreams.clone()
            };
            let pages = upstreams.len().div_ceil(4).max(1);
            context["upstreams"] = serialize(upstreams)?;
            context["editor_page"] = json!(
                fields
                    .get("editor_page")
                    .parse::<usize>()
                    .unwrap_or(1)
                    .clamp(1, pages)
            );
            context["pages"] = json!(pages);
            context["recursive"] = json!(if fields.get("_upstreams_present") == "1" {
                fields.checked("recursive_resolver_enabled")
            } else {
                config.recursive_resolver_enabled
            });
        }
        ("config", "startup") => {
            let mut snapshot = serialize(config.as_ref())?;
            let snapshot_fields = snapshot.as_object_mut().unwrap();
            snapshot_fields.remove("api_key");
            snapshot_fields.remove("api_token_sha256");
            context["startup"] = json!(
                [
                    "dnssec_validation",
                    "cache_l1_max_entries",
                    "cache_l2_max_size_mb",
                    "cache_negative_ttl_fallback_secs",
                    "ratelimit_qps_per_worker",
                    "ratelimit_window_duration_secs",
                    "ratelimit_max_ips",
                    "logging_enabled",
                    "logging_db_path",
                    "logging_channel_capacity",
                    "logging_retention_days",
                    "api_enabled",
                    "api_port",
                    "api_ratelimit_qps"
                ]
                .into_iter()
                .map(|key| json!({"name": key, "value": snapshot[key]}))
                .collect::<Vec<_>>()
            );
        }
        ("config", "pause") => {
            context["seconds"] = json!(if fields.get("seconds").is_empty() {
                config.protection_pause_default_duration_secs.to_string()
            } else {
                fields.get("seconds").into()
            });
        }
        ("config", "cache") => {
            context["stats"] = serialize(get_cache_stats(State(state.clone())).await.0)?;
        }
        ("config", "diagnostics") => {
            context["data"] = serialize(
                get_diagnostics(State(state.clone()))
                    .await
                    .map_err(api_error)?
                    .0,
            )?;
        }
        ("config", "probe") => {
            if !fields.get("domain").is_empty() {
                let start = Instant::now();
                match probe_domain(
                    State(state.clone()),
                    Query(ProbeQuery {
                        domain: fields.get("domain").into(),
                    }),
                )
                .await
                {
                    Ok(data) => {
                        context["result"] = serialize(data.0)?;
                        context["elapsed"] =
                            json!(format!("{:.1}", start.elapsed().as_secs_f64() * 1000.0));
                    }
                    Err(error) => context["error"] = json!(api_error(error)),
                }
            }
        }
        ("config", "security") => {}
        ("config", "api-token") => {
            context["configured"] = json!(config.api_token_sha256.is_some());
        }
        ("doh", "encrypted") => {
            let draft = fields.get("_doh_present") == "1";
            context["enabled"] = json!(if draft {
                fields.checked("enabled")
            } else {
                config.encrypted_upstream_enabled
            });
            context["active_url"] = json!(if draft {
                fields.get("active_url").to_owned()
            } else {
                config.encrypted_upstream_url.clone()
            });
            context["urls"] = json!(if draft {
                fields.all("url")
            } else {
                config.doh_upstreams.clone()
            });
        }
        ("overview", "stats") => {
            overview(state, fields, &mut context).await?;
        }
        ("queries", "feed") => {
            stream::history(state, fields, &mut context).await?;
        }
        _ => return Err("Unknown dashboard section".into()),
    }
    let file = if (page == "doh" && name == "primary") || (page == "config" && name == "main") {
        "config.html"
    } else {
        match page {
            "lists" => "lists.html",
            "services" => "services.html",
            "network" => "network.html",
            "config" => "config.html",
            "doh" => "doh.html",
            "overview" => "overview.html",
            _ => "queries.html",
        }
    };
    template(file, context)
}

/// Ranking widths are percentages; HTML labels retain their readable font size.
const BAR_MAX_PERCENT: f64 = 100.0;

async fn overview(state: &ApiState, fields: &Fields, context: &mut Value) -> WebResult<()> {
    let window = if ["24h", "7d", "all"].contains(&fields.get("window")) {
        fields.get("window")
    } else {
        "24h"
    };
    let query = || {
        Query(WindowQuery {
            window: Some(window.into()),
        })
    };
    context["window"] = json!(window);
    context["stats"] = get_stats(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0;
    context["domains"] = get_top_blocked(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0["domains"]
        .clone();
    context["clients"] = get_top_clients(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0["clients"]
        .clone();
    context["types"] = get_query_types(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0["types"]
        .clone();
    context["upstreams"] = get_upstreams_analytics(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0["upstreams"]
        .clone();
    context["buckets"] = get_queries_over_time(State(state.clone()), query())
        .await
        .map_err(api_error)?
        .0["buckets"]
        .clone();
    context["rate"] = json!(format!(
        "{:.1}",
        context["stats"]["block_rate"].as_f64().unwrap_or(0.0)
    ));
    for (source, label, target) in [
        ("domains", "domain", "domain_bars"),
        ("clients", "client_ip", "client_bars"),
        ("types", "qtype", "type_bars"),
        ("upstreams", "upstream", "upstream_bars"),
    ] {
        let values = context[source].as_array().cloned().unwrap_or_default();
        let maximum = values
            .iter()
            .map(|value| value["count"].as_u64().unwrap_or(0))
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        context[target] = json!(values.iter().take(15).map(|value| json!({"label": value[label], "count": value["count"], "width": value["count"].as_u64().unwrap_or(0) as f64 / maximum * BAR_MAX_PERCENT})).collect::<Vec<_>>());
    }
    let buckets = context["buckets"].as_array().cloned().unwrap_or_default();
    let maximum = buckets
        .iter()
        .map(|bucket| bucket["total"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(1)
        .max(1) as f64;
    let span = buckets.len().saturating_sub(1).max(1) as f64;
    let mut total_points = Vec::new();
    let mut blocked_points = Vec::new();
    let mut timeline = Vec::new();
    for (index, bucket) in buckets.iter().enumerate() {
        let x = 40.0 + index as f64 / span * 740.0;
        let y = 200.0 - bucket["total"].as_u64().unwrap_or(0) as f64 / maximum * 180.0;
        let blocked = 200.0 - bucket["blocked"].as_u64().unwrap_or(0) as f64 / maximum * 180.0;
        total_points.push(format!("{x:.1},{y:.1}"));
        blocked_points.push(format!("{x:.1},{blocked:.1}"));
        timeline.push(json!({"x": x, "y": y, "label": bucket["hour"], "total": bucket["total"], "blocked": bucket["blocked"]}));
    }
    context["total_points"] = json!(total_points.join(" "));
    context["blocked_points"] = json!(blocked_points.join(" "));
    context["timeline"] = json!(timeline);
    Ok(())
}
