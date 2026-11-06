use super::*;
use core_dns::config::{CustomService, UpstreamConfig};

#[derive(Default)]
pub(super) struct Outcome {
    pub notice: String,
    pub cookie: Option<HeaderValue>,
    pub draft: Option<Fields>,
    /// Shown once in the re-rendered section, never stored or echoed.
    pub secret: String,
}

async fn edit_config<F>(state: &ApiState, edit: F) -> WebResult<()>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    commit_config(state, edit).await?;
    state.l1_cache.clear();
    state.l2_cache.clear().await;
    Ok(())
}

/// Commits a configuration edit that cannot change DNS answers, so the
/// response caches are kept.
async fn commit_config<F>(state: &ApiState, edit: F) -> WebResult<()>
where
    F: FnOnce(&mut Config) -> Result<(), String>,
{
    state
        .config
        .update("web:form", edit)
        .await
        .map_err(|error| match error {
            ConfigUpdateError::Mutation(message) | ConfigUpdateError::Validation(message) => {
                message
            }
            ConfigUpdateError::Persistence(error) => {
                error!("Dashboard configuration commit failed: {error}");
                "Could not persist configuration. Your changes were not saved.".into()
            }
        })?;
    Ok(())
}

pub(super) fn upstreams(fields: &Fields) -> WebResult<Vec<UpstreamConfig>> {
    let addresses = fields.all("address");
    let protocols = fields.all("protocol");
    let snis = fields.all("tls_sni");
    let paths = fields.all("doh_path");
    if [protocols.len(), snis.len(), paths.len()]
        .iter()
        .any(|length| *length != addresses.len())
    {
        return Err("Incomplete upstream form".into());
    }
    Ok(addresses
        .into_iter()
        .enumerate()
        .map(|(index, address)| UpstreamConfig {
            address: address.trim().into(),
            protocol: protocols[index].clone(),
            tls_sni: (!snis[index].trim().is_empty()).then(|| snis[index].trim().into()),
            doh_path: (!paths[index].trim().is_empty()).then(|| paths[index].trim().into()),
        })
        .collect())
}

fn upstream_fields(mut fields: Fields, upstreams: &[UpstreamConfig], page: usize) -> Fields {
    fields.0.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            "address" | "protocol" | "tls_sni" | "doh_path" | "editor_page" | "intent"
        )
    });
    for upstream in upstreams {
        fields.0.extend([
            ("address".into(), upstream.address.clone()),
            ("protocol".into(), upstream.protocol.clone()),
            (
                "tls_sni".into(),
                upstream.tls_sni.clone().unwrap_or_default(),
            ),
            (
                "doh_path".into(),
                upstream.doh_path.clone().unwrap_or_default(),
            ),
        ]);
    }
    fields.0.push(("editor_page".into(), page.to_string()));
    fields
}

pub(super) async fn apply(
    state: &ApiState,
    page: &str,
    section: &str,
    fields: &Fields,
    headers: &HeaderMap,
) -> WebResult<Outcome> {
    let intent = fields.get("intent");
    let mut result = Outcome::default();
    if matches!((page, section), ("config", "main") | ("doh", "primary")) {
        let mut draft = upstreams(fields)?;
        let mut editor_page = fields
            .get("editor_page")
            .parse::<usize>()
            .unwrap_or(1)
            .max(1);
        if intent != "save" {
            match intent {
                "add" => {
                    draft.push(UpstreamConfig {
                        address: "1.1.1.1:53".into(),
                        protocol: "udp".into(),
                        tls_sni: None,
                        doh_path: None,
                    });
                    editor_page = draft.len().div_ceil(4);
                }
                "next" => editor_page = editor_page.saturating_add(1),
                "previous" => editor_page = editor_page.saturating_sub(1).max(1),
                "reset" => {
                    return Ok(result);
                }
                value if value.starts_with("remove:") => {
                    let index = value[7..]
                        .parse::<usize>()
                        .map_err(|_| "Invalid upstream index")?;
                    if index >= draft.len() {
                        return Err("Unknown upstream".into());
                    }
                    draft.remove(index);
                }
                _ => return Err("Unknown upstream action".into()),
            }
            result.draft = Some(upstream_fields(fields.clone(), &draft, editor_page));
            return Ok(result);
        }
        let recursive = fields.checked("recursive_resolver_enabled");
        edit_config(state, |config| {
            config.upstreams = draft;
            if page == "config" {
                config.recursive_resolver_enabled = recursive;
            }
            Ok(())
        })
        .await?;
        result.notice =
            "Settings saved. Restart the server to apply resolver and primary upstream changes."
                .into();
        return Ok(result);
    }
    match (page, section) {
        ("lists", kind @ ("allow" | "deny" | "regex-allow" | "regex-deny")) => {
            let payload = Json(LocalRuleRequest {
                pattern: fields.get("pattern").trim().into(),
            });
            let state = State(state.clone());
            match (kind, intent) {
                ("allow", "add") => {
                    let _ = add_allow(state, payload).await.map_err(api_error)?;
                }
                ("deny", "add") => {
                    let _ = add_deny(state, payload).await.map_err(api_error)?;
                }
                ("allow", "delete") => {
                    let _ = remove_allow(state, payload).await.map_err(api_error)?;
                }
                ("deny", "delete") => {
                    let _ = remove_deny(state, payload).await.map_err(api_error)?;
                }
                ("regex-allow", "add") => {
                    let _ = add_regex_allow(state, payload).await.map_err(api_error)?;
                }
                ("regex-deny", "add") => {
                    let _ = add_regex_deny(state, payload).await.map_err(api_error)?;
                }
                ("regex-allow", "delete") => {
                    let _ = remove_regex_allow(state, payload)
                        .await
                        .map_err(api_error)?;
                }
                ("regex-deny", "delete") => {
                    let _ = remove_regex_deny(state, payload).await.map_err(api_error)?;
                }
                _ => return Err("Unknown rule action".into()),
            }
            result.notice = "Rule updated.".into();
        }
        ("lists", "remote") => {
            if intent == "sync" {
                let _ = sync_sources(State(state.clone())).await;
                result.notice = "Blocklist sync initiated.".into();
                return Ok(result);
            }
            if matches!(intent, "pause" | "resume") {
                pause(state, fields).await?;
                return Ok(result);
            }
            edit_config(state, |config| {
                match intent {
                    "add" => {
                        let url = fields.get("url").trim();
                        if !url.starts_with("https://") && !url.starts_with("http://") {
                            return Err("Enter an HTTP or HTTPS source URL".into());
                        }
                        if config.blocklist_urls.iter().any(|existing| existing == url) {
                            return Err("Source URL already added".into());
                        }
                        config.blocklist_urls.push(url.into());
                    }
                    "delete" => {
                        config.blocklist_urls.retain(|url| url != fields.get("url"));
                    }
                    "toggle" => {
                        let category = config
                            .blocklist_categories
                            .iter_mut()
                            .find(|category| category.id == fields.get("id"))
                            .ok_or("Unknown category")?;
                        category.enabled = fields.checked("enabled");
                    }
                    _ => return Err("Unknown source action".into()),
                }
                Ok(())
            })
            .await?;
            state
                .updater
                .ensure_current_sources()
                .await
                .map_err(|e| e.to_string())?;
            let _ = sync_sources(State(state.clone())).await;
            result.notice = "Blocklist settings saved.".into();
        }
        ("services", "apps") => {
            if matches!(intent, "pause" | "resume") {
                pause(state, fields).await?;
                return Ok(result);
            }
            edit_config(state, |config| {
                let id = fields.get("id");
                match intent {
                    "toggle" => {
                        if let Some(custom) = config
                            .custom_services
                            .iter_mut()
                            .find(|service| service.id == id)
                        {
                            custom.enabled = fields.checked("blocked");
                        } else if core_dns::services::BLOCKED_SERVICES
                            .iter()
                            .any(|service| service.id == id)
                        {
                            config.blocked_services.retain(|existing| existing != id);
                            if fields.checked("blocked") {
                                config.blocked_services.push(id.into());
                            }
                        } else {
                            return Err("Unknown service".into());
                        }
                    }
                    "delete" => {
                        config.custom_services.retain(|service| service.id != id);
                    }
                    "add" => {
                        let name = fields.get("name").trim();
                        let wildcards: Vec<String> = fields
                            .get("wildcards")
                            .split(',')
                            .map(|value| value.trim().to_lowercase())
                            .filter(|value| !value.is_empty())
                            .collect();
                        if name.is_empty() || wildcards.is_empty() {
                            return Err("App name and wildcard domains are required".into());
                        }
                        if config
                            .custom_services
                            .iter()
                            .any(|service| service.name.trim().eq_ignore_ascii_case(name))
                        {
                            return Err("An app with this name already exists".into());
                        }
                        let id = custom_service_id(name, |candidate| {
                            config
                                .custom_services
                                .iter()
                                .any(|service| service.id == candidate)
                        });
                        config.custom_services.push(CustomService {
                            id,
                            name: name.into(),
                            description: fields.get("description").trim().into(),
                            wildcards,
                            enabled: true,
                        });
                    }
                    _ => return Err("Unknown service action".into()),
                }
                Ok(())
            })
            .await?;
            result.notice = "App blocking configuration saved.".into();
        }
        ("services", "detection") => {
            edit_config(state, |config| {
                match fields.get("field") {
                    "auto" => config.auto_block_upstream_sinkholes = fields.checked("enabled"),
                    "smart" => config.smart_ip_blocking = fields.checked("enabled"),
                    _ => return Err("Unknown detection setting".into()),
                }
                Ok(())
            })
            .await?;
            result.notice = "Detection setting saved.".into();
        }
        ("services", "ips") => {
            match intent {
                "add" => {
                    let _ = add_malicious_ip(
                        State(state.clone()),
                        Json(AddMaliciousIpRequest {
                            ip: fields.get("ip").trim().into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                "delete" => {
                    let _ = remove_malicious_ip(
                        State(state.clone()),
                        Json(RemoveMaliciousIpRequest {
                            ip: fields.get("ip").into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                _ => return Err("Unknown IP action".into()),
            }
            result.notice = "Malicious IP list updated.".into();
        }
        ("services", "safesearch") => {
            let _ = update_safesearch_config(
                State(state.clone()),
                Json(SafeSearchConfigDto {
                    enforce_safesearch: fields.checked("enabled"),
                }),
            )
            .await
            .map_err(api_error)?;
            result.notice = "SafeSearch settings saved.".into();
        }
        ("network", "devices") => {
            if matches!(intent, "pause" | "resume") {
                if fields.get("scope") != "device" {
                    return Err("Device pause scope is required".into());
                }
                pause(state, fields).await?;
                result.notice = if intent == "pause" {
                    "Device protection paused until its timer expires."
                } else {
                    "Device pause cleared; current policies apply."
                }
                .into();
                return Ok(result);
            }
            if intent == "enabled" {
                let _ = update_device_blocking_config(
                    State(state.clone()),
                    Json(DeviceBlockingConfigDto {
                        device_blocking_enabled: fields.checked("enabled"),
                    }),
                )
                .await
                .map_err(api_error)?;
            } else if intent == "policy" {
                let policy = fields.get("policy");
                if !["default", "block", "whitelist"].contains(&policy) {
                    return Err("Unknown device policy".into());
                }
                let ip = fields.get("ip");
                let mac = fields.get("mac");
                let identifier = if mac.is_empty() { ip } else { mac };
                if !core_dns::policy::valid_device_identifier(identifier)
                    || ip.parse::<IpAddr>().is_err()
                    || (!mac.is_empty() && !MAC_ADDR_RE.is_match(mac))
                {
                    return Err("Invalid IP or MAC address".into());
                }
                let observed = state.network_tracker.get_devices().await;
                let identity = core_dns::config::normalize_device_identifier(identifier);
                let obsolete_ips: Vec<String> = observed
                    .iter()
                    .filter(|device| {
                        device.mac.as_deref().is_some_and(|value| {
                            core_dns::config::normalize_device_identifier(value) == identity
                        })
                    })
                    .map(|device| device.ip.to_string())
                    .chain(std::iter::once(ip.to_string()))
                    .collect();
                edit_config(state, |config| {
                    config.device_pauses.retain(|existing, _| {
                        let key = core_dns::config::normalize_device_identifier(existing);
                        key != identity && !obsolete_ips.contains(&key)
                    });
                    config.device_policies.retain(|existing, _| {
                        let key = core_dns::config::normalize_device_identifier(existing);
                        key != identity && !obsolete_ips.contains(&key)
                    });
                    config
                        .device_policy_ip_overrides
                        .retain(|id, _| !obsolete_ips.contains(id));
                    config.device_policy_ip_overrides.remove(&identity);
                    if policy == "whitelist" && identity.parse::<IpAddr>().is_ok() {
                        config
                            .device_policy_ip_overrides
                            .insert(identity.clone(), true);
                    }
                    if policy != "default" {
                        config
                            .device_policies
                            .insert(identity.clone(), policy.into());
                    }
                    Ok(())
                })
                .await?;
            } else {
                return Err("Unknown device action".into());
            }
            result.notice = "Device policy saved.".into();
        }
        ("network", "schedules") => {
            match intent {
                "add" => {
                    let days = fields.all("days");
                    if days.is_empty() {
                        return Err("Select at least one day".into());
                    }
                    let _ = add_schedule(
                        State(state.clone()),
                        Json(AddScheduleRequest {
                            ip: fields.get("ip").trim().into(),
                            policy: fields.get("policy").into(),
                            days,
                            start_time: fields.get("start_time").into(),
                            end_time: fields.get("end_time").into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                "delete" => {
                    let _ = delete_schedule(State(state.clone()), Path(fields.get("ip").into()))
                        .await
                        .map_err(api_error)?;
                }
                _ => return Err("Unknown schedule action".into()),
            }
            result.notice = "Device schedules updated.".into();
        }
        ("network", "aliases") => {
            match intent {
                "add" => {
                    let _ = add_alias(
                        State(state.clone()),
                        Json(AddAliasRequest {
                            identifier: fields.get("identifier").trim().into(),
                            name: fields.get("name").trim().into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                "delete" => {
                    let _ =
                        delete_alias(State(state.clone()), Path(fields.get("identifier").into()))
                            .await
                            .map_err(api_error)?;
                }
                _ => return Err("Unknown alias action".into()),
            }
            result.notice = "Client aliases updated.".into();
        }
        ("network", "records") => {
            match intent {
                "add" => {
                    let _ = add_local_dns(
                        State(state.clone()),
                        Json(AddLocalDnsRequest {
                            name: fields.get("name").trim().into(),
                            record_type: fields.get("record_type").into(),
                            value: fields.get("value").trim().into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                "delete" => {
                    let _ = delete_local_dns(
                        State(state.clone()),
                        Json(DeleteLocalDnsRequest {
                            name: fields.get("name").into(),
                            record_type: fields.get("record_type").into(),
                        }),
                    )
                    .await
                    .map_err(api_error)?;
                }
                _ => return Err("Unknown DNS record action".into()),
            }
            result.notice = "Local DNS records updated.".into();
        }
        ("config", "pause") => {
            let seconds = fields
                .get("seconds")
                .parse::<u64>()
                .map_err(|_| "Enter a positive whole number of seconds")?;
            let _ = update_protection_settings(
                State(state.clone()),
                Json(ProtectionSettingsDto {
                    protection_pause_default_duration_secs: seconds,
                }),
            )
            .await
            .map_err(api_error)?;
            result.notice = "Protection pause default saved.".into();
        }
        ("config", "cache") => {
            let _ = invalidate_caches(State(state.clone())).await;
            result.notice = "DNS response and filter caches cleared.".into();
        }
        ("config", "security") => {
            if fields.get("new_password") != fields.get("confirm_password") {
                return Err("New passwords do not match".into());
            }
            let _ = update_password(
                State(state.clone()),
                Json(UpdatePasswordRequest {
                    current_password: fields.get("current_password").into(),
                    new_password: fields.get("new_password").into(),
                }),
            )
            .await
            .map_err(api_error)?;
            let token = state
                .sessions
                .issue(state.sessions.generation())
                .map_err(|_| "Password changed. Sign in again using your new password.")?
                .ok_or("The admin credential changed again. Sign in using the latest password.")?;
            result.cookie = Some(session_cookie(
                headers,
                &token,
                SESSION_TTL.as_secs(),
                state.config.load().api_allow_insecure_http,
            ));
            result.notice = "Admin password updated. Your browser session has been renewed.".into();
        }
        #[cfg(feature = "feat-json-api")]
        ("config", "api-token") => match intent {
            "generate" => {
                let (token, digest) =
                    issue_api_token().map_err(|_| "Could not generate an API token")?;
                commit_config(state, |config| {
                    config.api_token_sha256 = Some(digest);
                    Ok(())
                })
                .await?;
                result.secret = token;
                result.notice = "API token generated.".into();
            }
            "revoke" => {
                commit_config(state, |config| {
                    config.api_token_sha256 = None;
                    Ok(())
                })
                .await?;
                result.notice =
                    "API token revoked. The JSON API accepts the admin password again.".into();
            }
            _ => return Err("Unknown API token action".into()),
        },
        ("doh", "encrypted") => {
            // Draft pool edits travel in the form; no credentials or mutable
            // configuration snapshots need to live in browser JavaScript.
            let mut urls = fields.all("url");
            let mut active = fields.get("active_url").to_owned();
            if intent != "save" {
                let (command, target) = if let Some((command, index)) = intent.split_once(':') {
                    let index = index
                        .parse::<usize>()
                        .map_err(|_| "Invalid endpoint index")?;
                    (command, urls.get(index).cloned().ok_or("Unknown endpoint")?)
                } else {
                    (intent, fields.get("target").to_owned())
                };
                match command {
                    "add" => {
                        let url = fields.get("new_url").trim();
                        if !url.starts_with("https://") {
                            return Err("Enter an HTTPS endpoint URL".into());
                        }
                        if urls.iter().any(|existing| existing == url) {
                            return Err("Server already in list".into());
                        }
                        urls.push(url.into());
                    }
                    "select" => active = target.clone(),
                    "delete" => {
                        if target == active {
                            return Err("Cannot delete the currently active endpoint".into());
                        }
                        urls.retain(|url| url != &target);
                    }
                    "preset" => {
                        if !target.starts_with("https://") {
                            return Err("Invalid preset URL".into());
                        }
                        active = target;
                        if !urls.contains(&active) {
                            urls.push(active.clone());
                        }
                    }
                    _ => return Err("Unknown endpoint action".into()),
                }
                let mut draft = fields.clone();
                draft.0.retain(|(key, _)| {
                    !matches!(key.as_str(), "url" | "active_url" | "new_url" | "intent")
                });
                draft
                    .0
                    .extend(urls.into_iter().map(|url| ("url".into(), url)));
                draft.0.push(("active_url".into(), active));
                result.draft = Some(draft);
                result.notice = "Draft updated. Save Changes to apply.".into();
                return Ok(result);
            }
            // Configure the transport through the shared handler. The flag
            // not exposed by this form is read fresh rather than defaulted.
            let config = state.config.load();
            let _ = update_doh_config(
                State(state.clone()),
                Json(DohConfigDto {
                    encrypted_upstream_enabled: fields.checked("enabled"),
                    encrypted_upstream_allow_plaintext_fallback: config
                        .encrypted_upstream_allow_plaintext_fallback,
                    encrypted_upstream_url: active,
                    doh_upstreams: urls,
                }),
            )
            .await
            .map_err(api_error)?;
            result.notice = "Encrypted upstream settings saved.".into();
        }
        ("shell", "protection") => {
            pause(state, fields).await?;
        }
        _ => return Err("Unknown dashboard action".into()),
    }
    Ok(result)
}

/// Derives a stable ASCII id from an app name. Distinct names can share a
/// slug ("Foo Bar" / "Foo-Bar", or any two non-Latin names of equal length),
/// so a numeric suffix keeps ids unique instead of rejecting the new app.
fn custom_service_id(name: &str, taken: impl Fn(&str) -> bool) -> String {
    let base = format!(
        "custom_{}",
        name.to_lowercase()
            .chars()
            .map(|character| if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            })
            .collect::<String>()
    );
    if !taken(&base) {
        return base;
    }
    (2u32..)
        .map(|suffix| format!("{base}_{suffix}"))
        .find(|candidate| !taken(candidate))
        .expect("an unused suffix exists")
}

async fn pause(state: &ApiState, fields: &Fields) -> WebResult<()> {
    let seconds = fields.get("seconds");
    let duration_secs = if fields.get("intent") == "resume" || seconds.is_empty() {
        None
    } else {
        Some(
            seconds
                .parse::<u64>()
                .map_err(|_| "Choose a valid pause duration")?,
        )
    };
    let payload = Json(ProtectionScopeRequest {
        scope: fields.get("scope").into(),
        id: (!fields.get("id").is_empty()).then(|| fields.get("id").into()),
        duration_secs,
        indefinite: fields.get("seconds") == "0",
    });
    if fields.get("intent") == "resume" {
        let _ = resume_protection(State(state.clone()), payload)
            .await
            .map_err(api_error)?;
    } else {
        let _ = pause_protection(State(state.clone()), payload)
            .await
            .map_err(api_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::custom_service_id;

    #[test]
    fn colliding_custom_app_slugs_receive_unique_ids() {
        let taken = ["custom_foo_bar", "custom_foo_bar_2"];
        assert_eq!(
            custom_service_id("Foo Baz", |id| taken.contains(&id)),
            "custom_foo_baz"
        );
        assert_eq!(
            custom_service_id("Foo-Bar", |id| taken.contains(&id)),
            "custom_foo_bar_3"
        );
    }
}
