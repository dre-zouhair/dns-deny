use super::*;
use filter::FilterVerdict;
use std::collections::VecDeque;
use std::convert::Infallible;

fn filters(fields: &Fields) -> LogQueryRequest {
    LogQueryRequest {
        q: (!fields.get("q").is_empty()).then(|| fields.get("q").into()),
        verdict: (!fields.get("verdict").is_empty()).then(|| fields.get("verdict").into()),
        client: (!fields.get("client").is_empty()).then(|| fields.get("client").into()),
        limit: Some(100),
        offset: Some(
            fields
                .get("page")
                .parse::<usize>()
                .unwrap_or(1)
                .clamp(1, 1_000_000)
                .saturating_sub(1)
                * 100,
        ),
    }
}

/// Mirrors the history query: "Pass" means every verdict except `Block`,
/// including explicit allowlist hits.
fn verdict_matches(filter: &str, verdict: &FilterVerdict) -> bool {
    match filter {
        "Block" => *verdict == FilterVerdict::Block,
        "Pass" => *verdict != FilterVerdict::Block,
        _ => true,
    }
}

fn params(fields: &Fields) -> String {
    serde_urlencoded::to_string([
        ("q", fields.get("q")),
        ("verdict", fields.get("verdict")),
        ("client", fields.get("client")),
    ])
    .unwrap_or_default()
}

pub(super) async fn history(
    state: &ApiState,
    fields: &Fields,
    context: &mut Value,
) -> WebResult<()> {
    let mode = if ["history", "paused"].contains(&fields.get("mode")) {
        fields.get("mode")
    } else {
        "live"
    };
    context["mode"] = json!(mode);
    context["params"] = json!(params(fields));
    context["stream_url"] = json!(format!("/ui/queries/stream?{}", params(fields)));
    let config = state.config.load();
    let devices = state.network_tracker.get_devices().await;
    let clients: Vec<Value> = devices
        .into_iter()
        .map(|device| {
            let ip = device.ip.to_string();
            let name = alias_for(&config, &ip);
            json!({"ip": ip, "name": name})
        })
        .collect();
    context["clients"] = json!(clients);
    context["page_number"] = json!(
        fields
            .get("page")
            .parse::<usize>()
            .unwrap_or(1)
            .clamp(1, 1_000_000)
    );
    context["rows"] = json!("");
    context["count"] = json!(0);
    if mode == "history" {
        match get_logs(State(state.clone()), Query(filters(fields))).await {
            Ok(Json(data)) => {
                context["count"] = json!(data.logs.len());
                let mut rows = String::new();
                for entry in data.logs {
                    rows.push_str(&row(&config, &entry)?);
                }
                context["rows"] = json!(rows);
            }
            Err(error) => context["error"] = json!(api_error(error)),
        }
    }
    Ok(())
}

fn alias_for(config: &Config, ip: &str) -> String {
    config
        .client_aliases
        .iter()
        .find(|alias| alias.identifier == ip)
        .map(|alias| alias.name.clone())
        .unwrap_or_default()
}

fn row(config: &Config, entry: &HistoricalLogEntry) -> WebResult<String> {
    let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(entry.timestamp)
        .map(|time| time.format("%H:%M:%S").to_string())
        .unwrap_or_default();
    let duration = if entry.duration_ns >= 1_000_000 {
        format!("{:.1}ms", entry.duration_ns as f64 / 1_000_000.0)
    } else {
        format!("{}µs", entry.duration_ns / 1000)
    };
    render::template(
        "row.html",
        json!({"entry": entry, "time": timestamp, "duration": duration, "alias": alias_for(config, &entry.client_ip)}),
    )
}

fn patch(selector: &str, mode: &str, html: &str) -> Event {
    let elements = html
        .lines()
        .map(|line| format!("elements {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    Event::default()
        .event("datastar-patch-elements")
        .data(format!("selector {selector}\nmode {mode}\n{elements}"))
}
fn signals(value: Value) -> Event {
    Event::default()
        .event("datastar-patch-signals")
        .data(format!("signals {value}"))
}

pub(super) async fn queries(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(fields): Query<Vec<(String, String)>>,
) -> Response {
    if headers
        .get("x-stop-live")
        .is_some_and(|value| value == "true")
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    let Some(logger) = state.logger.clone() else {
        return Sse::new(tokio_stream::iter([Ok::<_, Infallible>(signals(
            json!({"live": false, "stream_status": "Query logging is disabled"}),
        ))]))
        .into_response();
    };
    let fields = Fields(fields);
    let query = fields.get("q").to_lowercase();
    let verdict = fields.get("verdict").to_owned();
    let client = fields.get("client").to_owned();
    let token = cookie_session(&headers).unwrap_or_default().to_owned();
    let mut receiver = logger.subscribe();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(4);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        let mut pending = VecDeque::with_capacity(500);
        let mut sequence = 0u64;
        let mut warning = false;
        if tx
            .send(Ok(signals(
                json!({"stream_status": "connected (live)", "stream_tick": 0}),
            )))
            .await
            .is_err()
        {
            return;
        }
        loop {
            tokio::select! {
                _ = tx.closed() => break,
                received = receiver.recv() => match received {
                    Ok(entry) => {
                        if entry.name.to_lowercase().contains(&query) && verdict_matches(&verdict, &entry.verdict) && (client.is_empty() || client == entry.client_ip.to_string()) {
                            if pending.len() == 500 { pending.pop_front(); warning = true; }
                            pending.push_back(entry);
                        }
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => warning = true,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = tick.tick() => {
                    if !state.sessions.verify(&token) {
                        let event = patch("#ui-error", "outer", "<p id=\"ui-error\" data-init=\"window.location.replace('/login.html')\">Your session expired. Sign in again.</p>");
                        let _ = tx.send(Ok(event)).await;
                        break;
                    }
                    if warning {
                        if tx.send(Ok(patch("#query-warning", "outer", "<p id=\"query-warning\" class=\"settings-note\">Some live queries were missed. Search history for the complete log.</p>"))).await.is_err() { break; }
                        warning = false;
                    }
                    if pending.is_empty() { continue; }
                    let config = state.config.load();
                    let mut html = String::new();
                    while let Some(entry) = pending.pop_back() {
                        let historical = HistoricalLogEntry {
                            timestamp: entry.timestamp.duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_millis().min(i64::MAX as u128) as i64),
                            client_ip: entry.client_ip.to_string(), name: entry.name, qtype: entry.qtype.to_string(),
                            response_code: entry.response_code.to_string(), duration_ns: entry.duration_ns,
                            verdict: format!("{:?}", entry.verdict), resolver: entry.resolver.into_owned(),
                        };
                        if let Ok(markup) = row(&config, &historical) { html.push_str(&markup); }
                    }
                    // CSS selection bounds the DOM across pause/resume without
                    // a browser row model or per-session snapshot cache.
                    for event in [patch("#query-rows", "prepend", &html), patch("#query-rows > :nth-child(n + 501)", "remove", "")] {
                        if tx.send(Ok(event)).await.is_err() { return; }
                    }
                    sequence = sequence.wrapping_add(1);
                    if tx.send(Ok(signals(json!({"stream_tick": sequence})))).await.is_err() { break; }
                }
            }
        }
    });
    Sse::new(tokio_stream::wrappers::ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_verdict_filter_matches_history_semantics() {
        assert!(verdict_matches("", &FilterVerdict::Allow));
        assert!(verdict_matches("Block", &FilterVerdict::Block));
        assert!(!verdict_matches("Block", &FilterVerdict::Allow));
        assert!(verdict_matches("Pass", &FilterVerdict::Pass));
        assert!(verdict_matches("Pass", &FilterVerdict::Allow));
        assert!(!verdict_matches("Pass", &FilterVerdict::Block));
    }
}
