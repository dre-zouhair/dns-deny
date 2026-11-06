//! Session-only, server-rendered dashboard. JSON API handlers stay independent.
mod actions;
mod render;
mod stream;

use super::*;
use axum::extract::{Form, OriginalUri, Path, Query};
use axum::http::Method;
use axum::response::{Redirect, Response};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Fields(Vec<(String, String)>);

impl Fields {
    fn get(&self, name: &str) -> &str {
        self.0
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .collect()
    }
    fn checked(&self, name: &str) -> bool {
        matches!(self.get(name), "on" | "true" | "1")
    }
    fn values(&self) -> Value {
        let mut fields = serde_json::Map::new();
        for (key, value) in &self.0 {
            if !matches!(
                key.as_str(),
                "password" | "current_password" | "new_password" | "confirm_password"
            ) {
                fields.insert(key.clone(), Value::String(value.clone()));
            }
        }
        Value::Object(fields)
    }
}

type WebResult<T> = Result<T, String>;
fn api_error(error: (StatusCode, Json<ErrorResponse>)) -> String {
    error.1.0.error
}
fn serialize(value: impl Serialize) -> WebResult<Value> {
    serde_json::to_value(value).map_err(|_| "Could not prepare dashboard data".into())
}
fn requested(headers: &HeaderMap) -> bool {
    headers
        .get("datastar-request")
        .is_some_and(|value| value == "true")
}

fn redirect(headers: &HeaderMap, destination: &str) -> Response {
    if requested(headers) {
        (
            [(header::CONTENT_TYPE, "text/javascript")],
            format!(
                "window.location.assign({});",
                serde_json::to_string(destination).unwrap()
            ),
        )
            .into_response()
    } else {
        Redirect::to(destination).into_response()
    }
}

fn destination(value: &str) -> String {
    // `/ui/*` serves fragments, streams and downloads, never a whole page.
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\\', '\r', '\n'])
        && !value.starts_with("/login.html")
        && !value.starts_with("/ui/")
        && value.parse::<Uri>().is_ok()
    {
        value.to_owned()
    } else {
        "/".into()
    }
}

/// The page to return to after signing in. Background `/ui/*` requests
/// (polls, streams, form actions) return to the page that issued them.
fn return_path(req: &Request) -> String {
    let path = req
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    if !path.starts_with("/ui/") {
        return destination(path);
    }
    let headers = req.headers();
    headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uri>().ok())
        .filter(|referer| {
            let host = headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok());
            matches!(referer.scheme_str(), Some("http" | "https"))
                && referer
                    .authority()
                    .zip(host)
                    .is_some_and(|(authority, host)| authority.as_str().eq_ignore_ascii_case(host))
        })
        .and_then(|referer| {
            referer
                .path_and_query()
                .map(|value| destination(value.as_str()))
        })
        .unwrap_or_else(|| "/".into())
}

async fn guard(State(state): State<ApiState>, req: Request, next: Next) -> Response {
    if !cookie_session(req.headers()).is_some_and(|token| state.sessions.verify(token)) {
        if req.uri().path() == "/ui/auth/session" {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let encoded: String = percent_encoding::utf8_percent_encode(
            &return_path(&req),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .collect();
        return redirect(req.headers(), &format!("/login.html?next={encoded}"));
    }
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        && !same_origin(req.headers())
    {
        return (
            StatusCode::FORBIDDEN,
            "Sign in and submit forms from the dashboard origin",
        )
            .into_response();
    }
    next.run(req).await
}

pub(super) fn routes(state: ApiState) -> Router<ApiState> {
    Router::new()
        .route("/", get(page))
        .route("/index.html", get(page))
        .route("/lists.html", get(page))
        .route("/services.html", get(page))
        .route("/network.html", get(page))
        .route("/config.html", get(page))
        .route("/doh.html", get(page))
        .route("/livetail.html", get(page))
        .route("/allowdeny.html", get(legacy))
        .route("/regex.html", get(legacy))
        .route("/listsoverview.html", get(legacy))
        .route("/autoblock.html", get(legacy))
        .route("/smartip.html", get(legacy))
        .route("/safesearch.html", get(legacy))
        .route("/localdns.html", get(legacy))
        .route("/diagnostics.html", get(legacy))
        .route("/protection.html", get(legacy))
        .route("/ui/section/{page}/{section}", get(section))
        .route("/ui/action/{page}/{section}", post(action))
        .route("/ui/protection", get(protection))
        .route("/ui/queries/stream", get(stream::queries))
        .route("/ui/queries/export", get(export_logs))
        .route("/ui/auth/session", get(|| async { StatusCode::NO_CONTENT }))
        .route("/ui/auth/logout", post(sign_out))
        .layer(middleware::from_fn_with_state(state, guard))
        .route("/login.html", get(sign_in_page))
        .route("/ui/auth/login", post(sign_in))
}

async fn legacy(OriginalUri(uri): OriginalUri) -> Redirect {
    Redirect::to(match uri.path() {
        "/allowdeny.html" => "/lists.html?tab=allowdeny",
        "/regex.html" => "/lists.html?tab=regex",
        "/listsoverview.html" => "/lists.html?tab=overview",
        "/autoblock.html" => "/services.html?tab=autoblock",
        "/smartip.html" => "/services.html?tab=smartip",
        "/safesearch.html" => "/services.html?tab=safesearch",
        "/localdns.html" => "/network.html?tab=localdns",
        "/diagnostics.html" => "/config.html?tab=diagnostics",
        _ => "/config.html",
    })
}

async fn sign_in_page(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let next = destination(query.get("next").map_or("/", String::as_str));
    if cookie_session(&headers).is_some_and(|token| state.sessions.verify(token)) {
        return redirect(&headers, &next);
    }
    render::full("login", json!({"next": next, "error": ""}))
}

async fn sign_in(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    if !same_origin(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let fields = Fields(fields);
    let next = destination(fields.get("next"));
    let generation = state.sessions.generation();
    let verified =
        match verify_api_key(&state, fields.get("password"), &state.config.load().api_key).await {
            Ok(verified) => verified,
            Err(status) => return (status, "Sign-in is busy. Try again shortly.").into_response(),
        };
    if !verified {
        let mut response = render::full(
            "login",
            json!({"next": next, "error": "Invalid admin password or API key"}),
        );
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        return response;
    }
    match state.sessions.issue(generation) {
        Ok(Some(token)) => {
            if let Some(previous) = cookie_session(&headers) {
                state.sessions.revoke(previous);
            }
            let mut response = redirect(&headers, &next);
            response.headers_mut().insert(
                header::SET_COOKIE,
                session_cookie(
                    &headers,
                    &token,
                    SESSION_TTL.as_secs(),
                    state.config.load().api_allow_insecure_http,
                ),
            );
            response
        }
        Ok(None) => {
            let mut response = render::full(
                "login",
                json!({"next": next, "error": "The admin credential changed. Sign in again."}),
            );
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            response
        }
        Err(error) => {
            error!("Failed to establish dashboard session: {error:?}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn sign_out(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_session(&headers) {
        state.sessions.revoke(token);
    }
    let mut response = redirect(&headers, "/login.html");
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(&headers, "", 0, state.config.load().api_allow_insecure_http),
    );
    response
}

async fn page(State(state): State<ApiState>, OriginalUri(uri): OriginalUri) -> Response {
    let page = match uri.path() {
        "/" | "/index.html" => "overview",
        "/lists.html" => "lists",
        "/services.html" => "services",
        "/network.html" => "network",
        "/config.html" => "config",
        "/doh.html" => "doh",
        "/livetail.html" => "queries",
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let fields = Fields(serde_urlencoded::from_str(uri.query().unwrap_or("")).unwrap_or_default());
    let context = render::page_context(&state, page, &fields).await;
    match context {
        Ok(context) => render::full(page, context),
        Err(error) => render::failure_page(&error),
    }
}

async fn section(
    State(state): State<ApiState>,
    Path((page, section)): Path<(String, String)>,
    Query(fields): Query<Vec<(String, String)>>,
) -> Response {
    if !render::valid_section(&page, &section) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match render::section(&state, &page, &section, &Fields(fields), "", "").await {
        Ok(html) => Html(html).into_response(),
        Err(error) => render::failure(&error),
    }
}

async fn action(
    State(state): State<ApiState>,
    Path((page, section)): Path<(String, String)>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    if !render::valid_section(&page, &section) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let fields = Fields(fields);
    let outcome = actions::apply(&state, &page, &section, &fields, &headers).await;
    let (notice, error, cookie, draft, secret) = match outcome {
        Ok(result) => (
            result.notice,
            String::new(),
            result.cookie,
            result.draft,
            result.secret,
        ),
        Err(error) => (
            String::new(),
            error,
            None,
            Some(fields.clone()),
            String::new(),
        ),
    };
    let has_draft = draft.is_some();
    let draft = draft.unwrap_or_else(|| Fields(vec![("_form".into(), fields.get("_form").into())]));
    let mut response = if requested(&headers) {
        match render::section_revealing(&state, &page, &section, &draft, &notice, &error, &secret)
            .await
        {
            Ok(mut html) => {
                // Adding a rule may remove it from the opposite list. Refresh
                // both visible tables while retaining the other form's draft.
                let opposite = match (page.as_str(), section.as_str()) {
                    ("lists", "allow") => Some("deny"),
                    ("lists", "deny") => Some("allow"),
                    ("lists", "regex-allow") => Some("regex-deny"),
                    ("lists", "regex-deny") => Some("regex-allow"),
                    _ => None,
                };
                if error.is_empty()
                    && let Some(opposite) = opposite
                    && let Ok(other) =
                        render::section(&state, &page, opposite, &Fields::default(), "", "").await
                {
                    html.push_str(&other);
                }
                Html(html).into_response()
            }
            Err(error) => render::failure(&error),
        }
    } else if error.is_empty() && !has_draft && secret.is_empty() {
        Redirect::to(&format!(
            "{}?tab={}#section-{page}-{section}",
            render::page_path(&page),
            render::section_tab(&page, &section)
        ))
        .into_response()
    } else {
        match render::page_context(
            &state,
            &page,
            &Fields(vec![(
                "tab".into(),
                render::section_tab(&page, &section).into(),
            )]),
        )
        .await
        {
            Ok(mut context) => {
                if let Ok(html) = render::section_revealing(
                    &state, &page, &section, &draft, &notice, &error, &secret,
                )
                .await
                {
                    context["overrides"] = json!({section: html});
                }
                render::full(&page, context)
            }
            Err(error) => render::failure_page(&error),
        }
    };
    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

async fn protection(State(state): State<ApiState>) -> Response {
    render::protection(&state)
}
