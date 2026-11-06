//! Builds with the JSON API but without `feat-web-ui`: no dashboard pages,
//! actions or static assets are served. Run with
//! `cargo test -p api --no-default-features --features feat-json-api`.
#![cfg(all(feature = "feat-json-api", not(feature = "feat-web-ui")))]

mod common;

use common::start_server;

#[tokio::test]
async fn test_dashboard_is_not_served() {
    let (base, _directory, client) = start_server().await;
    for path in [
        "/",
        "/login.html",
        "/config.html",
        "/styles.css",
        "/ui/protection",
    ] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
    }
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("origin", &base)
        .form(&[("password", "test-secret-key")])
        .send()
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(!response.headers().contains_key("set-cookie"));
}

#[tokio::test]
async fn test_api_token_is_managed_through_the_json_api() {
    let (base, _directory, client) = start_server().await;
    let status = |credential: String| {
        let request = client
            .get(format!("{base}/api/v1/stats"))
            .bearer_auth(credential);
        async move { request.send().await.unwrap().status() }
    };
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::OK
    );

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
    assert_eq!(token.len(), 64);
    assert_eq!(status(token.clone()).await, reqwest::StatusCode::OK);
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::UNAUTHORIZED
    );

    let response = client
        .delete(format!("{base}/api/v1/auth/token"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(status(token).await, reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        status("test-secret-key".into()).await,
        reqwest::StatusCode::OK
    );
}
