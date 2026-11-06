//! Builds with the dashboard but without `feat-json-api`: `/api/v1/*` does
//! not exist. Run with
//! `cargo test -p api --no-default-features --features feat-web-ui`.
#![cfg(all(feature = "feat-web-ui", not(feature = "feat-json-api")))]

mod common;

use common::start_server;

#[tokio::test]
async fn test_json_api_is_not_served() {
    let (base, _directory, client) = start_server().await;
    let response = client
        .get(format!("{base}/api/v1/stats"))
        .bearer_auth("test-secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let response = client
        .post(format!("{base}/api/v1/config/password"))
        .bearer_auth("test-secret-key")
        .json(&serde_json::json!({
            "current_password": "test-secret-key",
            "new_password": "a-brand-new-password"
        }))
        .send()
        .await
        .unwrap();
    assert!(!response.status().is_success());
}

#[tokio::test]
async fn test_dashboard_signs_in_without_the_json_api() {
    let (base, _directory, client) = start_server().await;
    let response = client
        .post(format!("{base}/ui/auth/login"))
        .header("origin", &base)
        .form(&[("password", "test-secret-key")])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let page = client
        .get(format!("{base}/config.html?tab=security"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    let page = page.text().await.unwrap();
    assert!(page.contains("Change Admin Password"));
    assert!(!page.contains("JSON API Token"));

    for request in [
        client.get(format!("{base}/ui/section/config/api-token")),
        client
            .post(format!("{base}/ui/action/config/api-token"))
            .header("origin", &base)
            .form(&[("intent", "generate")]),
    ] {
        let response = request.header("cookie", &cookie).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    }
}
