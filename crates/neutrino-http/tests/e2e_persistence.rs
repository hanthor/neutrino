//! Proves the embedded DB persists across an `AppState`/router drop+reopen on
//! the same `storage_dir` — the core guarantee of the configurable-storage work.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use neutrino_ctl::Config;
use neutrino_http::router;
use serde_json::{Value, json};
use tower::ServiceExt; // oneshot

fn config_in(dir: &std::path::Path) -> Config {
    Config {
        server_name: "example.org".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        localpart: "alice".to_string(),
        storage_dir: dir.to_path_buf(),
        ..Default::default()
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(match body {
            Some(b) => Body::from(serde_json::to_vec(b).unwrap()),
            None => Body::empty(),
        })
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn room_survives_restart_on_same_storage_dir() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg = config_in(tmp.path());

    // First boot: create a room.
    let app1 = router(cfg.clone()).await.expect("router boot 1");
    let (status, body) = send(
        &app1,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "createRoom failed: {body}");
    let room_id = body["room_id"].as_str().expect("room_id").to_string();
    drop(app1); // close the pools so the DB file is fully released

    // Second boot on the SAME directory: the room must still be there.
    let app2 = router(cfg).await.expect("router boot 2");
    let (status, state) = send(
        &app2,
        "GET",
        &format!("/_matrix/client/v3/rooms/{room_id}/state"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "state read after restart failed: {state}"
    );
    let has_create = state
        .as_array()
        .expect("state array")
        .iter()
        .any(|e| e["type"] == "m.room.create");
    assert!(has_create, "m.room.create missing after restart: {state}");
}

/// Account data — the DM list, room tags — is written through to the store
/// and comes back after a restart on the same directory, global and per
/// room; another user's entries are not readable, and a missing one is 404.
#[tokio::test]
async fn account_data_survives_restart_on_same_storage_dir() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let cfg = config_in(tmp.path());
    let me = "@alice:example.org";

    let app1 = router(cfg.clone()).await.expect("router boot 1");
    let (status, body) = send(
        &app1,
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let room_id = body["room_id"].as_str().unwrap().to_string();

    let direct = json!({ "@bob:example.org": [room_id] });
    let (status, _) = send(
        &app1,
        "PUT",
        &format!("/_matrix/client/v3/user/{me}/account_data/m.direct"),
        Some(&direct),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app1,
        "PUT",
        &format!("/_matrix/client/v3/user/{me}/rooms/{room_id}/account_data/m.tag"),
        Some(&json!({ "tags": { "m.favourite": {} } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &app1,
        "GET",
        &format!("/_matrix/client/v3/user/{me}/account_data/m.direct"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, direct);
    let (status, body) = send(
        &app1,
        "PUT",
        "/_matrix/client/v3/user/@bob:example.org/account_data/m.direct",
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(
        &app1,
        "GET",
        &format!("/_matrix/client/v3/user/{me}/account_data/nothing.here"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["errcode"], "M_NOT_FOUND");
    drop(app1);

    let app2 = router(cfg).await.expect("router boot 2");
    let (status, body) = send(
        &app2,
        "GET",
        &format!("/_matrix/client/v3/user/{me}/account_data/m.direct"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "global account data after restart");
    assert_eq!(body, direct);
    let (status, body) = send(
        &app2,
        "GET",
        &format!("/_matrix/client/v3/user/{me}/rooms/{room_id}/account_data/m.tag"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "room account data after restart");
    assert_eq!(body["tags"]["m.favourite"], json!({}));

    // And a restarted server's first sync carries it: the client's DM list
    // is there before it asks.
    let (status, body) = send(&app2, "GET", "/_matrix/client/v3/sync?timeout=0", None).await;
    assert_eq!(status, StatusCode::OK);
    let global = body["account_data"]["events"].as_array().unwrap();
    assert!(
        global
            .iter()
            .any(|e| e["type"] == "m.direct" && e["content"] == direct),
        "{body}"
    );
    let room_events = body["rooms"]["join"][&room_id]["account_data"]["events"]
        .as_array()
        .unwrap();
    assert!(room_events.iter().any(|e| e["type"] == "m.tag"), "{body}");
}
