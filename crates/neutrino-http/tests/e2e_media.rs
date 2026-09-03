//! End-to-end tests for the content repository: upload, download on both
//! paths, the size cap, and the federation download a peer uses.
#![cfg(not(feature = "multi-user-shim"))]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use neutrino_ctl::Config;
use neutrino_http::router;
use serde_json::Value;
use tower::ServiceExt;

const CAP: usize = 4096;

fn config() -> Config {
    Config {
        server_name: "example.org".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        localpart: "alice".to_string(),
        media_max_bytes: CAP,
        ..Default::default()
    }
}

async fn test_router() -> (axum::Router, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("create storage tempdir");
    let mut cfg = config();
    cfg.storage_dir = tmp.path().to_path_buf();
    let app = router(cfg).await.expect("router");
    (app, tmp)
}

struct Reply {
    status: StatusCode,
    content_type: String,
    disposition: String,
    bytes: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or(Value::Null)
    }
}

async fn drive(app: &axum::Router, req: Request<Body>) -> Reply {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let content_type = header("content-type");
    let disposition = header("content-disposition");
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap()
        .to_vec();
    Reply {
        status,
        content_type,
        disposition,
        bytes,
    }
}

async fn upload(app: &axum::Router, bytes: Vec<u8>, mime: &str, filename: Option<&str>) -> Reply {
    let path = match filename {
        Some(name) => format!("/_matrix/media/v3/upload?filename={name}"),
        None => "/_matrix/media/v3/upload".to_owned(),
    };
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", mime)
        .header("content-length", bytes.len())
        .body(Body::from(bytes))
        .unwrap();
    drive(app, req).await
}

async fn get(app: &axum::Router, path: &str, x_matrix: Option<&str>) -> Reply {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(auth) = x_matrix {
        builder = builder.header("authorization", auth);
    }
    drive(app, builder.body(Body::empty()).unwrap()).await
}

fn png() -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    bytes.extend((0..1000u32).map(|i| (i % 251) as u8));
    bytes
}

#[tokio::test]
async fn config_advertises_the_cap() {
    let (app, _tmp) = test_router().await;
    for path in [
        "/_matrix/media/v3/config",
        "/_matrix/client/v1/media/config",
    ] {
        let reply = get(&app, path, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.json()["m.upload.size"], CAP);
    }
}

#[tokio::test]
async fn upload_then_download_on_both_paths() {
    let (app, _tmp) = test_router().await;
    let reply = upload(&app, png(), "image/png", Some("photo.png")).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.bytes)
    );
    let mxc = reply.json()["content_uri"].as_str().unwrap().to_owned();
    let (server, id) = mxc.strip_prefix("mxc://").unwrap().split_once('/').unwrap();
    assert_eq!(server, "example.org");

    let authenticated = get(
        &app,
        &format!("/_matrix/client/v1/media/download/{server}/{id}"),
        None,
    )
    .await;
    assert_eq!(authenticated.status, StatusCode::OK);
    assert_eq!(authenticated.content_type, "image/png");
    assert_eq!(authenticated.disposition, "inline; filename=\"photo.png\"");
    assert_eq!(authenticated.bytes, png());

    let legacy = get(
        &app,
        &format!("/_matrix/media/v3/download/{server}/{id}"),
        None,
    )
    .await;
    assert_eq!(legacy.status, StatusCode::OK);
    assert_eq!(legacy.bytes, png());

    // An unsafe type is an attachment, whatever it is called.
    let reply = upload(&app, b"<html>".to_vec(), "text/html", Some("page.html")).await;
    let mxc = reply.json()["content_uri"].as_str().unwrap().to_owned();
    let id = mxc.rsplit('/').next().unwrap();
    let html = get(
        &app,
        &format!("/_matrix/client/v1/media/download/example.org/{id}"),
        None,
    )
    .await;
    assert_eq!(html.disposition, "attachment; filename=\"page.html\"");

    let missing = get(
        &app,
        "/_matrix/client/v1/media/download/example.org/nothing-here",
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.json()["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn an_upload_over_the_cap_is_refused_on_its_declared_length() {
    let (app, _tmp) = test_router().await;
    let reply = upload(&app, vec![7u8; CAP + 1], "application/octet-stream", None).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.json()["errcode"], "M_TOO_LARGE");

    // Exactly the cap is fine.
    let reply = upload(&app, vec![7u8; CAP], "application/octet-stream", None).await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn federation_download_serves_multipart_to_an_authenticated_peer() {
    let (app, _tmp) = test_router().await;
    let reply = upload(&app, png(), "image/png", None).await;
    let mxc = reply.json()["content_uri"].as_str().unwrap().to_owned();
    let id = mxc.rsplit('/').next().unwrap().to_owned();

    let unauthenticated = get(
        &app,
        &format!("/_matrix/federation/v1/media/download/{id}"),
        None,
    )
    .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let peer = r#"X-Matrix origin="peer.example.org",destination="example.org""#;
    let reply = get(
        &app,
        &format!("/_matrix/federation/v1/media/download/{id}"),
        Some(peer),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply.content_type.starts_with("multipart/mixed; boundary="),
        "{}",
        reply.content_type
    );
    let boundary = reply.content_type.split("boundary=").nth(1).unwrap();
    let body = String::from_utf8_lossy(&reply.bytes);
    assert!(
        body.contains("Content-Type: application/json\r\n\r\n{}"),
        "{body}"
    );
    assert!(body.contains("Content-Type: image/png"), "{body}");
    assert!(
        body.trim_end().ends_with(&format!("--{boundary}--")),
        "{body}"
    );
    let content_start = reply
        .bytes
        .windows(4)
        .rposition(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    let content_end = reply.bytes.len() - format!("\r\n--{boundary}--\r\n").len();
    assert_eq!(&reply.bytes[content_start..content_end], &png()[..]);

    let missing = get(
        &app,
        "/_matrix/federation/v1/media/download/nothing-here",
        Some(peer),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}
