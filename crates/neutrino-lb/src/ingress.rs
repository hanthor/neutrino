//! Ingress: the wire→local half. Implements `WireHandler` — decodes the CBOR
//! request body to JSON, forwards it verbatim (method/path/forwardable headers)
//! to the loopback `neutrino-http` upstream, and re-encodes the JSON response
//! to CBOR. Path/method are never interpreted, so no federation routes are
//! mirrored.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use crate::capture::{CaptureControl, Leg, record_response};
use crate::codec::{cbor_to_json, json_to_cbor};
use crate::headers::{
    CONTENT_TYPE_SENTINEL, claimed_origin, content_type, is_forwardable, is_json_content_type,
};
use crate::transport::{OCTET_STREAM_CONTENT_FORMAT, WireHandler, WireRequest, WireResponse};

/// The only path namespace the ingress forwards to the loopback homeserver.
/// The ingress owns the *public* federation port, but the co-located
/// `neutrino-http` serves the (unauthenticated, trusted-network) Client-Server
/// API on the same listener (see `build_router`). Forwarding only
/// `/_matrix/federation/*` keeps a peer from reaching CSAPI/other routes
/// through the proxy — restoring the route boundary the single-port homeserver
/// used to imply when it wasn't network-exposed. No `/_matrix/key/` prefix:
/// this server has no signing keys and serves no key endpoints.
const FEDERATION_PREFIX: &str = "/_matrix/federation/";

/// Join an error's source chain into `": "`-separated causes. reqwest's `Display`
/// stops at its own message and drops the underlying cause (connect / reset /
/// timeout), which is exactly the datum needed to tell a loopback-family mismatch
/// from a genuinely dead upstream.
fn source_chain(err: &dyn std::error::Error) -> String {
    std::iter::successors(err.source(), |c| c.source())
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

/// Forwards transcoded requests to the local homeserver.
pub struct IngressHandler {
    http: reqwest::Client,
    /// Base URL of local `neutrino-http`, e.g. `http://127.0.0.1:8008`.
    upstream: String,
    /// Runtime-toggleable pcap sink, `None` when the host declared no tap. This
    /// is the peer→local leg of the capture (see [`crate::capture`]).
    capture: Option<Arc<CaptureControl>>,
}

impl IngressHandler {
    pub fn new(upstream: String, capture: Option<Arc<CaptureControl>>) -> Self {
        Self::with_timeouts(
            upstream,
            capture,
            crate::CONNECT_TIMEOUT,
            crate::REQUEST_TIMEOUT,
        )
    }

    fn with_timeouts(
        upstream: String,
        capture: Option<Arc<CaptureControl>>,
        connect: Duration,
        request: Duration,
    ) -> Self {
        // Bound the loopback hop to `neutrino-http`: a hung upstream must not
        // pin this wire-handler task (and its buffers) indefinitely.
        crate::install_crypto_provider();
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(connect)
            .timeout(request)
            .build()
            // `build()` only fails on TLS-backend init; this is a plaintext
            // client (no TLS), so it can't fail. Panic loud rather than fall
            // back to a default `Client::new()` that silently drops `.no_proxy()`
            // + the timeouts (re-enabling ambient-proxy hijack and the dead-peer
            // request leak these settings exist to prevent).
            .expect("plaintext reqwest client always builds; no TLS backend to init");
        Self {
            http,
            upstream,
            capture,
        }
    }

    /// `502` with an empty body, used when transcoding or the upstream fails.
    fn bad_gateway() -> WireResponse {
        WireResponse {
            status: 502,
            headers: vec![],
            body: vec![],
            ..Default::default()
        }
    }
}

#[async_trait]
impl WireHandler for IngressHandler {
    async fn handle(&self, req: WireRequest) -> WireResponse {
        let json_body = match cbor_to_json(&req.body) {
            Ok(b) => b,
            Err(e) => {
                warn!(%e, "ingress: CBOR request body decode failed");
                return Self::bad_gateway();
            }
        };
        // pcap tap, request half: the literal JSON about to be handed upstream.
        // The peer's `server_name` is the claimed `X-Matrix origin` — an inbound
        // `WireRequest` carries no source, so this is the only peer identity the
        // ingress has. (On the datagram transport the claim was already bound to
        // the link-authenticated node; see `Hub::origin_binding_violation`.)
        // Recorded before the gates below, so a rejected request is still
        // visible, and before the upstream call, so the gap to the response half
        // is the upstream's service time.
        let exchange = self.capture.as_ref().and_then(|capture| {
            capture.record_request(
                Leg::Ingress,
                claimed_origin(&req.headers).unwrap_or("unknown"),
                req.method.as_str(),
                &req.path,
                &req.headers,
                &json_body,
            )
        });
        let url = format!("{}{}", self.upstream, req.path);
        // Parse first, then gate on the *normalized* path: a raw `starts_with`
        // is bypassable by `..` / percent-encoded-dot traversal (e.g.
        // `/_matrix/federation/v1/../../client/...`), which the URL parser
        // collapses into a CSAPI path. Checking `parsed.path()` catches it.
        let parsed = match reqwest::Url::parse(&url) {
            Ok(u) => u,
            Err(e) => {
                warn!(%e, "ingress: upstream URL parse failed");
                record_response(&self.capture, exchange, 502, &[], b"");
                return Self::bad_gateway();
            }
        };
        if !parsed.path().starts_with(FEDERATION_PREFIX) {
            warn!(path = %parsed.path(), "ingress: rejecting non-federation path");
            record_response(&self.capture, exchange, 404, &[], b"");
            return WireResponse {
                status: 404,
                headers: vec![],
                body: vec![],
                ..Default::default()
            };
        }
        let mut rb = self.http.request(req.method, parsed);
        for (name, value) in &req.headers {
            if is_forwardable(name) {
                rb = rb.header(name.as_str(), value.as_slice());
            }
        }
        if !json_body.is_empty() {
            rb = rb.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        let resp = match rb.body(json_body).send().await {
            Ok(r) => r,
            Err(e) => {
                // reqwest's `Display` stops at "error sending request for url";
                // the load-bearing root cause (e.g. "connection refused (os error
                // 111)" — the IPv4/IPv6 loopback mismatch) lives in the source
                // chain, so log that too or the failure is undiagnosable.
                warn!(%e, cause = %source_chain(&e), "ingress: upstream request failed");
                record_response(&self.capture, exchange, 502, &[], b"");
                return Self::bad_gateway();
            }
        };
        let status = resp.status().as_u16();
        // Carry the upstream's response headers across the wire (the framing
        // ones — content-length/-type, etc. — are dropped per hop by the
        // downstream `is_forwardable` filter). Collected before the body is
        // consumed, mirroring `HttpWireClient::send`.
        let headers: Vec<(String, Vec<u8>)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        let resp_bytes = match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => {
                warn!(%e, "ingress: reading upstream response failed");
                record_response(&self.capture, exchange, 502, &[], b"");
                return Self::bad_gateway();
            }
        };
        // pcap tap, response half: the upstream's literal JSON, before the
        // transcode. Recorded on the non-JSON path too — what the homeserver
        // actually returned (a framework error page, say) is the whole
        // diagnostic there, even though it is not forwarded over the wire.
        record_response(&self.capture, exchange, status, &headers, &resp_bytes);
        // A non-JSON response body — a `multipart/mixed` media download, above
        // all — cannot be JSON⇄CBOR transcoded. Pass it through byte-for-byte and
        // carry its real Content-Type on the forwardable sentinel header, so the
        // recipient's egress restores that type (with its multipart `boundary`)
        // instead of forcing `application/json`. Keyed off the upstream
        // Content-Type header, per hop; an `application/json` (or absent) type
        // stays on the transcode path below.
        if let Some(ct) = content_type(&headers)
            .filter(|ct| !is_json_content_type(ct))
            .map(<[u8]>::to_vec)
        {
            let mut headers = headers;
            headers.push((CONTENT_TYPE_SENTINEL.to_owned(), ct));
            return WireResponse {
                status,
                headers,
                body: resp_bytes,
                // Not CBOR: mark the opaque body so a CoAP capture dissects it as
                // octet-stream rather than mis-parsing it as CBOR.
                content_format: OCTET_STREAM_CONTENT_FORMAT,
            };
        }
        match json_to_cbor(&resp_bytes) {
            Ok(cbor_body) => WireResponse {
                status,
                headers,
                body: cbor_body,
                ..Default::default()
            },
            // A non-2xx with a non-JSON body (e.g. a framework error page) must
            // keep its status so the originating server's 4xx-give-up /
            // 5xx-retry decision survives the proxy. Only a 2xx payload we
            // cannot encode is a genuine bad-gateway.
            Err(e) if (200..300).contains(&status) => {
                warn!(%e, "ingress: 2xx JSON response body encode failed");
                Self::bad_gateway()
            }
            Err(e) => {
                warn!(%e, status, "ingress: non-JSON error body; forwarding status without it");
                WireResponse {
                    status,
                    headers,
                    body: vec![],
                    ..Default::default()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::WireRequest;
    use axum::extract::State;
    use axum::http::Method;
    use axum::routing::put;
    use axum::{Json, Router};
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn forwards_decoded_json_to_upstream_and_recodes_response() {
        // Upstream records the JSON body it received and replies with JSON.
        let seen: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let seen_c = seen.clone();
        let app = Router::new()
            .route(
                "/_matrix/federation/v1/send/1",
                put(
                    |State(s): State<Arc<Mutex<Option<serde_json::Value>>>>,
                     body: axum::body::Bytes| async move {
                        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        *s.lock().unwrap() = Some(v);
                        Json(serde_json::json!({"ok": true}))
                    },
                ),
            )
            .with_state(seen_c);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let cbor_in = json_to_cbor(br#"{"hello":"world"}"#).unwrap();
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::PUT,
                path: "/_matrix/federation/v1/send/1".to_owned(),
                headers: vec![],
                body: cbor_in,
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 200);
        assert_eq!(
            *seen.lock().unwrap(),
            Some(serde_json::json!({"hello": "world"}))
        );
        // Response body must come back as CBOR of the upstream JSON.
        let decoded = cbor_to_json(&resp.body).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    // Upstream response headers must be carried back across the wire, not
    // dropped — the homeserver relies on the proxy being transparent.
    #[tokio::test]
    async fn forwards_upstream_response_headers() {
        let app = Router::new().fallback(|| async {
            (
                [("x-custom-header", "via-upstream")],
                Json(serde_json::json!({"ok": true})),
            )
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::GET,
                // A federation path so the route-gate forwards it.
                path: "/_matrix/federation/v1/backfill/!r".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 200);
        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("x-custom-header") && v == b"via-upstream"),
            "upstream response header was dropped: {:?}",
            resp.headers
        );
    }

    // A non-2xx upstream response that CLAIMS `application/json` but whose body
    // will not parse must keep its status (the body is dropped). Masking it as a
    // generic 502 would flip the homeserver's "drop a 4xx / retry a 5xx" decision
    // into a retry storm. (A non-JSON Content-Type now passes through with its
    // body intact instead — that is the media path, not this failure path.)
    #[tokio::test]
    async fn preserves_non_2xx_status_when_upstream_body_is_not_json() {
        let app = Router::new().fallback(|| async {
            (
                axum::http::StatusCode::FORBIDDEN,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "no",
            )
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::GET,
                path: "/_matrix/federation/v1/make_join/!r/@u".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 403, "4xx give-up status must survive");
        assert!(resp.body.is_empty());
    }

    // A 2xx that CLAIMS `application/json` but whose body will not parse is a
    // genuine proxy failure → 502. (A non-JSON *Content-Type* is no longer a
    // failure: it takes the binary-passthrough path — see
    // `passes_through_non_json_body_with_its_content_type`.)
    #[tokio::test]
    async fn masks_2xx_with_undecodable_body_as_bad_gateway() {
        let app = Router::new().fallback(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                "200 but not json",
            )
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::GET,
                // A federation path so the route-gate forwards it.
                path: "/_matrix/federation/v1/backfill/!r".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 502);
    }

    // A non-JSON upstream response (a `multipart/mixed` media download) must NOT
    // be transcoded: its bytes ride through verbatim and its real Content-Type is
    // carried on the sentinel header for the egress to restore. This is the media
    // fix — before it, the multipart body failed `json_to_cbor` and 502'd.
    #[tokio::test]
    async fn passes_through_non_json_body_with_its_content_type() {
        let media: Vec<u8> = vec![0x89, 0xff, 0x00, 0xfe, b'X', 0xc0];
        let ct = "multipart/mixed; boundary=neutrino-abc123";
        let app = Router::new().fallback({
            let media = media.clone();
            move || {
                let media = media.clone();
                async move { ([(axum::http::header::CONTENT_TYPE, ct)], media) }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::GET,
                path: "/_matrix/federation/v1/media/download/abc".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 200);
        // Body is the raw media bytes, NOT CBOR of anything.
        assert_eq!(resp.body, media, "binary body was not passed through verbatim");
        assert_eq!(resp.content_format, OCTET_STREAM_CONTENT_FORMAT);
        let sentinel = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(CONTENT_TYPE_SENTINEL))
            .map(|(_, v)| v.clone());
        assert_eq!(
            sentinel.as_deref(),
            Some(ct.as_bytes()),
            "original Content-Type (with boundary) must ride the sentinel header"
        );
    }

    // A peer must not be able to reach the co-resident Client-Server API
    // through the public federation port: any non-`/_matrix/federation/` path
    // is 404'd and never forwarded to the loopback upstream.
    #[tokio::test]
    async fn rejects_non_federation_path() {
        let hit: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let hit_c = hit.clone();
        let app = Router::new().fallback(move || {
            let hit_c = hit_c.clone();
            async move {
                *hit_c.lock().unwrap() = true;
                Json(serde_json::json!({"ok": true}))
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::POST,
                path: "/_matrix/client/v3/createRoom".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 404, "non-federation path must be rejected");
        assert!(!*hit.lock().unwrap(), "upstream must not be reached");
    }

    // `..` (and percent-encoded-dot) traversal that the URL parser would
    // normalize into a CSAPI path must be caught by the post-normalization
    // gate, not just a raw prefix check.
    #[tokio::test]
    async fn rejects_dotdot_traversal_into_csapi() {
        let hit: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
        let hit_c = hit.clone();
        let app = Router::new().fallback(move || {
            let hit_c = hit_c.clone();
            async move {
                *hit_c.lock().unwrap() = true;
                Json(serde_json::json!({"ok": true}))
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let handler = IngressHandler::new(format!("http://{addr}"), None);
        let resp = handler
            .handle(WireRequest {
                dest: String::new(),
                method: Method::POST,
                // Normalizes to `/_matrix/client/v3/createRoom`.
                path: "/_matrix/federation/v1/../../client/v3/createRoom".to_owned(),
                headers: vec![],
                body: vec![],
                ..Default::default()
            })
            .await;

        assert_eq!(resp.status, 404, "traversal escape must be rejected");
        assert!(!*hit.lock().unwrap(), "upstream must not be reached");
    }

    // Proves the localhost/127.0.0.1 address-family mismatch is what turns a
    // federated invite into a 502 (the "Empty Room" failure). Production binds
    // the homeserver v4-only
    // (`neutrino_main: listening on 127.0.0.1:8008`) but the ingress upstream is
    // the *hostname* `http://localhost:8008` (upstream_url passes a non-numeric
    // bind_addr through verbatim). On Android `localhost` also resolves to `::1`,
    // where nothing listens. Against ONE v4-only upstream the only variable here
    // is the address family of the upstream URL: same family forwards and returns
    // the homeserver's 200; the other family ([::1], which `localhost` can pick)
    // can't connect, so the ingress reports 502 — exactly the observed failure.
    #[tokio::test]
    async fn upstream_address_family_mismatch_yields_bad_gateway() {
        // v4-only listener, mirroring production's `listening on 127.0.0.1:8008`.
        let app = Router::new().fallback(|| async { Json(serde_json::json!({"event": {}})) });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let invite = || WireRequest {
            dest: String::new(),
            method: Method::PUT,
            path: "/_matrix/federation/v2/invite/!r/$e".to_owned(),
            headers: vec![],
            body: json_to_cbor(br#"{"room_version":"org.matrix.msc4242.12"}"#).unwrap(),
            ..Default::default()
        };

        // Matching family (v4) → reaches the v4-bound homeserver.
        let matched = IngressHandler::new(format!("http://127.0.0.1:{port}"), None)
            .handle(invite())
            .await;
        assert_eq!(
            matched.status, 200,
            "v4 upstream must reach the v4-bound homeserver"
        );

        // Other family (v6) — the address `localhost` can resolve to — has no
        // listener, so the loopback connect fails and the ingress 502s.
        let mismatched = IngressHandler::new(format!("http://[::1]:{port}"), None)
            .handle(invite())
            .await;
        assert_eq!(
            mismatched.status, 502,
            "v6 upstream against a v4-only homeserver must 502 (the invite failure)"
        );
    }
}
