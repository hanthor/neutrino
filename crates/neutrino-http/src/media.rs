//! The content repository: `POST /_matrix/media/v3/upload`, the
//! authenticated download and its legacy twin, `/media/config`, and the
//! federation download a peer uses to fetch what another node holds.
//!
//! Everything is capped at [`neutrino_ctl::Config::media_max_bytes`]: an
//! upload over it is refused on its declared length before the body is read,
//! and a peer's content over it is not fetched. The cap is advertised as
//! `m.upload.size` so a client can refuse before any bytes cross a BLE link.
//! Content is stored verbatim under `(origin, media id)`; what a peer serves
//! is cached under the peer's name, so the same `mxc://` resolves the same
//! way on every node that has seen it.

use std::collections::HashMap;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use neutrino_store::{MediaStore, StoredMedia};
use ruma::OwnedServerName;
use serde_json::{Value, json};
use tracing::warn;

use crate::federation::{FedError, auth};
use crate::{AppState, AuthUser, error_response, lock_app};

fn too_large(cap: usize) -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "M_TOO_LARGE",
        &format!("Media exceeds this server's {cap} byte cap"),
    )
}

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Media not found")
}

fn fresh_media_id() -> String {
    use rand::Rng;
    use rand::distr::Alphanumeric;
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

/// `GET /_matrix/media/v3/config` and `/_matrix/client/v1/media/config`.
pub(crate) async fn config(State(state): State<AppState>, AuthUser(_): AuthUser) -> Json<Value> {
    let cap = lock_app(&state).config.media_max_bytes;
    Json(json!({ "m.upload.size": cap }))
}

/// `POST /_matrix/media/v3/upload`: the body is the content, verbatim.
pub(crate) async fn upload(
    State(state): State<AppState>,
    AuthUser(uploader): AuthUser,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let (cap, store, our_name) = {
        let app = lock_app(&state);
        (
            app.config.media_max_bytes,
            app.store.clone(),
            app.config.server_name.clone(),
        )
    };
    // The declared length is checked first so an oversized upload is refused
    // before its bytes are read; the read itself is capped for the ones that
    // declare nothing.
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|len| len > cap) {
        return too_large(cap);
    }
    let bytes = match axum::body::to_bytes(body, cap).await {
        Ok(bytes) => bytes,
        Err(_) => return too_large(cap),
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let media = StoredMedia {
        content_type,
        filename: params.get("filename").cloned(),
        bytes: bytes.to_vec(),
    };
    let media_id = fresh_media_id();
    if let Err(e) = store
        .put_media(&our_name, &media_id, uploader.as_str(), &media)
        .await
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        );
    }
    Json(json!({ "content_uri": format!("mxc://{our_name}/{media_id}") })).into_response()
}

/// `GET /_matrix/client/v1/media/download/{server}/{id}` (authenticated).
pub(crate) async fn download(
    State(state): State<AppState>,
    AuthUser(_): AuthUser,
    Path((server, media_id)): Path<(String, String)>,
) -> Response {
    serve(&state, &server, &media_id).await
}

/// `GET /_matrix/media/v3/download/{server}/{id}`: the pre-v1.11 path older
/// clients still try first. Unauthenticated, as the spec had it.
pub(crate) async fn download_legacy(
    State(state): State<AppState>,
    Path((server, media_id)): Path<(String, String)>,
) -> Response {
    serve(&state, &server, &media_id).await
}

async fn serve(state: &AppState, server: &str, media_id: &str) -> Response {
    let (our_name, store, fed_client, cap) = {
        let app = lock_app(state);
        (
            app.config.server_name.clone(),
            app.store.clone(),
            app.fed_client.clone(),
            app.config.media_max_bytes,
        )
    };
    match store.get_media(server, media_id).await {
        Ok(Some(media)) => return content_response(media),
        Ok(None) => {}
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            );
        }
    }
    if server == our_name {
        return not_found();
    }
    // Someone else's: fetch it from the node that has it, once, and keep it.
    let Ok(dest) = OwnedServerName::try_from(server) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "invalid server name",
        );
    };
    match fed_client.media_download(&dest, media_id, cap).await {
        Ok(media) => {
            if let Err(e) = store.put_media(server, media_id, "", &media).await {
                warn!(error = %e, "caching a peer's media");
            }
            content_response(media)
        }
        Err(e) => {
            warn!(%dest, %media_id, error = %e, "fetching a peer's media");
            error_response(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "Media not found on the server that holds it",
            )
        }
    }
}

/// Content types a browser may render inline; anything else is served as
/// an attachment, per the spec's list.
fn inline_safe(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        essence,
        "text/css"
            | "text/plain"
            | "text/csv"
            | "application/json"
            | "application/ld+json"
            | "image/jpeg"
            | "image/gif"
            | "image/png"
            | "image/apng"
            | "image/webp"
            | "image/avif"
            | "video/mp4"
            | "video/webm"
            | "video/ogg"
            | "video/quicktime"
            | "audio/mp4"
            | "audio/webm"
            | "audio/aac"
            | "audio/mpeg"
            | "audio/ogg"
            | "audio/wave"
            | "audio/wav"
            | "audio/x-wav"
            | "audio/x-pn-wav"
            | "audio/flac"
            | "audio/x-flac"
    )
}

fn content_response(media: StoredMedia) -> Response {
    let disposition = match (&media.filename, inline_safe(&media.content_type)) {
        (Some(name), true) => format!("inline; filename=\"{}\"", name.replace('"', "")),
        (Some(name), false) => format!("attachment; filename=\"{}\"", name.replace('"', "")),
        (None, true) => "inline".to_owned(),
        (None, false) => "attachment".to_owned(),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, media.content_type),
            (header::CONTENT_DISPOSITION, disposition),
            (
                header::CONTENT_SECURITY_POLICY,
                "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; \
                 style-src 'unsafe-inline'; object-src 'self';"
                    .to_owned(),
            ),
            (
                header::CACHE_CONTROL,
                "public,max-age=86400,s-maxage=86400".to_owned(),
            ),
        ],
        media.bytes,
    )
        .into_response()
}

/// `GET /_matrix/federation/v1/media/download/{id}`: what this server's
/// users uploaded, as `multipart/mixed` — a JSON metadata part, then the
/// content — the shape the spec gives a peer to fetch.
pub(crate) async fn federation_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(media_id): Path<String>,
) -> Result<Response, FedError> {
    let (our_name, store) = {
        let app = lock_app(&state);
        (app.config.server_name.clone(), app.store.clone())
    };
    auth::authenticated_origin(&headers, &our_name)?;
    let media = store
        .get_media(&our_name, &media_id)
        .await
        .map_err(|_| FedError::Internal("reading media"))?;
    let Some(media) = media else {
        return Ok(not_found());
    };
    let boundary = format!("neutrino-{}", fresh_media_id());
    let body = multipart_body(&boundary, &media);
    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={boundary}"),
        )],
        body,
    )
        .into_response())
}

/// The two-part body the federation download carries: an empty JSON
/// metadata object, then the content under its own type.
pub(crate) fn multipart_body(boundary: &str, media: &StoredMedia) -> Vec<u8> {
    let mut body = Vec::with_capacity(media.bytes.len() + 256);
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: application/json\r\n\r\n{{}}\r\n").as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: {}\r\n\r\n",
            media.content_type
        )
        .as_bytes(),
    );
    body.extend_from_slice(&media.bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// The boundary named by a `multipart/mixed` content type, if any.
pub(crate) fn multipart_boundary(content_type: &str) -> Option<String> {
    let (essence, params) = content_type.split_once(';')?;
    if essence.trim() != "multipart/mixed" {
        return None;
    }
    params.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k.trim() == "boundary").then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// The content part of a federation download body: the last part that is
/// not the JSON metadata, with its declared type. `None` when the body is
/// not the shape the spec describes.
pub(crate) fn parse_multipart(boundary: &str, body: &[u8]) -> Option<(String, Vec<u8>)> {
    let delimiter = format!("--{boundary}");
    let delimiter = delimiter.as_bytes();
    let mut parts = Vec::new();
    let mut rest = body;
    // Skip to the first delimiter.
    let first = find(rest, delimiter)?;
    rest = &rest[first + delimiter.len()..];
    loop {
        if rest.starts_with(b"--") {
            break;
        }
        // Past the CRLF that ends the delimiter line.
        rest = rest.strip_prefix(b"\r\n").unwrap_or(rest);
        let end = find(rest, delimiter)?;
        let part = &rest[..end];
        // The CRLF before the next delimiter belongs to the delimiter.
        let part = part.strip_suffix(b"\r\n").unwrap_or(part);
        parts.push(part);
        rest = &rest[end + delimiter.len()..];
    }
    for part in parts.into_iter().rev() {
        let split = find(part, b"\r\n\r\n")?;
        let headers = std::str::from_utf8(&part[..split]).ok()?;
        let content = &part[split + 4..];
        let content_type = headers
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-type")
                    .then(|| v.trim().to_owned())
            })
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        if content_type.starts_with("application/json") {
            continue;
        }
        return Some((content_type, content.to_vec()));
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_round_trips_binary_content() {
        let media = StoredMedia {
            content_type: "image/png".to_owned(),
            filename: None,
            bytes: vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0, 0xff, b'-', b'-'],
        };
        let body = multipart_body("b0undary", &media);
        let (content_type, bytes) = parse_multipart("b0undary", &body).expect("parsed");
        assert_eq!(content_type, "image/png");
        assert_eq!(bytes, media.bytes);
    }

    #[test]
    fn multipart_boundary_is_read_from_the_content_type() {
        assert_eq!(
            multipart_boundary("multipart/mixed; boundary=abc").as_deref(),
            Some("abc")
        );
        assert_eq!(
            multipart_boundary("multipart/mixed;boundary=\"q q\"").as_deref(),
            Some("q q")
        );
        assert_eq!(multipart_boundary("image/png"), None);
    }

    #[test]
    fn a_body_without_a_content_part_is_rejected() {
        assert_eq!(
            parse_multipart(
                "b",
                b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b--\r\n"
            ),
            None
        );
        assert_eq!(parse_multipart("b", b"garbage"), None);
    }

    #[test]
    fn inline_only_for_safe_types() {
        assert!(inline_safe("image/png"));
        assert!(inline_safe("text/plain; charset=utf-8"));
        assert!(!inline_safe("text/html"));
        assert!(!inline_safe("application/octet-stream"));
    }
}
