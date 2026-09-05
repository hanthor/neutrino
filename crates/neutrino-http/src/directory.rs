//! The room directory: `#alias:server` → room id.
//!
//! Aliases are how attendees converge. The companion derives the same
//! `#event-session-id:server` on every phone (`conferenceChatAlias`), so the
//! first client to reach a room creates it and the rest must *find* it rather
//! than create their own. That requires three things, and all three were
//! missing: somewhere to keep a local alias, a way to answer for it, and a way
//! to ask another server about theirs.
//!
//! Local aliases are served from the store. A remote one is resolved by asking
//! the server named in the alias — the only server entitled to answer.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use neutrino_store::AliasStore;
use ruma::{OwnedRoomId, RoomAliasId, RoomId, ServerName};
use serde_json::{Value, json};

use crate::{AppState, AuthUser, error_response, lock_app};

/// Validate an alias and hand back its domain.
///
/// The domain is copied out rather than borrowed from the parsed value: ruma's
/// `RoomAliasId` owns the storage its `server_name()` points into, so returning
/// that borrow would outlive the parse.
fn alias_domain(raw: &str) -> Result<String, Response> {
    match RoomAliasId::parse(raw) {
        Ok(parsed) => Ok(parsed.server_name().as_str().to_owned()),
        Err(_) => Err(error_response(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Room alias is malformed",
        )),
    }
}

/// `GET /_matrix/client/v3/directory/room/{alias}`
pub(crate) async fn get_alias(state: State<AppState>, Path(alias): Path<String>) -> Response {
    let domain = match alias_domain(&alias) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let whole = alias.as_str();
    let (store, own_server, client) = {
        let app = lock_app(&state.0);
        (
            app.store.clone(),
            app.config.server_name.clone(),
            app.fed_client.clone(),
        )
    };

    if domain == own_server {
        return match store.resolve_alias(whole).await {
            Ok(Some(room_id)) => (
                StatusCode::OK,
                Json(json!({ "room_id": room_id, "servers": [own_server] })),
            )
                .into_response(),
            Ok(None) => {
                error_response(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Room alias not found")
            }
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &format!("resolving alias: {e}"),
            ),
        };
    }

    // Remote: ask the alias's own server. On the mesh that request rides the
    // datagram link like any other federation call, so it works with no
    // internet as long as the peer is reachable.
    let Ok(dest) = ServerName::parse(&domain) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Room alias server name is malformed",
        );
    };
    match client.query_directory(&dest, whole).await {
        Ok(resp) => (
            StatusCode::OK,
            Json(json!({ "room_id": resp.room_id, "servers": [&domain] })),
        )
            .into_response(),
        Err(e) => error_response(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            &format!("could not resolve {whole} at {domain}: {e}"),
        ),
    }
}

/// `PUT /_matrix/client/v3/directory/room/{alias}` — claim an alias here.
pub(crate) async fn put_alias(
    state: State<AppState>,
    AuthUser(sender): AuthUser,
    Path(alias): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let domain = match alias_domain(&alias) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let whole = alias.as_str();
    let (store, own_server) = {
        let app = lock_app(&state.0);
        (app.store.clone(), app.config.server_name.clone())
    };
    if domain != own_server {
        return error_response(
            StatusCode::FORBIDDEN,
            "M_EXCLUSIVE",
            "Cannot create an alias in another server's namespace",
        );
    }
    let Some(room_id) = body.get("room_id").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            "Missing room_id",
        );
    };
    let Ok(room_id) = RoomId::parse(room_id) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Malformed room_id",
        );
    };
    match store.put_alias(whole, &room_id, &sender).await {
        // Losing the race is a conflict, not a success: the caller must join
        // the winner's room rather than believe it owns the alias.
        Ok(true) => (StatusCode::OK, Json(json!({}))).into_response(),
        Ok(false) => error_response(
            StatusCode::CONFLICT,
            "M_ROOM_IN_USE",
            "Room alias is already taken",
        ),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("claiming alias: {e}"),
        ),
    }
}

/// Resolve an alias to a room id for the join path: local store first, then the
/// alias's own server. Returns `None` when it cannot be resolved anywhere.
pub(crate) async fn resolve_for_join(
    state: &AppState,
    alias: &str,
) -> Option<(OwnedRoomId, Option<String>)> {
    let parsed = RoomAliasId::parse(alias).ok()?;
    let domain = parsed.server_name().as_str().to_owned();
    let (store, own_server, client) = {
        let app = lock_app(state);
        (
            app.store.clone(),
            app.config.server_name.clone(),
            app.fed_client.clone(),
        )
    };
    if domain == own_server {
        // Local rooms need no resident hint — we host it.
        return store
            .resolve_alias(alias)
            .await
            .ok()
            .flatten()
            .map(|r| (r, None));
    }
    let dest = ServerName::parse(&domain).ok()?;
    let resp = client.query_directory(&dest, alias).await.ok()?;
    let room_id = RoomId::parse(&resp.room_id).ok()?;
    // The alias's server is by definition in the room, so it is the resident
    // to join through.
    Some((room_id, Some(domain)))
}
