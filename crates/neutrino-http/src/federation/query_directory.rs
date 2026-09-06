//! `GET /_matrix/federation/v1/query/directory` — resolve one of *our* aliases
//! for a peer.
//!
//! Matrix aliases are server-scoped: `#session:A` can only be resolved by A.
//! Without this endpoint an alias is unresolvable off the server that created
//! it, which breaks the deterministic conference aliases outright — every
//! attendee's client would create its own room under the same name instead of
//! converging on one.
//!
//! Only the local directory is consulted. A server must not answer for another
//! server's namespace, and chaining the lookup onward would let one peer use
//! us as an open resolver.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use neutrino_store::AliasStore;
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, error_response, lock_app};

#[derive(Deserialize)]
pub(crate) struct Params {
    room_alias: String,
}

pub(crate) async fn handle(state: State<AppState>, Query(params): Query<Params>) -> Response {
    let (store, own_server) = {
        let app = lock_app(&state.0);
        (app.store.clone(), app.config.server_name.clone())
    };

    // Refuse another server's namespace explicitly rather than returning "not
    // found": the caller has asked the wrong server, and saying so is the
    // difference between a bug it can see and an alias it thinks is free.
    match params.room_alias.rsplit_once(':') {
        Some((_, domain)) if domain == own_server => {}
        Some(_) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "Room alias is not in this server's namespace",
            );
        }
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "Room alias is malformed",
            );
        }
    }

    match store.resolve_alias(&params.room_alias).await {
        Ok(Some(room_id)) => (
            StatusCode::OK,
            // `servers` is ours alone: we know we host the room, and we do not
            // track which peers have joined it.
            Json(json!({ "room_id": room_id, "servers": [own_server] })),
        )
            .into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Room alias not found"),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("resolving alias: {e}"),
        ),
    }
}
