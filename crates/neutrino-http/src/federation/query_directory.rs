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
    match alias_domain(&params.room_alias) {
        Some(domain) if domain == own_server => {}
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

/// The server part of `#localpart:server`, or `None` if it is not an alias.
///
/// Split on the *first* colon, not the last. A localpart cannot contain a
/// colon but a server name can — `#session:127.0.0.1:8008` is an ordinary
/// alias on a server with a port — and splitting from the right reads that
/// domain as `8008`, so the server refuses to answer for its own namespace.
/// Mesh server names are 64 hex characters with no colon in them, which is
/// why this survived every test on the mesh and broke the moment two ported
/// nodes federated.
fn alias_domain(alias: &str) -> Option<&str> {
    let rest = alias.strip_prefix('#')?;
    let (localpart, domain) = rest.split_once(':')?;
    if localpart.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::alias_domain;

    #[test]
    fn keeps_the_port_in_a_server_name() {
        assert_eq!(alias_domain("#s:127.0.0.1:8008"), Some("127.0.0.1:8008"));
        assert_eq!(alias_domain("#s:example.org"), Some("example.org"));
        // A mesh node id: 64 hex, no colon.
        let node = "0".repeat(64);
        assert_eq!(alias_domain(&format!("#s:{node}")).map(str::to_owned), Some(node));
    }

    #[test]
    fn rejects_what_is_not_an_alias() {
        for bad in ["", "#", "#s", "s:example.org", "#:example.org", "#s:"] {
            assert_eq!(alias_domain(bad), None, "{bad}");
        }
    }
}
