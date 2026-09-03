//! Federation device-key and one-time-key endpoints — the half of E2EE that
//! crosses the mesh.
//!
//! On a phone mesh every device is its own homeserver, so *every* peer is a
//! remote peer: without these routes a client can hold a perfect Olm
//! implementation and still never learn a single key belonging to the person
//! sitting next to it. The client-server siblings in `lib.rs` answer for users
//! this node owns; these answer the same questions for a peer that asks over
//! federation, reading the same [`crate::e2ee::KeyStore`].
//!
//! - `POST /_matrix/federation/v1/user/keys/query`
//! - `POST /_matrix/federation/v1/user/keys/claim`
//! - `GET  /_matrix/federation/v1/user/devices/{userId}`
//!
//! Trust model matches the rest of `federation/`: the `X-Matrix` origin is
//! network-attested, not signed (see [`auth`]). A peer therefore learns any
//! device key it asks for — which is what a key directory is for, but worth
//! stating plainly: these endpoints publish public keys, and nothing here is a
//! secret. One-time keys are the exception that matters, and `claim` pops
//! rather than reads so a claimed key is never handed out twice, however many
//! peers ask.
//!
//! **Users this node does not own are simply absent from the answer.** We never
//! proxy a query onward: answering for someone else's user would let one node
//! substitute keys for another's, which is exactly the attack E2EE exists to
//! stop.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use ruma::OwnedUserId;
use serde_json::{Map, Value, json};

use crate::federation::{FedError, auth};
use crate::{AppState, lock_app};

/// Restrict a `{user: …}` request map to the users this node actually owns.
/// A user id that does not parse, or whose server is not us, is dropped
/// silently — the spec's answer for "I don't know them" is absence, not an
/// error.
fn ours(requested: &Map<String, Value>, our_name: &str) -> Map<String, Value> {
    requested
        .iter()
        .filter(|(user, _)| {
            OwnedUserId::try_from(user.as_str()).is_ok_and(|u| u.server_name().as_str() == our_name)
        })
        .map(|(user, value)| (user.clone(), value.clone()))
        .collect()
}

/// `POST /_matrix/federation/v1/user/keys/query` — the device directory as
/// seen from another server. Body and response mirror the client-server
/// `/keys/query`, minus the per-user `failures` (a server answers only for its
/// own users, so there is nothing to fail).
pub(crate) async fn query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, FedError> {
    let our_name = lock_app(&state).config.server_name.clone();
    auth::authenticated_origin(&headers, &our_name)?;

    let requested = body
        .pointer("/device_keys")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let e2ee = lock_app(&state).e2ee.clone();
    let inner = e2ee.lock();
    let device_keys = inner.keys.device_keys_for(&ours(&requested, &our_name));
    let mut response = Map::new();
    response.insert("device_keys".to_owned(), Value::Object(device_keys));
    for (key, value) in inner.keys.cross_signing.iter() {
        response.insert(key.clone(), value.clone());
    }
    Ok(Json(Value::Object(response)))
}

/// `POST /_matrix/federation/v1/user/keys/claim` — take one one-time key per
/// requested device so the asking peer can open an Olm session with one of our
/// users. The keys are removed as they are handed out.
pub(crate) async fn claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, FedError> {
    let our_name = lock_app(&state).config.server_name.clone();
    auth::authenticated_origin(&headers, &our_name)?;

    let requested = body
        .pointer("/one_time_keys")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let e2ee = lock_app(&state).e2ee.clone();
    let claimed = e2ee.lock().keys.claim_for(&ours(&requested, &our_name));
    Ok(Json(json!({ "one_time_keys": claimed })))
}

/// `GET /_matrix/federation/v1/user/devices/{userId}` — the whole device list
/// for one of our users, which is how a peer discovers devices it was never
/// told about rather than having to guess device ids.
///
/// `stream_id` is required by the spec and is meant to order device-list
/// updates. We have no device-list stream (nothing here ever revokes a device),
/// so it is a constant: a peer using it to detect staleness will conclude our
/// list never changes, which is true of this implementation.
pub(crate) async fn devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, FedError> {
    let our_name = lock_app(&state).config.server_name.clone();
    auth::authenticated_origin(&headers, &our_name)?;

    let user = OwnedUserId::try_from(user_id.as_str())
        .map_err(|_| FedError::BadRequest("user id is not a valid Matrix user id"))?;
    if user.server_name().as_str() != our_name {
        return Err(FedError::BadRequest("user does not belong to this server"));
    }

    let e2ee = lock_app(&state).e2ee.clone();
    let inner = e2ee.lock();
    let devices = inner
        .keys
        .devices
        .get(user.as_str())
        .into_iter()
        .flatten()
        .map(|(device_id, keys)| json!({ "device_id": device_id, "keys": keys }))
        .collect::<Vec<_>>();
    let mut response = json!({
        "user_id": user.as_str(),
        "stream_id": 1,
        "devices": devices,
    });
    // Cross-signing keys ride along under the names the spec gives them here,
    // when the user has uploaded any.
    if let Some(object) = response.as_object_mut() {
        for name in ["master_key", "self_signing_key"] {
            let uploaded = inner
                .keys
                .cross_signing
                .get(&format!("{name}s"))
                .or_else(|| inner.keys.cross_signing.get(name));
            if let Some(value) = uploaded {
                object.insert(name.to_owned(), value.clone());
            }
        }
    }
    Ok(Json(response))
}
