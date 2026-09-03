//! The server's share of end-to-end encryption: a device-key directory and a
//! to-device inbox, shared between the HTTP handlers and the sliding-sync
//! long-poll.
//!
//! Matrix keeps the cryptography in the client. What a homeserver holds is
//! public key material and ciphertext addressed to devices, and what it has
//! to do well is *wake the recipient*: a Megolm room key that sits in an inbox
//! until the next unrelated event is a message the recipient cannot read
//! until then. So this state carries its own watch, advanced on every inbox
//! write, and the sync handlers select on it alongside the event stream.
//!
//! Held once per server behind an `Arc`, locked independently of `App`: the
//! sync path must reach it without taking the whole application lock, and
//! nothing here ever needs `App`. Lock order, where both are taken, is `App`
//! then this — never the reverse.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde_json::{Value, json};
use tokio::sync::watch;

/// The end-to-end encryption key directory.
///
/// Matrix keeps the cryptography in the client: a homeserver's whole job here
/// is to remember which devices exist, hand out one one-time key per requested
/// device so a peer can open an Olm session, and never hand the same one out
/// twice. This is that, and no more.
#[derive(Default)]
pub(crate) struct KeyStore {
    /// `device_keys[user][device] -> the uploaded device key object`.
    pub(crate) devices: BTreeMap<String, BTreeMap<String, Value>>,
    /// `one_time_keys[user][device][key_id] -> key`. Claiming removes.
    pub(crate) one_time_keys: BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>,
    /// Cross-signing keys, merged as uploaded and echoed back on query.
    pub(crate) cross_signing: serde_json::Map<String, Value>,
}

impl KeyStore {
    /// Store a device's keys under the id the device actually claims, not a
    /// fixed one: two devices of the same user must not overwrite each other.
    pub(crate) fn put_device(&mut self, user: &str, device: &str, keys: Value) {
        self.devices
            .entry(user.to_owned())
            .or_default()
            .insert(device.to_owned(), keys);
    }

    /// Merge uploaded one-time keys, keeping any already held.
    pub(crate) fn put_one_time_keys(
        &mut self,
        user: &str,
        device: &str,
        keys: &serde_json::Map<String, Value>,
    ) {
        let slot = self
            .one_time_keys
            .entry(user.to_owned())
            .or_default()
            .entry(device.to_owned())
            .or_default();
        for (key_id, key) in keys {
            slot.insert(key_id.clone(), key.clone());
        }
    }

    /// Counts by algorithm, which is what `/keys/upload` answers with. The
    /// client uses these to decide when to top the server up, so an invented
    /// number means it either never replenishes or replenishes forever.
    pub(crate) fn one_time_key_counts(
        &self,
        user: &str,
        device: &str,
    ) -> serde_json::Map<String, Value> {
        let mut counts = serde_json::Map::new();
        let held = self
            .one_time_keys
            .get(user)
            .and_then(|devices| devices.get(device));
        for key_id in held.into_iter().flat_map(|keys| keys.keys()) {
            let algorithm = key_id.split_once(':').map_or(key_id.as_str(), |(a, _)| a);
            let entry = counts
                .entry(algorithm.to_owned())
                .or_insert_with(|| Value::from(0u64));
            if let Some(n) = entry.as_u64() {
                *entry = Value::from(n + 1);
            }
        }
        counts
    }

    /// Device keys for an explicit `{user: [device_ids]}` request map. An
    /// empty device list means every device of that user, per the spec; a user
    /// we hold nothing for is absent from the answer rather than present and
    /// empty, so a caller can tell "no such user" from "user with no devices".
    pub(crate) fn device_keys_for(
        &self,
        requested: &serde_json::Map<String, Value>,
    ) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        for (user, wanted) in requested {
            let Some(devices) = self.devices.get(user) else {
                continue;
            };
            let filter = wanted.as_array().filter(|ids| !ids.is_empty());
            let mut per_user = serde_json::Map::new();
            for (device, keys) in devices {
                let asked_for = filter
                    .is_none_or(|ids| ids.iter().any(|id| id.as_str() == Some(device.as_str())));
                if asked_for {
                    per_user.insert(device.clone(), keys.clone());
                }
            }
            out.insert(user.clone(), Value::Object(per_user));
        }
        out
    }

    /// Claim one one-time key per `{user: {device: algorithm}}` entry. Shared
    /// by the client-server and federation `/keys/claim` handlers so a key can
    /// never be handed to a local client and a remote peer both.
    pub(crate) fn claim_for(
        &mut self,
        requested: &serde_json::Map<String, Value>,
    ) -> serde_json::Map<String, Value> {
        let mut claimed = serde_json::Map::new();
        for (user, devices) in requested {
            let Some(devices) = devices.as_object() else {
                continue;
            };
            let mut per_device = serde_json::Map::new();
            for (device, algorithm) in devices {
                let Some(algorithm) = algorithm.as_str() else {
                    continue;
                };
                if let Some((key_id, key)) = self.claim_one_time_key(user, device, algorithm) {
                    per_device.insert(device.clone(), json!({ key_id: key }));
                }
            }
            if !per_device.is_empty() {
                claimed.insert(user.clone(), Value::Object(per_device));
            }
        }
        claimed
    }

    /// Take one key of `algorithm` for a device, removing it. A one-time key
    /// handed out twice is not one-time, so this is a pop and not a read.
    pub(crate) fn claim_one_time_key(
        &mut self,
        user: &str,
        device: &str,
        algorithm: &str,
    ) -> Option<(String, Value)> {
        let keys = self.one_time_keys.get_mut(user)?.get_mut(device)?;
        let key_id = keys
            .keys()
            .find(|id| id.split_once(':').is_some_and(|(a, _)| a == algorithm))
            .cloned()?;
        let key = keys.remove(&key_id)?;
        Some((key_id, key))
    }
}

/// What the lock guards: the directory and the inbox, together because a
/// claim and the to-device message it enables belong to one flow.
#[derive(Default)]
pub(crate) struct Inner {
    /// Device keys, one-time keys and cross-signing blobs, per user and device.
    pub(crate) keys: KeyStore,
    /// Undelivered to-device messages, per recipient user. Drained by sync.
    ///
    /// Keyed by user rather than by device because login issues one device id
    /// for everyone, so the server cannot yet tell two of a user's devices
    /// apart. On a mesh node — one user, one phone — the two are the same
    /// thing; on a multi-device account they are not, and this needs
    /// revisiting when login stops handing out a fixed device id.
    pub(crate) to_device: BTreeMap<String, Vec<Value>>,
}

pub(crate) struct E2eeState {
    inner: Mutex<Inner>,
    /// Bumped on every inbox write. Sync long-polls watch it so a room key
    /// wakes the recipient now rather than on the next room event.
    changed: watch::Sender<u64>,
}

impl Default for E2eeState {
    fn default() -> Self {
        Self::new()
    }
}

impl E2eeState {
    pub(crate) fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: Mutex::new(Inner::default()),
            changed,
        }
    }

    /// The directory and inbox, for handlers that read or write keys
    /// directly. Poison is ignored for the same reason `lock_app` ignores it:
    /// every field here is independently meaningful, so a panic mid-write
    /// leaves nothing half-true.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue one to-device event for `user` and wake anyone syncing as them.
    pub(crate) fn push_to_device(
        &self,
        user: &str,
        event_type: &str,
        sender: &str,
        content: Value,
    ) {
        self.lock()
            .to_device
            .entry(user.to_owned())
            .or_default()
            .push(json!({
                "type": event_type,
                "sender": sender,
                "content": content,
            }));
        self.changed.send_modify(|n| *n += 1);
    }

    /// Take everything queued for a user, leaving the inbox empty. Matrix
    /// expects a to-device message to be delivered once; the client
    /// acknowledges by syncing again with the returned token.
    pub(crate) fn drain_to_device(&self, user: &str) -> Vec<Value> {
        self.lock().to_device.remove(user).unwrap_or_default()
    }

    /// How many to-device events wait for `user` — what a long-poll checks to
    /// decide whether it has something to return.
    pub(crate) fn pending_to_device(&self, user: &str) -> usize {
        self.lock().to_device.get(user).map_or(0, Vec::len)
    }

    /// A receiver that changes whenever the inbox is written to. Subscribe
    /// *before* checking `pending_to_device`, or a push between the two is
    /// missed until the next unrelated wake-up — the same discipline as the
    /// store's event watch.
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// One-time key counts for a user, as sync reports them. Sync does not
    /// know which of the user's devices is asking (the request carries no
    /// device id), so with several devices this is the *minimum* per
    /// algorithm: every device then believes it should top up, which errs on
    /// the side of never running out. With one device — the mesh case — it is
    /// simply that device's counts.
    pub(crate) fn one_time_key_counts_for_user(
        &self,
        user: &str,
    ) -> serde_json::Map<String, Value> {
        let inner = self.lock();
        let devices: Vec<String> = inner
            .keys
            .devices
            .get(user)
            .map(|d| d.keys().cloned().collect())
            .unwrap_or_default();
        let mut min: Option<serde_json::Map<String, Value>> = None;
        for device in devices {
            let counts = inner.keys.one_time_key_counts(user, &device);
            min = Some(match min {
                None => counts,
                Some(mut acc) => {
                    for (algorithm, n) in counts {
                        let n = n.as_u64().unwrap_or(0);
                        let entry = acc.entry(algorithm).or_insert_with(|| Value::from(n));
                        let cur = entry.as_u64().unwrap_or(0);
                        *entry = Value::from(cur.min(n));
                    }
                    acc
                }
            });
        }
        min.unwrap_or_default()
    }
}
