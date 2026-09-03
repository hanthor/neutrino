//! The server's share of end-to-end encryption: a device-key directory and a
//! to-device inbox, shared between the HTTP handlers and the sliding-sync
//! long-poll, written through to the store and reloaded at start.
//!
//! Matrix keeps the cryptography in the client. What a homeserver holds is
//! public key material and ciphertext addressed to devices, and what it has
//! to do well is *wake the recipient*: a Megolm room key that sits in an inbox
//! until the next unrelated event is a message the recipient cannot read
//! until then. So this state carries its own watch, advanced on every inbox
//! write, and the sync handlers select on it alongside the event stream.
//!
//! Memory is authoritative at runtime; every mutation is journaled to a task
//! that writes it to the [`E2eeStore`] in order. On a phone the app is killed
//! routinely, and a restart that forgot every device key and every
//! undelivered room key would silently break every peer's Olm session.
//!
//! Held once per server behind an `Arc`, locked independently of `App`: the
//! sync path must reach it without taking the whole application lock, and
//! nothing here ever needs `App`. Lock order, where both are taken, is `App`
//! then this — never the reverse.

use indexmap::IndexMap;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use neutrino_store::{E2eeSnapshot, E2eeStore};
use serde_json::value::RawValue as RawJsonValue;
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tracing::error;

/// One write-through, applied to the store in the order it was journaled.
/// Memory has already changed by the time an `Op` is sent; the store is
/// catching up, never consulted.
#[derive(Debug)]
pub(crate) enum Op {
    PutDevice {
        user: String,
        device: String,
        keys: Box<RawJsonValue>,
    },
    PutOneTimeKeys {
        user: String,
        device: String,
        keys: Vec<(String, Box<RawJsonValue>)>,
    },
    RemoveOneTimeKey {
        user: String,
        device: String,
        key_id: String,
    },
    PutCrossSigning {
        name: String,
        value: Box<RawJsonValue>,
    },
    PushToDevice {
        id: i64,
        user: String,
        device: String,
        event: Box<RawJsonValue>,
    },
    RemoveToDevice {
        ids: Vec<i64>,
    },
    SetDeviceStream {
        user: String,
        stream_id: u64,
    },
}

fn raw(value: &Value) -> Box<RawJsonValue> {
    serde_json::value::to_raw_value(value).expect("a serde_json::Value always serializes")
}

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
    /// `one_time_keys[user][device][key_id] -> key`, in upload order: a claim
    /// hands out the oldest key first (MSC4225), so the inner map keeps the
    /// order keys arrived in rather than sorting by id. Claiming removes.
    pub(crate) one_time_keys: BTreeMap<String, BTreeMap<String, IndexMap<String, Value>>>,
    /// Cross-signing keys, merged as uploaded and echoed back on query.
    pub(crate) cross_signing: serde_json::Map<String, Value>,
    /// `device_streams[user] -> stream_id`: how many times a local user's
    /// device list has changed. Carried in `m.device_list_update` so a peer
    /// can order our updates and notice a gap; persisted for that reason.
    pub(crate) device_streams: BTreeMap<String, u64>,
    /// Every device-list change this node has learnt of, local or remote, as
    /// `(seq, user)` in the order it happened. A sync connection remembers
    /// the `seq` it last served and reports the users after it under
    /// `device_lists.changed` — the cue for a client to fetch keys again.
    pub(crate) device_changes: Vec<(u64, String)>,
    /// The last `seq` handed out.
    pub(crate) device_seq: u64,
    /// Where every mutation is written through to, when persistence is
    /// attached. `None` in unit tests that want memory only.
    journal: Option<mpsc::UnboundedSender<Op>>,
}

impl KeyStore {
    fn journal(&self, op: Op) {
        if let Some(journal) = &self.journal {
            // A closed journal means the persistence task is gone, which only
            // happens at shutdown; memory stays correct either way.
            let _ = journal.send(op);
        }
    }

    /// Store a device's keys under the id the device actually claims, not a
    /// fixed one: two devices of the same user must not overwrite each other.
    pub(crate) fn put_device(&mut self, user: &str, device: &str, keys: Value) {
        self.journal(Op::PutDevice {
            user: user.to_owned(),
            device: device.to_owned(),
            keys: raw(&keys),
        });
        self.devices
            .entry(user.to_owned())
            .or_default()
            .insert(device.to_owned(), keys);
    }

    /// Note that `user`'s device list changed. For one of our own users the
    /// stream advances and is journaled, and the new `stream_id` is returned
    /// for the `m.device_list_update` that announces it; for a peer's user
    /// (`local = false`) only the change log moves, since their server owns
    /// their stream.
    pub(crate) fn note_device_change(&mut self, user: &str, local: bool) -> u64 {
        self.device_seq += 1;
        self.device_changes.push((self.device_seq, user.to_owned()));
        if !local {
            return 0;
        }
        let stream = self.device_streams.entry(user.to_owned()).or_default();
        *stream += 1;
        let stream_id = *stream;
        self.journal(Op::SetDeviceStream {
            user: user.to_owned(),
            stream_id,
        });
        stream_id
    }

    /// A local user's device-list `stream_id`; `0` before any change.
    pub(crate) fn device_stream(&self, user: &str) -> u64 {
        self.device_streams.get(user).copied().unwrap_or(0)
    }

    /// Users whose device list changed after `since`, oldest first, each
    /// once.
    pub(crate) fn device_changes_since(&self, since: u64) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (seq, user) in &self.device_changes {
            if *seq > since && !out.contains(user) {
                out.push(user.clone());
            }
        }
        out
    }

    /// Store a cross-signing section as uploaded; echoed back on query.
    pub(crate) fn put_cross_signing(&mut self, name: &str, value: Value) {
        self.journal(Op::PutCrossSigning {
            name: name.to_owned(),
            value: raw(&value),
        });
        self.cross_signing.insert(name.to_owned(), value);
    }

    /// Merge a `/keys/signatures/upload` block into the stored device it
    /// signs. An absent device is skipped rather than created, since a
    /// signature over nothing means nothing.
    pub(crate) fn merge_device_signatures(
        &mut self,
        user: &str,
        device: &str,
        signatures: serde_json::Map<String, Value>,
    ) {
        let Some(stored) = self.devices.get_mut(user).and_then(|d| d.get_mut(device)) else {
            return;
        };
        if let Some(target) = stored
            .pointer_mut(&format!("/signatures/{user}"))
            .and_then(Value::as_object_mut)
        {
            target.extend(signatures);
        }
        let keys = raw(stored);
        self.journal(Op::PutDevice {
            user: user.to_owned(),
            device: device.to_owned(),
            keys,
        });
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
        let mut fresh = Vec::new();
        for (key_id, key) in keys {
            if !slot.contains_key(key_id) {
                fresh.push((key_id.clone(), raw(key)));
            }
            slot.insert(key_id.clone(), key.clone());
        }
        self.journal(Op::PutOneTimeKeys {
            user: user.to_owned(),
            device: device.to_owned(),
            keys: fresh,
        });
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
            // A user we hold nothing for answers with an empty map: the
            // caller asked about them and gets a definite "no devices", not
            // an absence it would have to read as "not answered".
            let Some(devices) = self.devices.get(user) else {
                out.insert(user.clone(), Value::Object(serde_json::Map::new()));
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
        let key = keys.shift_remove(&key_id)?;
        self.journal(Op::RemoveOneTimeKey {
            user: user.to_owned(),
            device: device.to_owned(),
            key_id: key_id.clone(),
        });
        Some((key_id, key))
    }
}

/// What the lock guards: the directory and the inbox, together because a
/// claim and the to-device message it enables belong to one flow.
#[derive(Default)]
pub(crate) struct Inner {
    /// Device keys, one-time keys and cross-signing blobs, per user and device.
    pub(crate) keys: KeyStore,
    /// Undelivered to-device messages, per recipient user, each under the id
    /// its store row carries and the device it is for. Drained by the sync of
    /// that device. `*` as the device is a message for whichever device of
    /// the user syncs first — what a sender uses when it knows none of them.
    pub(crate) to_device: BTreeMap<String, Vec<(i64, String, Value)>>,
    /// Next inbox id. Process-lifetime, seeded past the loaded snapshot's
    /// maximum so memory and disk name the same rows.
    next_inbox_id: i64,
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

    /// Rebuild memory from what the store holds. Called once before serving;
    /// rows loaded here are not journaled again.
    pub(crate) fn load(&self, snapshot: E2eeSnapshot) {
        let parse = |r: &RawJsonValue| serde_json::from_str::<Value>(r.get()).ok();
        let mut inner = self.lock();
        for (user, device, keys) in &snapshot.devices {
            if let Some(keys) = parse(keys) {
                inner
                    .keys
                    .devices
                    .entry(user.clone())
                    .or_default()
                    .insert(device.clone(), keys);
            }
        }
        for (user, stream_id) in &snapshot.device_streams {
            inner.keys.device_streams.insert(user.clone(), *stream_id);
        }
        for (user, device, key_id, key) in &snapshot.one_time_keys {
            if let Some(key) = parse(key) {
                inner
                    .keys
                    .one_time_keys
                    .entry(user.clone())
                    .or_default()
                    .entry(device.clone())
                    .or_default()
                    .insert(key_id.clone(), key);
            }
        }
        for (name, value) in &snapshot.cross_signing {
            if let Some(value) = parse(value) {
                inner.keys.cross_signing.insert(name.clone(), value);
            }
        }
        let mut max_id = inner.next_inbox_id - 1;
        for (id, user, device, event) in &snapshot.to_device {
            if let Some(event) = parse(event) {
                inner
                    .to_device
                    .entry(user.clone())
                    .or_default()
                    .push((*id, device.clone(), event));
                max_id = max_id.max(*id);
            }
        }
        inner.next_inbox_id = max_id + 1;
        drop(inner);
        if !snapshot.to_device.is_empty() {
            self.changed.send_modify(|n| *n += 1);
        }
    }

    /// Write every later mutation through to `store`, in order, on a task
    /// that lives as long as this state does. Memory stays authoritative; a
    /// write that fails is logged, and the next restart simply loads less
    /// than it might have.
    pub(crate) fn attach_persistence<S: E2eeStore + 'static>(&self, store: Arc<S>) {
        let (tx, mut rx) = mpsc::unbounded_channel::<Op>();
        self.lock().keys.journal = Some(tx);
        tokio::spawn(async move {
            while let Some(op) = rx.recv().await {
                let result = match &op {
                    Op::PutDevice { user, device, keys } => {
                        store.put_device_keys(user, device, keys).await
                    }
                    Op::PutOneTimeKeys { user, device, keys } => {
                        store.put_one_time_keys(user, device, keys).await
                    }
                    Op::RemoveOneTimeKey {
                        user,
                        device,
                        key_id,
                    } => store.remove_one_time_key(user, device, key_id).await,
                    Op::PutCrossSigning { name, value } => {
                        store.put_cross_signing(name, value).await
                    }
                    Op::PushToDevice {
                        id,
                        user,
                        device,
                        event,
                    } => store.push_to_device(*id, user, device, event).await,
                    Op::RemoveToDevice { ids } => store.remove_to_device(ids).await,
                    Op::SetDeviceStream { user, stream_id } => {
                        store.put_device_stream(user, *stream_id).await
                    }
                };
                if let Err(e) = result {
                    error!(error = %e, ?op, "persisting E2EE state");
                }
            }
        });
    }

    /// Queue one to-device event for a device of `user` and wake anyone
    /// syncing as them. `device` may be `*`: whichever device syncs first.
    pub(crate) fn push_to_device(
        &self,
        user: &str,
        device: &str,
        event_type: &str,
        sender: &str,
        content: Value,
    ) {
        let event = json!({
            "type": event_type,
            "sender": sender,
            "content": content,
        });
        let mut inner = self.lock();
        let id = inner.next_inbox_id;
        inner.next_inbox_id += 1;
        inner.keys.journal(Op::PushToDevice {
            id,
            user: user.to_owned(),
            device: device.to_owned(),
            event: raw(&event),
        });
        inner
            .to_device
            .entry(user.to_owned())
            .or_default()
            .push((id, device.to_owned(), event));
        drop(inner);
        self.changed.send_modify(|n| *n += 1);
    }

    /// Queue a `{device: content}` map as `/sendToDevice` and the
    /// `m.direct_to_device` EDU carry it. `*` fans out to every device the
    /// directory knows for the user — which is what a room-key share to a
    /// freshly-seen peer uses — and, when it knows none, stays a wildcard
    /// row for whichever device turns up first.
    pub(crate) fn push_to_devices(
        &self,
        user: &str,
        targets: &serde_json::Map<String, Value>,
        event_type: &str,
        sender: &str,
    ) {
        for (device, content) in targets {
            if device == "*" {
                let known: Vec<String> = self
                    .lock()
                    .keys
                    .devices
                    .get(user)
                    .map(|d| d.keys().cloned().collect())
                    .unwrap_or_default();
                if known.is_empty() {
                    self.push_to_device(user, "*", event_type, sender, content.clone());
                }
                for device in known {
                    self.push_to_device(user, &device, event_type, sender, content.clone());
                }
            } else {
                self.push_to_device(user, device, event_type, sender, content.clone());
            }
        }
    }

    /// Whether an inbox row addressed to `row_device` is for the device
    /// syncing as `device`. A wildcard on either side matches.
    fn addressed_to(row_device: &str, device: &str) -> bool {
        row_device == "*" || device == "*" || row_device == device
    }

    /// Take everything queued for `device` of `user` (or every device, for
    /// `*`), leaving the rest. Matrix expects a to-device message to be
    /// delivered once; the client acknowledges by syncing again with the
    /// returned token.
    pub(crate) fn drain_to_device(&self, user: &str, device: &str) -> Vec<Value> {
        let mut inner = self.lock();
        let Some(rows) = inner.to_device.get_mut(user) else {
            return Vec::new();
        };
        let (drained, kept): (Vec<_>, Vec<_>) = std::mem::take(rows)
            .into_iter()
            .partition(|(_, row_device, _)| Self::addressed_to(row_device, device));
        *rows = kept;
        if drained.is_empty() {
            return Vec::new();
        }
        let ids: Vec<i64> = drained.iter().map(|(id, _, _)| *id).collect();
        inner.keys.journal(Op::RemoveToDevice { ids });
        drained.into_iter().map(|(_, _, event)| event).collect()
    }

    /// Record a device-list change and wake every sync waiting on this
    /// state: a client that learns of it now can fetch the new keys before
    /// its next message, not after. Returns the user's new `stream_id`
    /// (`0` for a peer's user).
    pub(crate) fn note_device_change(&self, user: &str, local: bool) -> u64 {
        let stream_id = self.lock().keys.note_device_change(user, local);
        self.changed.send_modify(|n| *n += 1);
        stream_id
    }

    /// The change-log position now; a sync remembers it and asks for what
    /// came after.
    pub(crate) fn device_seq(&self) -> u64 {
        self.lock().keys.device_seq
    }

    /// Users whose device list changed after `since`.
    pub(crate) fn device_changes_since(&self, since: u64) -> Vec<String> {
        self.lock().keys.device_changes_since(since)
    }

    /// How many to-device events wait for `device` of `user` — what a
    /// long-poll checks to decide whether it has something to return.
    pub(crate) fn pending_to_device(&self, user: &str, device: &str) -> usize {
        self.lock().to_device.get(user).map_or(0, |rows| {
            rows.iter()
                .filter(|(_, row_device, _)| Self::addressed_to(row_device, device))
                .count()
        })
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
