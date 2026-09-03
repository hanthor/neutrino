//! Ephemeral room data: who is typing, and who has read up to where.
//!
//! Neither is an event. Typing expires on its own and is never persisted;
//! a read receipt is the newest position a user has acknowledged in a room,
//! one per user, replaced rather than appended. Both arrive from local
//! clients (`/typing`, `/receipt`) and from peers (`m.typing` / `m.receipt`
//! EDUs), and both have to wake a sliding-sync long-poll the moment they
//! change — a typing notice delivered on the next room event is a typing
//! notice delivered after the message it announced.
//!
//! Same shape as [`crate::e2ee::E2eeState`]: one `Arc` per server, its own
//! lock, its own watch, reachable from the handlers and the sync path without
//! the application lock.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ruma::{OwnedEventId, OwnedRoomId, OwnedUserId, RoomId, UserId};
use tokio::sync::watch;

/// Spec default for a typing notice with no `timeout`, and the ceiling for
/// one that asks for more: a phone that stops sending stops being shown.
const DEFAULT_TYPING_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TYPING_TIMEOUT: Duration = Duration::from_secs(120);

/// One user's read position in a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadReceipt {
    pub(crate) event_id: OwnedEventId,
    /// Milliseconds since the epoch, as the client or peer reported it.
    pub(crate) ts: u64,
}

#[derive(Default)]
struct Inner {
    /// `typing[room][user] -> when the notice expires`. A room stays in the
    /// map once it has had a notice, empty or not, so a stop can be told
    /// apart from never having started.
    typing: BTreeMap<OwnedRoomId, BTreeMap<OwnedUserId, Instant>>,
    /// The change counter's value when `typing[room]` last changed — a start,
    /// a stop, or an expiry noticed on read. A sync that remembers the
    /// counter it last served asks for the rooms stamped after it, which is
    /// how "nobody is typing any more" reaches a client as an empty notice.
    typing_changed: BTreeMap<OwnedRoomId, u64>,
    /// `receipts[room][user] -> newest m.read`.
    receipts: BTreeMap<OwnedRoomId, BTreeMap<OwnedUserId, ReadReceipt>>,
}

pub(crate) struct EphemeralState {
    inner: Mutex<Inner>,
    /// Bumped on every change. Sync long-polls watch it and compare against
    /// the value they started with, so a notice that arrives mid-wait is
    /// returned now.
    changed: watch::Sender<u64>,
}

impl Default for EphemeralState {
    fn default() -> Self {
        Self::new()
    }
}

impl EphemeralState {
    pub(crate) fn new() -> Self {
        let (changed, _) = watch::channel(0);
        Self {
            inner: Mutex::new(Inner::default()),
            changed,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn bump(&self) {
        self.changed.send_modify(|n| *n += 1);
    }

    /// Record that `room`'s typing set changed, stamped with the counter
    /// value the bump produces. Called with the lock held so the stamp and
    /// the counter cannot disagree.
    fn stamp_typing(&self, inner: &mut Inner, room: &RoomId) {
        let next = *self.changed.borrow() + 1;
        inner.typing_changed.insert(room.to_owned(), next);
        self.changed.send_modify(|n| *n = next);
    }

    /// Drop expired notices in every room, stamping the rooms that lost one.
    fn expire_typing(&self, inner: &mut Inner) {
        let now = Instant::now();
        let expired: Vec<OwnedRoomId> = inner
            .typing
            .iter_mut()
            .filter_map(|(room, users)| {
                let before = users.len();
                users.retain(|_, expiry| *expiry > now);
                (users.len() != before).then(|| room.clone())
            })
            .collect();
        for room in expired {
            self.stamp_typing(inner, &room);
        }
    }

    /// The change counter now; compare a later reading to know whether
    /// anything moved in between.
    pub(crate) fn version(&self) -> u64 {
        *self.changed.borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Start or stop a user's typing notice. `timeout` is the client's; the
    /// default applies when absent and the ceiling when excessive.
    pub(crate) fn set_typing(
        &self,
        room: &RoomId,
        user: &UserId,
        typing: bool,
        timeout: Option<Duration>,
    ) {
        let mut inner = self.lock();
        let room_typing = inner.typing.entry(room.to_owned()).or_default();
        let before = room_typing.contains_key(user);
        if typing {
            let ttl = timeout
                .unwrap_or(DEFAULT_TYPING_TIMEOUT)
                .min(MAX_TYPING_TIMEOUT);
            room_typing.insert(user.to_owned(), Instant::now() + ttl);
        } else {
            room_typing.remove(user);
        }
        // A refreshed notice is not a change worth waking for; a start or a
        // stop is.
        if before != typing {
            self.stamp_typing(&mut inner, room);
        }
    }

    /// Users typing in `room` right now, expired notices dropped.
    pub(crate) fn typing_in(&self, room: &RoomId) -> Vec<OwnedUserId> {
        let mut inner = self.lock();
        self.expire_typing(&mut inner);
        inner
            .typing
            .get(room)
            .map(|users| users.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Rooms whose typing set changed after the counter stood at `since` —
    /// including rooms that emptied, which is the news a stop carries.
    /// `since = 0` is every room that has ever had a notice.
    pub(crate) fn typing_changed_since(&self, since: u64) -> Vec<OwnedRoomId> {
        let mut inner = self.lock();
        self.expire_typing(&mut inner);
        inner
            .typing_changed
            .iter()
            .filter(|(_, stamp)| **stamp > since)
            .map(|(room, _)| room.clone())
            .collect()
    }

    /// Move a user's read position in `room` forward to `event_id`. A receipt
    /// older than the one held (by timestamp) is ignored: receipts can arrive
    /// out of order over federation and a read position never walks back.
    pub(crate) fn set_receipt(&self, room: &RoomId, user: &UserId, receipt: ReadReceipt) {
        let mut inner = self.lock();
        let room_receipts = inner.receipts.entry(room.to_owned()).or_default();
        if room_receipts
            .get(user)
            .is_some_and(|held| held.ts > receipt.ts || *held == receipt)
        {
            return;
        }
        room_receipts.insert(user.to_owned(), receipt);
        drop(inner);
        self.bump();
    }

    /// Rooms with at least one read receipt.
    pub(crate) fn rooms_with_receipts(&self) -> Vec<OwnedRoomId> {
        self.lock()
            .receipts
            .iter()
            .filter(|(_, r)| !r.is_empty())
            .map(|(room, _)| room.clone())
            .collect()
    }

    /// Every user's read position in `room`.
    pub(crate) fn receipts_in(&self, room: &RoomId) -> BTreeMap<OwnedUserId, ReadReceipt> {
        self.lock().receipts.get(room).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruma::{room_id, user_id};

    #[test]
    fn typing_starts_stops_and_expires() {
        let s = EphemeralState::new();
        let room = room_id!("!r:x");
        let alice = user_id!("@alice:x");
        let v0 = s.version();
        s.set_typing(room, alice, true, None);
        assert_eq!(s.typing_in(room), vec![alice.to_owned()]);
        assert!(s.version() > v0, "a start wakes");
        let v1 = s.version();
        s.set_typing(room, alice, true, None);
        assert_eq!(s.version(), v1, "a refresh does not");
        s.set_typing(room, alice, false, None);
        assert!(s.typing_in(room).is_empty());
        assert!(s.version() > v1, "a stop wakes");

        s.set_typing(room, alice, true, Some(Duration::ZERO));
        assert!(
            s.typing_in(room).is_empty(),
            "expired notices are dropped on read"
        );
    }

    #[test]
    fn a_stop_is_a_change_a_sync_can_ask_for() {
        let s = EphemeralState::new();
        let room = room_id!("!r:x");
        let other = room_id!("!other:x");
        let alice = user_id!("@alice:x");
        assert!(s.typing_changed_since(0).is_empty(), "nothing yet");

        s.set_typing(room, alice, true, None);
        let served = s.version();
        assert_eq!(s.typing_changed_since(0), vec![room.to_owned()]);
        assert!(s.typing_changed_since(served).is_empty(), "already served");

        s.set_typing(room, alice, false, None);
        assert_eq!(
            s.typing_changed_since(served),
            vec![room.to_owned()],
            "the stop is news even though the room is now empty"
        );
        assert!(s.typing_in(room).is_empty());

        let served = s.version();
        s.set_typing(other, alice, true, Some(Duration::ZERO));
        assert_eq!(
            s.typing_changed_since(served),
            vec![other.to_owned()],
            "an expiry noticed on read is a change too"
        );
    }

    #[test]
    fn receipts_only_move_forward() {
        let s = EphemeralState::new();
        let room = room_id!("!r:x");
        let alice = user_id!("@alice:x");
        let newer = ReadReceipt {
            event_id: "$b:x".try_into().unwrap(),
            ts: 20,
        };
        let older = ReadReceipt {
            event_id: "$a:x".try_into().unwrap(),
            ts: 10,
        };
        s.set_receipt(room, alice, newer.clone());
        let v = s.version();
        s.set_receipt(room, alice, older);
        assert_eq!(s.receipts_in(room)[alice], newer);
        assert_eq!(s.version(), v, "an older receipt changes nothing");
        s.set_receipt(room, alice, newer);
        assert_eq!(s.version(), v, "a repeat changes nothing");
    }
}
