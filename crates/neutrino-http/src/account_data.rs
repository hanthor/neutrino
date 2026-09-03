//! Account data: the small per-user key/value store a client keeps on its
//! homeserver — the DM list (`m.direct`), room tags, push rules it wrote,
//! anything a client wants to find again on another device or after a
//! reinstall.
//!
//! Global entries are keyed by type; room entries by room and type. Every
//! write replaces the previous value, is written through to the store before
//! it is acknowledged, and stamps the change so a sync connection that
//! remembers the counter it last served can ask for what changed since —
//! the same shape as typing notices in [`crate::ephemeral`].

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use serde_json::Value;
use tokio::sync::watch;

/// One entry as sync reports it: `(type, content)`.
pub(crate) type Entry = (String, Value);

#[derive(Default)]
struct Inner {
    /// `global[user][type] -> content`.
    global: BTreeMap<String, BTreeMap<String, Value>>,
    /// `rooms[user][room][type] -> content`.
    rooms: BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>,
    /// `(stamp, user, room, type)` for every write since startup, newest
    /// last. A sync asks for the entries stamped after the counter it last
    /// served and gets their current content.
    changes: Vec<(u64, String, Option<String>, String)>,
}

pub(crate) struct AccountDataState {
    inner: Mutex<Inner>,
    /// Bumped on every write. Sync long-polls watch it.
    changed: watch::Sender<u64>,
}

impl Default for AccountDataState {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountDataState {
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

    pub(crate) fn version(&self) -> u64 {
        *self.changed.borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Rebuild from the store at startup. Nothing is stamped: a connection
    /// that has never synced is sent everything anyway.
    pub(crate) fn load(&self, rows: Vec<(String, Option<String>, String, Value)>) {
        let mut inner = self.lock();
        for (user, room, event_type, content) in rows {
            match room {
                None => {
                    inner
                        .global
                        .entry(user)
                        .or_default()
                        .insert(event_type, content);
                }
                Some(room) => {
                    inner
                        .rooms
                        .entry(user)
                        .or_default()
                        .entry(room)
                        .or_default()
                        .insert(event_type, content);
                }
            }
        }
    }

    fn stamp(&self, inner: &mut Inner, user: &str, room: Option<&str>, event_type: &str) {
        let next = *self.changed.borrow() + 1;
        inner.changes.push((
            next,
            user.to_owned(),
            room.map(str::to_owned),
            event_type.to_owned(),
        ));
        self.changed.send_modify(|n| *n = next);
    }

    pub(crate) fn set_global(&self, user: &str, event_type: &str, content: Value) {
        let mut inner = self.lock();
        inner
            .global
            .entry(user.to_owned())
            .or_default()
            .insert(event_type.to_owned(), content);
        self.stamp(&mut inner, user, None, event_type);
    }

    pub(crate) fn set_room(&self, user: &str, room: &str, event_type: &str, content: Value) {
        let mut inner = self.lock();
        inner
            .rooms
            .entry(user.to_owned())
            .or_default()
            .entry(room.to_owned())
            .or_default()
            .insert(event_type.to_owned(), content);
        self.stamp(&mut inner, user, Some(room), event_type);
    }

    pub(crate) fn get_global(&self, user: &str, event_type: &str) -> Option<Value> {
        self.lock().global.get(user)?.get(event_type).cloned()
    }

    pub(crate) fn get_room(&self, user: &str, room: &str, event_type: &str) -> Option<Value> {
        self.lock()
            .rooms
            .get(user)?
            .get(room)?
            .get(event_type)
            .cloned()
    }

    /// What a sync for `user` should carry: everything held when `since` is
    /// `0` (a connection that has seen nothing), otherwise the entries
    /// written after the counter stood at `since`, each with its current
    /// content. Returns `(global, per room)`.
    pub(crate) fn changed_since(
        &self,
        user: &str,
        since: u64,
    ) -> (Vec<Entry>, BTreeMap<String, Vec<Entry>>) {
        let inner = self.lock();
        let mut global = Vec::new();
        let mut rooms: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        if since == 0 {
            if let Some(held) = inner.global.get(user) {
                global.extend(held.iter().map(|(t, c)| (t.clone(), c.clone())));
            }
            if let Some(held) = inner.rooms.get(user) {
                for (room, entries) in held {
                    rooms.insert(
                        room.clone(),
                        entries
                            .iter()
                            .map(|(t, c)| (t.clone(), c.clone()))
                            .collect(),
                    );
                }
            }
            return (global, rooms);
        }
        let mut seen = std::collections::BTreeSet::new();
        for (stamp, who, room, event_type) in inner.changes.iter().rev() {
            if *stamp <= since {
                break;
            }
            if who != user || !seen.insert((room.clone(), event_type.clone())) {
                continue;
            }
            match room {
                None => {
                    if let Some(content) = inner.global.get(user).and_then(|g| g.get(event_type)) {
                        global.push((event_type.clone(), content.clone()));
                    }
                }
                Some(room) => {
                    if let Some(content) = inner
                        .rooms
                        .get(user)
                        .and_then(|r| r.get(room))
                        .and_then(|e| e.get(event_type))
                    {
                        rooms
                            .entry(room.clone())
                            .or_default()
                            .push((event_type.clone(), content.clone()));
                    }
                }
            }
        }
        (global, rooms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn writes_replace_and_are_reported_once_since_a_version() {
        let s = AccountDataState::new();
        s.set_global("@a:x", "m.direct", json!({"@b:x": ["!r:x"]}));
        let v1 = s.version();
        s.set_room("@a:x", "!r:x", "m.tag", json!({"tags": {}}));
        s.set_global("@a:x", "m.direct", json!({"@b:x": ["!r:x", "!s:x"]}));
        s.set_global("@other:x", "m.direct", json!({}));

        let (global, rooms) = s.changed_since("@a:x", 0);
        assert_eq!(global.len(), 1, "everything held, once");
        assert_eq!(global[0].1["@b:x"], json!(["!r:x", "!s:x"]));
        assert_eq!(rooms["!r:x"][0].0, "m.tag");

        let (global, rooms) = s.changed_since("@a:x", v1);
        assert_eq!(global.len(), 1, "the later m.direct write, current content");
        assert_eq!(global[0].1["@b:x"], json!(["!r:x", "!s:x"]));
        assert_eq!(rooms.len(), 1);

        let (global, rooms) = s.changed_since("@a:x", s.version());
        assert!(global.is_empty() && rooms.is_empty(), "nothing since now");
        assert_eq!(
            s.get_room("@a:x", "!r:x", "m.tag").unwrap()["tags"],
            json!({})
        );
        assert!(s.get_global("@nobody:x", "m.direct").is_none());
    }
}
