//! `AliasStore` impl on [`crate::SqliteStore`].
//!
//! The local room directory, in the `room_aliases` table. Only aliases in this
//! server's own namespace live here — Matrix aliases are server-scoped, so a
//! peer's alias is resolved by asking that peer over federation.
//!
//! Claiming is first-write-wins against the alias primary key. That matters for
//! the deterministic conference aliases: every attendee's client derives the
//! same `#event-session-id:server` and races to create it, so exactly one must
//! win and the rest must be able to tell they lost and join instead. An
//! `INSERT OR REPLACE` would silently repoint the alias at the newest room and
//! scatter the attendees across as many rooms as there were racers.

use async_trait::async_trait;
use deadpool_sqlite::rusqlite::{OptionalExtension, params};
use neutrino_store::{AliasStore, StorageError};
use ruma::{OwnedRoomId, RoomId, UserId};

use crate::{SqliteStore, error::Error};

#[async_trait]
impl AliasStore for SqliteStore {
    async fn put_alias(
        &self,
        alias: &str,
        room_id: &RoomId,
        created_by: &UserId,
    ) -> Result<bool, StorageError> {
        let alias = alias.to_owned();
        let room_id = room_id.to_string();
        let created_by = created_by.to_string();
        self.run_write(move |conn| -> Result<bool, Error> {
            // OR IGNORE, not OR REPLACE: a losing racer must see `false`.
            let n = conn.execute(
                "INSERT OR IGNORE INTO room_aliases (alias, room_id, created_by) \
                 VALUES (?1, ?2, ?3)",
                params![alias, room_id, created_by],
            )?;
            Ok(n == 1)
        })
        .await
    }

    async fn resolve_alias(&self, alias: &str) -> Result<Option<OwnedRoomId>, StorageError> {
        let alias = alias.to_owned();
        let found: Option<String> = self
            .run_read(move |conn| -> Result<Option<String>, Error> {
                Ok(conn
                    .query_row(
                        "SELECT room_id FROM room_aliases WHERE alias = ?1",
                        params![alias],
                        |r| r.get(0),
                    )
                    .optional()?)
            })
            .await?;
        // A row that will not parse is corruption, not a miss: say so rather
        // than reporting the alias unclaimed and letting a caller re-create it.
        found
            .map(|id| {
                RoomId::parse(&id)
                    .map_err(|e| StorageError::Internal(format!("stored room id {id:?}: {e}")))
            })
            .transpose()
    }

    async fn delete_alias(&self, alias: &str, requester: &UserId) -> Result<bool, StorageError> {
        let alias = alias.to_owned();
        let requester = requester.to_string();
        self.run_write(move |conn| -> Result<bool, Error> {
            let n = conn.execute(
                "DELETE FROM room_aliases WHERE alias = ?1 AND created_by = ?2",
                params![alias, requester],
            )?;
            Ok(n == 1)
        })
        .await
    }

    async fn aliases_for_room(&self, room_id: &RoomId) -> Result<Vec<String>, StorageError> {
        let room_id = room_id.to_string();
        self.run_read(move |conn| -> Result<Vec<String>, Error> {
            let mut stmt =
                conn.prepare("SELECT alias FROM room_aliases WHERE room_id = ?1 ORDER BY alias")?;
            let rows = stmt.query_map(params![room_id], |r| r.get::<_, String>(0))?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> SqliteStore {
        SqliteStore::open_in_memory().await.expect("open")
    }

    #[tokio::test]
    async fn first_claim_wins_and_the_loser_is_told() {
        let s = store().await;
        let a = RoomId::parse("!a:x").expect("room");
        let b = RoomId::parse("!b:x").expect("room");
        let u = UserId::parse("@n:x").expect("user");
        assert!(s.put_alias("#s:x", &a, &u).await.expect("put"));
        // The whole point: the second claim does not repoint the alias, and the
        // caller learns it lost so it can join `a` rather than sit alone in `b`.
        assert!(!s.put_alias("#s:x", &b, &u).await.expect("put"));
        assert_eq!(s.resolve_alias("#s:x").await.expect("resolve"), Some(a));
    }

    #[tokio::test]
    async fn resolves_and_lists_and_deletes_only_for_the_creator() {
        let s = store().await;
        let room = RoomId::parse("!r:x").expect("room");
        let owner = UserId::parse("@n:x").expect("user");
        let other = UserId::parse("@m:x").expect("user");
        s.put_alias("#one:x", &room, &owner).await.expect("put");
        s.put_alias("#two:x", &room, &owner).await.expect("put");
        assert_eq!(
            s.aliases_for_room(&room).await.expect("list"),
            vec!["#one:x".to_string(), "#two:x".to_string()]
        );
        assert!(!s.delete_alias("#one:x", &other).await.expect("delete"));
        assert!(s.delete_alias("#one:x", &owner).await.expect("delete"));
        assert_eq!(s.resolve_alias("#one:x").await.expect("resolve"), None);
    }

    #[tokio::test]
    async fn an_unclaimed_alias_is_none_not_an_error() {
        let s = store().await;
        assert_eq!(s.resolve_alias("#nope:x").await.expect("resolve"), None);
    }
}
