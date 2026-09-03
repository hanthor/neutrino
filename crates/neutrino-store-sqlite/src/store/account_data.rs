//! `AccountDataStore` impl on [`crate::SqliteStore`]: one table of
//! wire-verbatim JSON, `room = ''` for a global entry.

use async_trait::async_trait;
use deadpool_sqlite::rusqlite::params;
use neutrino_store::{AccountDataStore, StorageError};
use serde_json::value::RawValue as RawJsonValue;

use crate::{SqliteStore, error::Error};

fn raw(text: String) -> Result<Box<RawJsonValue>, Error> {
    RawJsonValue::from_string(text)
        .map_err(|e| Error::Internal(format!("malformed JSON in DB: {e}")))
}

#[async_trait]
impl AccountDataStore for SqliteStore {
    async fn load_account_data(
        &self,
    ) -> Result<Vec<(String, Option<String>, String, Box<RawJsonValue>)>, StorageError> {
        self.run_read(move |conn| -> Result<Vec<_>, Error> {
            let mut stmt =
                conn.prepare("SELECT user, room, event_type, content FROM account_data")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                let (user, room, event_type, content) = r?;
                let room = if room.is_empty() { None } else { Some(room) };
                out.push((user, room, event_type, raw(content)?));
            }
            Ok(out)
        })
        .await
    }

    async fn put_account_data(
        &self,
        user: &str,
        room: Option<&str>,
        event_type: &str,
        content: &RawJsonValue,
    ) -> Result<(), StorageError> {
        let (user, room, event_type, content) = (
            user.to_owned(),
            room.unwrap_or_default().to_owned(),
            event_type.to_owned(),
            content.get().to_owned(),
        );
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT INTO account_data (user, room, event_type, content) VALUES (?, ?, ?, ?) \
                 ON CONFLICT(user, room, event_type) DO UPDATE SET content = excluded.content",
                params![user, room, event_type, content],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(v: Value) -> Box<RawJsonValue> {
        serde_json::value::to_raw_value(&v).unwrap()
    }
    use serde_json::Value;

    #[tokio::test]
    async fn account_data_round_trips_and_replaces() {
        let tmp = tempfile::TempDir::new().unwrap();
        let s = SqliteStore::open(tmp.path().join("store.sqlite"))
            .await
            .unwrap();
        s.put_account_data("@a:x", None, "m.direct", &raw(json!({"v": 1})))
            .await
            .unwrap();
        s.put_account_data("@a:x", None, "m.direct", &raw(json!({"v": 2})))
            .await
            .unwrap();
        s.put_account_data("@a:x", Some("!r:x"), "m.tag", &raw(json!({"t": 1})))
            .await
            .unwrap();
        let mut rows = s.load_account_data().await.unwrap();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(rows.len(), 2, "the second global write replaced the first");
        assert_eq!(rows[0].1, None);
        assert_eq!(rows[0].3.get(), r#"{"v":2}"#);
        assert_eq!(rows[1].1.as_deref(), Some("!r:x"));
    }
}
