//! `E2eeStore` impl on [`crate::SqliteStore`].
//!
//! Four small tables of wire-verbatim JSON text (`device_keys`,
//! `one_time_keys`, `cross_signing_keys`, `to_device_inbox`). Nothing here is
//! interpreted; the in-memory directory in `neutrino-http` is the runtime
//! copy and these rows are what it is rebuilt from after a restart.

use async_trait::async_trait;
use deadpool_sqlite::rusqlite::params;
use neutrino_store::{E2eeSnapshot, E2eeStore, StorageError};
use serde_json::value::RawValue as RawJsonValue;

use crate::{SqliteStore, error::Error};

fn raw(text: String) -> Result<Box<RawJsonValue>, Error> {
    RawJsonValue::from_string(text)
        .map_err(|e| Error::Internal(format!("malformed JSON in DB: {e}")))
}

#[async_trait]
impl E2eeStore for SqliteStore {
    async fn load_e2ee(&self) -> Result<E2eeSnapshot, StorageError> {
        self.run_read(move |conn| -> Result<E2eeSnapshot, Error> {
            let mut snapshot = E2eeSnapshot::default();

            let mut stmt = conn.prepare("SELECT user, device, keys FROM device_keys")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for r in rows {
                let (user, device, keys) = r?;
                snapshot.devices.push((user, device, raw(keys)?));
            }

            let mut stmt = conn.prepare(
                "SELECT user, device, key_id, key FROM one_time_keys ORDER BY user, device, seq",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for r in rows {
                let (user, device, key_id, key) = r?;
                snapshot
                    .one_time_keys
                    .push((user, device, key_id, raw(key)?));
            }

            let mut stmt = conn.prepare("SELECT name, value FROM cross_signing_keys")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for r in rows {
                let (name, value) = r?;
                snapshot.cross_signing.push((name, raw(value)?));
            }

            let mut stmt = conn.prepare(
                "SELECT inbox_id, user, event FROM to_device_inbox ORDER BY inbox_id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for r in rows {
                let (id, user, event) = r?;
                snapshot.to_device.push((id, user, raw(event)?));
            }

            let mut stmt = conn.prepare("SELECT user, stream_id FROM device_streams")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for r in rows {
                let (user, stream_id) = r?;
                snapshot
                    .device_streams
                    .push((user, u64::try_from(stream_id).unwrap_or(0)));
            }

            Ok(snapshot)
        })
        .await
    }

    async fn put_device_keys(
        &self,
        user: &str,
        device: &str,
        keys: &RawJsonValue,
    ) -> Result<(), StorageError> {
        let (user, device, keys) = (user.to_owned(), device.to_owned(), keys.get().to_owned());
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT INTO device_keys (user, device, keys) VALUES (?, ?, ?) \
                 ON CONFLICT (user, device) DO UPDATE SET keys = excluded.keys",
                params![user, device, keys],
            )?;
            Ok(())
        })
        .await
    }

    async fn put_one_time_keys(
        &self,
        user: &str,
        device: &str,
        keys: &[(String, Box<RawJsonValue>)],
    ) -> Result<(), StorageError> {
        if keys.is_empty() {
            return Ok(());
        }
        let (user, device) = (user.to_owned(), device.to_owned());
        let keys: Vec<(String, String)> = keys
            .iter()
            .map(|(id, key)| (id.clone(), key.get().to_owned()))
            .collect();
        self.run_write(move |conn| -> Result<(), Error> {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT OR IGNORE INTO one_time_keys (user, device, key_id, key, seq) \
                     VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM one_time_keys))",
                )?;
                for (key_id, key) in &keys {
                    stmt.execute(params![user, device, key_id, key])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    async fn remove_one_time_key(
        &self,
        user: &str,
        device: &str,
        key_id: &str,
    ) -> Result<(), StorageError> {
        let (user, device, key_id) = (user.to_owned(), device.to_owned(), key_id.to_owned());
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "DELETE FROM one_time_keys WHERE user = ? AND device = ? AND key_id = ?",
                params![user, device, key_id],
            )?;
            Ok(())
        })
        .await
    }

    async fn put_cross_signing(
        &self,
        name: &str,
        value: &RawJsonValue,
    ) -> Result<(), StorageError> {
        let (name, value) = (name.to_owned(), value.get().to_owned());
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT INTO cross_signing_keys (name, value) VALUES (?, ?) \
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value",
                params![name, value],
            )?;
            Ok(())
        })
        .await
    }

    async fn put_device_stream(&self, user: &str, stream_id: u64) -> Result<(), StorageError> {
        let user = user.to_owned();
        let stream_id = i64::try_from(stream_id).unwrap_or(i64::MAX);
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT INTO device_streams (user, stream_id) VALUES (?, ?) \
                 ON CONFLICT (user) DO UPDATE SET stream_id = excluded.stream_id",
                params![user, stream_id],
            )?;
            Ok(())
        })
        .await
    }

    async fn push_to_device(
        &self,
        id: i64,
        user: &str,
        event: &RawJsonValue,
    ) -> Result<(), StorageError> {
        let (user, event) = (user.to_owned(), event.get().to_owned());
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT OR IGNORE INTO to_device_inbox (inbox_id, user, event) VALUES (?, ?, ?)",
                params![id, user, event],
            )?;
            Ok(())
        })
        .await
    }

    async fn remove_to_device(&self, ids: &[i64]) -> Result<(), StorageError> {
        if ids.is_empty() {
            return Ok(());
        }
        let ids = ids.to_vec();
        self.run_write(move |conn| -> Result<(), Error> {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare("DELETE FROM to_device_inbox WHERE inbox_id = ?")?;
                for id in &ids {
                    stmt.execute(params![id])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use neutrino_store::E2eeStore;
    use serde_json::json;

    use crate::tests::store;

    fn raw(v: serde_json::Value) -> Box<serde_json::value::RawValue> {
        serde_json::value::to_raw_value(&v).unwrap()
    }

    #[tokio::test]
    async fn empty_store_loads_an_empty_snapshot() {
        let s = store().await;
        let snap = s.load_e2ee().await.unwrap();
        assert!(snap.devices.is_empty());
        assert!(snap.one_time_keys.is_empty());
        assert!(snap.cross_signing.is_empty());
        assert!(snap.to_device.is_empty());
    }

    // Every table round-trips; a device upload replaces, a one-time key is
    // never replaced, a claim removes exactly its row.
    #[tokio::test]
    async fn keys_round_trip_with_the_right_conflict_rules() {
        let s = store().await;
        s.put_device_keys("@a:x", "D1", &raw(json!({ "v": 1 })))
            .await
            .unwrap();
        s.put_device_keys("@a:x", "D1", &raw(json!({ "v": 2 })))
            .await
            .unwrap();
        s.put_one_time_keys(
            "@a:x",
            "D1",
            &[
                ("k1".to_owned(), raw(json!("one"))),
                ("k2".to_owned(), raw(json!("two"))),
            ],
        )
        .await
        .unwrap();
        s.put_one_time_keys("@a:x", "D1", &[("k1".to_owned(), raw(json!("changed")))])
            .await
            .unwrap();
        s.put_cross_signing("master_key", &raw(json!({ "m": true })))
            .await
            .unwrap();
        s.remove_one_time_key("@a:x", "D1", "k2").await.unwrap();
        s.remove_one_time_key("@a:x", "D1", "k2").await.unwrap();

        let snap = s.load_e2ee().await.unwrap();
        assert_eq!(snap.devices.len(), 1);
        assert_eq!(snap.devices[0].2.get(), r#"{"v":2}"#);
        assert_eq!(snap.one_time_keys.len(), 1);
        assert_eq!(snap.one_time_keys[0].2, "k1");
        assert_eq!(
            snap.one_time_keys[0].3.get(),
            r#""one""#,
            "first upload wins"
        );
        assert_eq!(snap.cross_signing[0].0, "master_key");
    }

    // The inbox keeps caller-assigned ids in order, ignores a repeated id,
    // and a drain removes exactly the named rows.
    #[tokio::test]
    async fn inbox_keeps_order_and_ids() {
        let s = store().await;
        s.push_to_device(7, "@a:x", &raw(json!({ "n": 7 })))
            .await
            .unwrap();
        s.push_to_device(3, "@a:x", &raw(json!({ "n": 3 })))
            .await
            .unwrap();
        s.push_to_device(7, "@a:x", &raw(json!({ "n": 70 })))
            .await
            .unwrap();
        s.push_to_device(9, "@b:x", &raw(json!({ "n": 9 })))
            .await
            .unwrap();

        let snap = s.load_e2ee().await.unwrap();
        let ids: Vec<i64> = snap.to_device.iter().map(|(id, _, _)| *id).collect();
        assert_eq!(ids, [3, 7, 9]);
        assert_eq!(snap.to_device[1].2.get(), r#"{"n":7}"#, "repeat id ignored");

        s.remove_to_device(&[3, 7]).await.unwrap();
        s.remove_to_device(&[]).await.unwrap();
        let snap = s.load_e2ee().await.unwrap();
        assert_eq!(snap.to_device.len(), 1);
        assert_eq!(snap.to_device[0].1, "@b:x");
    }
}
