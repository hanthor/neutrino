//! `SessionStore` impl on [`crate::SqliteStore`]: the multi-user shim's
//! access tokens, so a restart does not sign every client out.

use async_trait::async_trait;
use deadpool_sqlite::rusqlite::params;
use neutrino_store::{SessionStore, StorageError};

use crate::{SqliteStore, error::Error};

#[async_trait]
impl SessionStore for SqliteStore {
    async fn load_sessions(&self) -> Result<Vec<(String, String, String)>, StorageError> {
        self.run_read(move |conn| -> Result<Vec<_>, Error> {
            let mut stmt = conn.prepare("SELECT token, user, device FROM sessions")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            Ok(out)
        })
        .await
    }

    async fn put_session(&self, token: &str, user: &str, device: &str) -> Result<(), StorageError> {
        let (token, user, device) = (token.to_owned(), user.to_owned(), device.to_owned());
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT OR IGNORE INTO sessions (token, user, device) VALUES (?, ?, ?)",
                params![token, user, device],
            )?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sessions_round_trip_and_keep_the_first() {
        let tmp = tempfile::TempDir::new().unwrap();
        let s = SqliteStore::open(tmp.path().join("store.sqlite"))
            .await
            .unwrap();
        s.put_session("syt_a", "@a:x", "PHONE").await.unwrap();
        s.put_session("syt_a", "@a:x", "LAPTOP").await.unwrap();
        s.put_session("syt_b", "@b:x", "*").await.unwrap();
        let mut rows = s.load_sessions().await.unwrap();
        rows.sort();
        assert_eq!(
            rows,
            vec![
                ("syt_a".to_owned(), "@a:x".to_owned(), "PHONE".to_owned()),
                ("syt_b".to_owned(), "@b:x".to_owned(), "*".to_owned()),
            ]
        );
    }
}
