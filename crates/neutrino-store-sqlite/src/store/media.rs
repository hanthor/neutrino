//! `MediaStore` impl on [`crate::SqliteStore`]: the content repository as
//! one table of blobs. Uploads are capped small (a mesh hop is a BLE link),
//! so keeping them in the database — one file to back up, one directory to
//! wipe — beats a second store on disk.

use async_trait::async_trait;
use deadpool_sqlite::rusqlite::{OptionalExtension, params};
use neutrino_store::{MediaStore, StorageError, StoredMedia};

use crate::{SqliteStore, error::Error};

#[async_trait]
impl MediaStore for SqliteStore {
    async fn put_media(
        &self,
        origin: &str,
        media_id: &str,
        uploader: &str,
        media: &StoredMedia,
    ) -> Result<(), StorageError> {
        let (origin, media_id, uploader) =
            (origin.to_owned(), media_id.to_owned(), uploader.to_owned());
        let (content_type, filename, bytes) = (
            media.content_type.clone(),
            media.filename.clone(),
            media.bytes.clone(),
        );
        self.run_write(move |conn| -> Result<(), Error> {
            conn.execute(
                "INSERT OR IGNORE INTO media \
                 (origin, media_id, uploader, content_type, filename, bytes) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![origin, media_id, uploader, content_type, filename, bytes],
            )?;
            Ok(())
        })
        .await
    }

    async fn get_media(
        &self,
        origin: &str,
        media_id: &str,
    ) -> Result<Option<StoredMedia>, StorageError> {
        let (origin, media_id) = (origin.to_owned(), media_id.to_owned());
        self.run_read(move |conn| -> Result<Option<StoredMedia>, Error> {
            let row = conn
                .query_row(
                    "SELECT content_type, filename, bytes FROM media \
                     WHERE origin = ? AND media_id = ?",
                    params![origin, media_id],
                    |row| {
                        Ok(StoredMedia {
                            content_type: row.get(0)?,
                            filename: row.get(1)?,
                            bytes: row.get(2)?,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn media_round_trips_and_keeps_the_first_under_an_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let s = SqliteStore::open(tmp.path().join("store.sqlite"))
            .await
            .unwrap();
        let png = StoredMedia {
            content_type: "image/png".to_owned(),
            filename: Some("a.png".to_owned()),
            bytes: vec![0x89, b'P', b'N', b'G'],
        };
        s.put_media("x", "m1", "@a:x", &png).await.unwrap();
        let other = StoredMedia {
            content_type: "text/plain".to_owned(),
            filename: None,
            bytes: b"nope".to_vec(),
        };
        s.put_media("x", "m1", "@a:x", &other).await.unwrap();
        assert_eq!(s.get_media("x", "m1").await.unwrap(), Some(png));
        assert_eq!(s.get_media("x", "m2").await.unwrap(), None);
        assert_eq!(
            s.get_media("y", "m1").await.unwrap(),
            None,
            "keyed by origin too"
        );
    }
}
