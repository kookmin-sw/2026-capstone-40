use rusqlite::{params, Connection};

use crate::paths::expand_tilde;

pub struct Cache {
    conn: Connection,
}

impl Cache {
    pub fn new(path: &str) -> rusqlite::Result<Self> {
        let path = expand_tilde(path);
        if let Some(p) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(p).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                provider TEXT NOT NULL,
                key      TEXT NOT NULL,
                ts       INTEGER NOT NULL,
                status   INTEGER NOT NULL,
                body     BLOB,
                PRIMARY KEY (provider, key)
            );",
        )?;
        Ok(Self { conn })
    }

    pub fn get(&self, provider: &str, key: &str) -> Option<(i64, i64, Option<Vec<u8>>)> {
        self.conn
            .query_row(
                "SELECT ts, status, body FROM cache WHERE provider=?1 AND key=?2",
                params![provider, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok()
    }

    pub fn put(&self, provider: &str, key: &str, ts: i64, status: i64, body: Option<&[u8]>) {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO cache(provider,key,ts,status,body) VALUES(?1,?2,?3,?4,?5)",
                params![provider, key, ts, status, body],
            )
            .ok();
    }
}
