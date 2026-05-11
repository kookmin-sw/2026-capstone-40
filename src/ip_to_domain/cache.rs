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

    pub fn clear_key(&self, key: &str) -> rusqlite::Result<usize> {
        self.conn
            .execute("DELETE FROM cache WHERE key=?1", params![key])
    }

    pub fn clear_all(&self) -> rusqlite::Result<usize> {
        self.conn.execute("DELETE FROM cache", [])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("capstone-{name}-{}.sqlite3", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn clear_key_removes_only_matching_ip() {
        let path = temp_cache_path("clear-key");
        let _ = std::fs::remove_file(&path);
        let cache = Cache::new(&path).unwrap();
        cache.put("ptr", "1.1.1.1", 1, 200, Some(b"one"));
        cache.put("ptr", "8.8.8.8", 1, 200, Some(b"eight"));

        assert_eq!(cache.clear_key("1.1.1.1").unwrap(), 1);
        assert!(cache.get("ptr", "1.1.1.1").is_none());
        assert!(cache.get("ptr", "8.8.8.8").is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn clear_all_removes_every_provider_entry() {
        let path = temp_cache_path("clear-all");
        let _ = std::fs::remove_file(&path);
        let cache = Cache::new(&path).unwrap();
        cache.put("ptr", "1.1.1.1", 1, 200, Some(b"one"));
        cache.put("hackertarget", "1.1.1.1", 1, 200, Some(b"one.example"));

        assert_eq!(cache.clear_all().unwrap(), 2);
        assert!(cache.get("ptr", "1.1.1.1").is_none());
        assert!(cache.get("hackertarget", "1.1.1.1").is_none());
        let _ = std::fs::remove_file(&path);
    }
}
