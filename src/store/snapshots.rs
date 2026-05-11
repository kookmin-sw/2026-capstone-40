use rusqlite::{Connection, Result, params};

use super::types::StoredFingerprint;

pub fn save_fingerprint(
    conn: &Connection,
    domain: &str,
    title: Option<&str>,
    h1: Option<&str>,
    simhash: u64,
    html_hash: &str,
    ts: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO domains (domain,risk_score,decision,first_seen,last_seen)
         VALUES (?1,NULL,NULL,?2,?2)",
        params![domain, ts],
    )?;
    let domain_id: i64 = conn.query_row(
        "SELECT id FROM domains WHERE domain=?1", [domain], |r| r.get(0),
    )?;
    conn.execute(
        "INSERT INTO snapshots (domain_id,ts,title,h1_text,simhash_text,html_hash)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![domain_id, ts, title, h1, simhash as i64, html_hash],
    )?;
    Ok(())
}

pub fn get_fingerprints(conn: &Connection, domain: &str, limit: usize) -> Vec<StoredFingerprint> {
    let mut stmt = match conn.prepare(
        "SELECT s.simhash_text, s.html_hash, s.title, s.ts
         FROM snapshots s
         JOIN domains d ON d.id = s.domain_id
         WHERE d.domain=?1 AND s.simhash_text IS NOT NULL
         ORDER BY s.ts DESC LIMIT ?2",
    ) { Ok(s) => s, Err(_) => return vec![] };

    stmt.query_map(params![domain, limit as i64], |r| {
        Ok(StoredFingerprint {
            simhash:   r.get::<_, i64>(0)? as u64,
            html_hash: r.get(1).unwrap_or_default(),
            title:     r.get(2)?,
            ts:        r.get(3)?,
        })
    })
    .ok()
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

pub fn record_probe_run(conn: &Connection, domain: &str, ts: i64, success: bool) -> Result<()> {
    conn.execute(
        "INSERT INTO probe_runs (domain,ts,success) VALUES (?1,?2,?3)",
        params![domain, ts, success as i64],
    )?;
    conn.execute(
        "UPDATE pipeline_stats SET total_probe=total_probe+1, last_probe_ts=?1 WHERE id=1",
        [ts],
    )?;
    super::inc_bucket(conn, ts, 0, 0, 0, 1).ok();
    Ok(())
}
