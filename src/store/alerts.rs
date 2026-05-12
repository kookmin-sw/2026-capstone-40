use rusqlite::{Connection, Result, params};

use super::types::Alert;

fn map_alert(r: &rusqlite::Row) -> rusqlite::Result<Alert> {
    Ok(Alert {
        id:           r.get(0)?,
        severity:     r.get::<_, i64>(1)? as u8,
        alert_type:   r.get(2)?,
        domain:       r.get(3)?,
        detail:       r.get(4)?,
        ts:           r.get(5)?,
        acknowledged: r.get::<_, i64>(6)? != 0,
    })
}

pub fn recent_alerts(conn: &Connection, limit: usize) -> Vec<Alert> {
    let mut stmt = match conn.prepare(
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts ORDER BY ts DESC LIMIT ?1",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([limit as i64], map_alert)
        .ok().map(|r| r.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn all_alerts(conn: &Connection, include_acked: bool) -> Vec<Alert> {
    let sql = if include_acked {
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged FROM alerts ORDER BY ts DESC"
    } else {
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged FROM alerts WHERE acknowledged=0 ORDER BY ts DESC"
    };
    let mut stmt = match conn.prepare(sql) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([], map_alert)
        .ok().map(|r| r.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn domain_alerts(conn: &Connection, domain: &str) -> Vec<Alert> {
    let mut stmt = match conn.prepare(
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts WHERE domain=?1 ORDER BY ts DESC",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([domain], map_alert)
        .ok().map(|r| r.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn severity_counts(conn: &Connection) -> Vec<(u8, u64)> {
    let mut stmt = match conn.prepare(
        "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged=0 GROUP BY severity",
    ) { Ok(s) => s, Err(_) => return vec![] };
    stmt.query_map([], |r| Ok((r.get::<_, i64>(0)? as u8, r.get::<_, i64>(1)? as u64)))
        .ok().map(|r| r.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn insert_alert(
    conn: &Connection,
    domain: &str,
    severity: u8,
    alert_type: &str,
    detail: Option<&str>,
    ts: i64,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO alerts (domain,severity,alert_type,detail,ts) VALUES (?1,?2,?3,?4,?5)",
        params![domain, severity as i64, alert_type, detail, ts],
    )?;
    super::inc_bucket(conn, ts, 0, 1, 0, 0).ok();
    Ok(conn.last_insert_rowid())
}

/// Replay domain's alerts oldest→newest, accumulate risk score.
/// Returns (ts, score) pairs — suitable for plotting a risk trend.
pub fn domain_risk_trend(conn: &Connection, domain: &str) -> Vec<(i64, u32)> {
    let mut stmt = match conn.prepare(
        "SELECT alert_type, ts FROM alerts WHERE domain=?1 ORDER BY ts ASC",
    ) { Ok(s) => s, Err(_) => return vec![] };

    let rows: Vec<(String, i64)> = stmt
        .query_map([domain], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok()
        .map(|r| r.filter_map(|x| x.ok()).collect())
        .unwrap_or_default();

    let mut score: u32 = 0;
    let mut trend = Vec::with_capacity(rows.len() + 1);
    if !rows.is_empty() {
        trend.push((rows[0].1, 0u32)); // start at 0
    }
    for (alert_type, ts) in rows {
        let delta: u32 = match alert_type.as_str() {
            "PREFILTER_MALICIOUS"  => 60,
            "PREFILTER_CLASSIFIED" => 10,
            _ => 5,
        };
        score = (score + delta).min(100);
        trend.push((ts, score));
    }
    trend
}

pub fn ack_alert(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?1", [id])?;
    Ok(())
}
