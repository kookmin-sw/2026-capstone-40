use rusqlite::{params, Connection, Result};

use super::types::{Domain, Stats};

pub fn stats(conn: &Connection) -> Stats {
    let q = |sql: &str| -> u64 {
        conn.query_row(sql, [], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .max(0) as u64
    };
    Stats {
        total_domains: q("SELECT COUNT(*) FROM domains"),
        active_alerts: q("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
        ips_captured: q("SELECT COUNT(DISTINCT ip) FROM dns.domain_ips"),
        probes_run: q("SELECT COUNT(*) FROM probe_runs"),
    }
}

pub fn upsert_domain(conn: &Connection, domain: &str, ip: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO domains (domain, first_seen, last_seen) VALUES (?1,?2,?2)
         ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen",
        params![domain, now],
    )?;
    let id: i64 = conn.query_row("SELECT id FROM domains WHERE domain=?1", [domain], |r| {
        r.get(0)
    })?;
    if !ip.is_empty() {
        conn.execute(
            "INSERT INTO dns.domain_ips (domain_id, domain, ip, first_seen, last_seen)
             VALUES (?1,?2,?3,?4,?4)
             ON CONFLICT(domain, ip) DO UPDATE SET last_seen=excluded.last_seen, domain_id=excluded.domain_id",
            params![id, domain, ip, now],
        )?;
    }
    Ok(())
}

/// All domains known to resolve to `ip` via dns_cache.db domain_ips.
pub fn domains_by_ip(conn: &Connection, ip: &str) -> Vec<String> {
    let mut stmt = match conn.prepare(
        "SELECT domain FROM dns.domain_ips
         WHERE ip=?1
         ORDER BY last_seen DESC
         LIMIT 20",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map([ip], |r| r.get(0))
        .ok()
        .map(|rows| rows.filter_map(|x| x.ok()).collect())
        .unwrap_or_default()
}

/// Atomically add `delta` to risk_score (capped at `cap`), derive decision in SQL.
/// Single statement — safe under concurrent worker threads.
pub fn increment_domain_risk(conn: &Connection, domain: &str, delta: u32, cap: u32) -> Result<()> {
    conn.execute(
        "UPDATE domains
         SET risk_score = MIN(COALESCE(risk_score, 0) + ?1, ?2),
             decision   = CASE
                 WHEN MIN(COALESCE(risk_score, 0) + ?1, ?2) >= 60 THEN 'probe'
                 WHEN MIN(COALESCE(risk_score, 0) + ?1, ?2) >= 30 THEN 'watch'
                 ELSE 'skip'
             END
         WHERE domain = ?3",
        params![delta, cap, domain],
    )?;
    Ok(())
}

pub fn domain_detail(conn: &Connection, domain: &str) -> Option<(Option<u32>, Option<String>)> {
    conn.query_row(
        "SELECT risk_score, decision FROM domains WHERE domain=?1",
        [domain],
        |r| Ok((r.get::<_, Option<i64>>(0)?.map(|s| s as u32), r.get(1)?)),
    )
    .ok()
}

pub fn domain_ip_history(conn: &Connection, domain: &str) -> Vec<(String, i64, i64)> {
    let mut stmt = match conn.prepare(
        "SELECT ip, first_seen, last_seen FROM dns.domain_ips WHERE domain=?1 ORDER BY last_seen DESC",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([domain], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

pub fn recent_domains(conn: &Connection, limit: usize) -> Vec<Domain> {
    query_domains(conn, Some(limit))
}

/// Domains with risk_score >= min_score that have no snapshot newer than stale_secs.
/// These are candidates for background probing.
pub fn domains_needing_probe(
    conn: &Connection,
    min_score: u32,
    stale_secs: i64,
    now: i64,
) -> Vec<String> {
    let cutoff = now - stale_secs;
    let mut stmt = match conn.prepare(
        "SELECT d.domain FROM domains d
         WHERE d.risk_score >= ?1
           AND d.domain NOT GLOB '*.*.*.*'
           AND (
               NOT EXISTS (SELECT 1 FROM probe_runs p WHERE p.domain = d.domain AND p.ts > ?2)
           )
         ORDER BY d.risk_score DESC
         LIMIT 50",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    stmt.query_map([min_score as i64, cutoff], |r| r.get(0))
        .ok()
        .map(|rows| rows.filter_map(|x| x.ok()).collect())
        .unwrap_or_default()
}

pub fn all_domains(conn: &Connection) -> Vec<Domain> {
    query_domains(conn, None)
}

fn query_domains(conn: &Connection, limit: Option<usize>) -> Vec<Domain> {
    let sql = "SELECT d.domain, d.risk_score, d.decision, d.last_seen,
                      COALESCE((SELECT COUNT(*) FROM alerts
                                WHERE domain=d.domain AND acknowledged=0), 0) AS alert_count,
                      COALESCE((SELECT GROUP_CONCAT(ip, ',') FROM (
                          SELECT ip FROM dns.domain_ips
                          WHERE domain=d.domain ORDER BY last_seen DESC LIMIT 5
                      )), '') AS ips_csv
               FROM domains d
               ORDER BY d.last_seen DESC";

    let limited = if limit.is_some() {
        format!("{sql} LIMIT ?1")
    } else {
        sql.to_owned()
    };
    let mut stmt = match conn.prepare(&limited) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let map_row = |r: &rusqlite::Row| -> rusqlite::Result<Domain> {
        let ips_csv: String = r.get(5)?;
        Ok(Domain {
            domain: r.get(0)?,
            risk_score: r.get::<_, Option<i64>>(1)?.map(|s| s as u32),
            decision: r.get(2)?,
            last_seen: r.get(3)?,
            alert_count: r.get::<_, i64>(4)? as u32,
            ips: if ips_csv.is_empty() {
                vec![]
            } else {
                ips_csv.split(',').map(String::from).collect()
            },
        })
    };

    match limit {
        Some(n) => stmt
            .query_map([n as i64], map_row)
            .ok()
            .map(|r| r.filter_map(|x| x.ok()).collect())
            .unwrap_or_default(),
        None => stmt
            .query_map([], map_row)
            .ok()
            .map(|r| r.filter_map(|x| x.ok()).collect())
            .unwrap_or_default(),
    }
}
