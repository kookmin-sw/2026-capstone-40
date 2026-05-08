use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, Result, params};

use crate::paths::expand_tilde;
use crate::time::now_secs;

pub type Db = Arc<Mutex<Connection>>;

// ── open / init ───────────────────────────────────────────────────────────────

pub fn open(path: &str) -> Result<Db, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(path);
    if let Some(parent) = Path::new(&expanded).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&expanded)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         PRAGMA synchronous=NORMAL;",
    )?;
    init_schema(&conn)?;
    log::info!("opened {expanded}");
    Ok(Arc::new(Mutex::new(conn)))
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS domains (
            id          INTEGER PRIMARY KEY,
            domain      TEXT    NOT NULL UNIQUE,
            risk_score  INTEGER,
            decision    TEXT,
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS domain_ips (
            domain_id   INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            ip          TEXT    NOT NULL,
            first_seen  INTEGER NOT NULL,
            last_seen   INTEGER NOT NULL,
            PRIMARY KEY (domain_id, ip)
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY,
            domain       TEXT    NOT NULL,
            severity     INTEGER NOT NULL,
            alert_type   TEXT    NOT NULL,
            detail       TEXT,
            ts           INTEGER NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS probe_runs (
            id      INTEGER PRIMARY KEY,
            domain  TEXT    NOT NULL,
            ts      INTEGER NOT NULL,
            success INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS snapshots (
            id             INTEGER PRIMARY KEY,
            domain_id      INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
            ts             INTEGER NOT NULL,
            status_code    INTEGER,
            title          TEXT,
            has_login_form INTEGER NOT NULL DEFAULT 0,
            redirect_depth INTEGER NOT NULL DEFAULT 0,
            html_hash      TEXT
        );
        CREATE TABLE IF NOT EXISTS pipeline_stats (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            total_skip    INTEGER NOT NULL DEFAULT 0,
            total_watch   INTEGER NOT NULL DEFAULT 0,
            total_probe   INTEGER NOT NULL DEFAULT 0,
            queue_depth   INTEGER NOT NULL DEFAULT 0,
            last_probe_ts INTEGER
        );
        INSERT OR IGNORE INTO pipeline_stats (id) VALUES (1);
        CREATE TABLE IF NOT EXISTS traffic_buckets (
            minute  INTEGER NOT NULL PRIMARY KEY,
            ips     INTEGER NOT NULL DEFAULT 0,
            alerts  INTEGER NOT NULL DEFAULT 0,
            domains INTEGER NOT NULL DEFAULT 0,
            probes  INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
        CREATE INDEX IF NOT EXISTS idx_domains_last  ON domains(last_seen DESC);
    ")
}

// ── query result types ────────────────────────────────────────────────────────

pub struct Stats {
    pub total_domains: u64,
    pub active_alerts: u64,
    pub ips_captured:  u64,
    pub probes_run:    u64,
}

pub struct Alert {
    pub id:           i64,
    pub severity:     u8,
    pub alert_type:   String,
    pub domain:       String,
    pub detail:       Option<String>,
    pub ts:           i64,
    pub acknowledged: bool,
}

pub struct Domain {
    pub domain:      String,
    pub risk_score:  Option<u32>,
    pub decision:    Option<String>,
    pub ips:         Vec<String>,
    pub last_seen:   i64,
    pub alert_count: u32,
}

pub struct Pipeline {
    pub total_skip:    u64,
    pub total_watch:   u64,
    pub total_probe:   u64,
    pub queue_depth:   u64,
    pub last_probe_ts: Option<i64>,
    pub db_size_kb:    u64,
}

// ── read queries ──────────────────────────────────────────────────────────────

pub fn stats(conn: &Connection) -> Stats {
    let q = |sql: &str| -> u64 {
        conn.query_row(sql, [], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            .max(0) as u64
    };
    Stats {
        total_domains: q("SELECT COUNT(*) FROM domains"),
        active_alerts: q("SELECT COUNT(*) FROM alerts WHERE acknowledged=0"),
        ips_captured:  q("SELECT COUNT(DISTINCT ip) FROM domain_ips"),
        probes_run:    q("SELECT COUNT(*) FROM probe_runs"),
    }
}

pub fn recent_alerts(conn: &Connection, limit: usize) -> Vec<Alert> {
    let mut stmt = match conn.prepare(
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts ORDER BY ts DESC LIMIT ?1",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([limit as i64], |r| {
        Ok(Alert {
            id:           r.get(0)?,
            severity:     r.get::<_, i64>(1)? as u8,
            alert_type:   r.get(2)?,
            domain:       r.get(3)?,
            detail:       r.get(4)?,
            ts:           r.get(5)?,
            acknowledged: r.get::<_, i64>(6)? != 0,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

pub fn all_alerts(conn: &Connection, include_acked: bool) -> Vec<Alert> {
    let sql = if include_acked {
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts ORDER BY ts DESC"
    } else {
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts WHERE acknowledged=0 ORDER BY ts DESC"
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([], |r| {
        Ok(Alert {
            id:           r.get(0)?,
            severity:     r.get::<_, i64>(1)? as u8,
            alert_type:   r.get(2)?,
            domain:       r.get(3)?,
            detail:       r.get(4)?,
            ts:           r.get(5)?,
            acknowledged: r.get::<_, i64>(6)? != 0,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

pub fn recent_domains(conn: &Connection, limit: usize) -> Vec<Domain> {
    query_domains(conn, Some(limit))
}

pub fn all_domains(conn: &Connection) -> Vec<Domain> {
    query_domains(conn, None)
}

/// Single-query domain list with correlated subqueries — avoids N+1.
fn query_domains(conn: &Connection, limit: Option<usize>) -> Vec<Domain> {
    let sql = "SELECT d.domain, d.risk_score, d.decision, d.last_seen,
                      COALESCE((SELECT COUNT(*) FROM alerts
                                WHERE domain=d.domain AND acknowledged=0), 0) AS alert_count,
                      COALESCE((SELECT GROUP_CONCAT(ip, ',') FROM (
                          SELECT ip FROM domain_ips
                          WHERE domain_id=d.id ORDER BY last_seen DESC LIMIT 5
                      )), '') AS ips_csv
               FROM domains d
               ORDER BY d.last_seen DESC";

    let limited = if limit.is_some() {
        format!("{sql} LIMIT ?1")
    } else {
        sql.to_owned()
    };

    let mut stmt = match conn.prepare(&limited) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };

    let map_row = |r: &rusqlite::Row| -> rusqlite::Result<Domain> {
        let ips_csv: String = r.get(5)?;
        let ips = if ips_csv.is_empty() {
            vec![]
        } else {
            ips_csv.split(',').map(String::from).collect()
        };
        Ok(Domain {
            domain:      r.get(0)?,
            risk_score:  r.get::<_, Option<i64>>(1)?.map(|s| s as u32),
            decision:    r.get(2)?,
            last_seen:   r.get(3)?,
            alert_count: r.get::<_, i64>(4)? as u32,
            ips,
        })
    };

    match limit {
        Some(n) => match stmt.query_map([n as i64], map_row) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_)   => vec![],
        },
        None => match stmt.query_map([], map_row) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_)   => vec![],
        },
    }
}

// kept for domain detail page (returns first_seen + last_seen, not needed by list views)
fn domain_ips_for(conn: &Connection, domain_id: i64) -> Vec<String> {
    let mut stmt = match conn.prepare(
        "SELECT ip FROM domain_ips WHERE domain_id=?1 ORDER BY last_seen DESC LIMIT 5",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([domain_id], |r| r.get::<_, String>(0)) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

pub fn severity_counts(conn: &Connection) -> Vec<(u8, u64)> {
    let mut stmt = match conn.prepare(
        "SELECT severity, COUNT(*) FROM alerts WHERE acknowledged=0 GROUP BY severity",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([], |r| Ok((r.get::<_, i64>(0)? as u8, r.get::<_, i64>(1)? as u64))) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

pub fn pipeline_status(conn: &Connection) -> Pipeline {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(0);
    let page_size:  i64 = conn.query_row("PRAGMA page_size",  [], |r| r.get(0)).unwrap_or(4096);
    let db_size_kb = ((page_count * page_size) / 1024) as u64;

    conn.query_row(
        "SELECT total_skip,total_watch,total_probe,queue_depth,last_probe_ts
         FROM pipeline_stats WHERE id=1",
        [],
        |r| {
            Ok(Pipeline {
                total_skip:    r.get::<_, i64>(0)? as u64,
                total_watch:   r.get::<_, i64>(1)? as u64,
                total_probe:   r.get::<_, i64>(2)? as u64,
                queue_depth:   r.get::<_, i64>(3)? as u64,
                last_probe_ts: r.get(4)?,
                db_size_kb,
            })
        },
    )
    .unwrap_or(Pipeline {
        total_skip: 0, total_watch: 0, total_probe: 0,
        queue_depth: 0, last_probe_ts: None, db_size_kb,
    })
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
    let id: i64 = match conn.query_row(
        "SELECT id FROM domains WHERE domain=?1", [domain], |r| r.get(0),
    ) {
        Ok(i)  => i,
        Err(_) => return vec![],
    };
    let mut stmt = match conn.prepare(
        "SELECT ip, first_seen, last_seen FROM domain_ips WHERE domain_id=?1 ORDER BY last_seen DESC",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

pub fn domain_alerts(conn: &Connection, domain: &str) -> Vec<Alert> {
    let mut stmt = match conn.prepare(
        "SELECT id,severity,alert_type,domain,detail,ts,acknowledged
         FROM alerts WHERE domain=?1 ORDER BY ts DESC",
    ) {
        Ok(s)  => s,
        Err(_) => return vec![],
    };
    match stmt.query_map([domain], |r| {
        Ok(Alert {
            id:           r.get(0)?,
            severity:     r.get::<_, i64>(1)? as u8,
            alert_type:   r.get(2)?,
            domain:       r.get(3)?,
            detail:       r.get(4)?,
            ts:           r.get(5)?,
            acknowledged: r.get::<_, i64>(6)? != 0,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_)   => vec![],
    }
}

// ── write operations ──────────────────────────────────────────────────────────

pub fn upsert_domain(conn: &Connection, domain: &str, ip: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO domains (domain, first_seen, last_seen) VALUES (?1,?2,?2)
         ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen",
        params![domain, now],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM domains WHERE domain=?1", [domain], |r| r.get(0),
    )?;
    conn.execute(
        "INSERT INTO domain_ips (domain_id, ip, first_seen, last_seen) VALUES (?1,?2,?3,?3)
         ON CONFLICT(domain_id, ip) DO UPDATE SET last_seen=excluded.last_seen",
        params![id, ip, now],
    )?;
    Ok(())
}

#[allow(dead_code)] // Phase 3
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
    inc_bucket(conn, ts, 0, 1, 0, 0).ok();
    Ok(conn.last_insert_rowid())
}

pub fn ack_alert(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?1", [id])?;
    Ok(())
}

#[allow(dead_code)] // Phase 3
pub fn update_domain_risk(conn: &Connection, domain: &str, risk_score: u32, decision: &str) -> Result<()> {
    conn.execute(
        "UPDATE domains SET risk_score=?1, decision=?2 WHERE domain=?3",
        params![risk_score, decision, domain],
    )?;
    Ok(())
}

#[allow(dead_code)] // Phase 2
pub fn record_probe_run(conn: &Connection, domain: &str, ts: i64, success: bool) -> Result<()> {
    conn.execute(
        "INSERT INTO probe_runs (domain,ts,success) VALUES (?1,?2,?3)",
        params![domain, ts, success as i64],
    )?;
    conn.execute(
        "UPDATE pipeline_stats SET total_probe=total_probe+1, last_probe_ts=?1 WHERE id=1",
        [ts],
    )?;
    inc_bucket(conn, ts, 0, 0, 0, 1).ok();
    Ok(())
}

#[allow(dead_code)] // Phase 3
pub fn inc_filter_decision(conn: &Connection, decision: &str) -> Result<()> {
    let col = match decision {
        "skip"  => "total_skip",
        "watch" => "total_watch",
        "probe" => "total_probe",
        _       => return Ok(()),
    };
    conn.execute(
        &format!("UPDATE pipeline_stats SET {col}={col}+1 WHERE id=1"),
        [],
    )?;
    Ok(())
}

// ── traffic time-series ───────────────────────────────────────────────────────

/// Per-minute bucket counts for the last `minutes` minutes, oldest → newest.
pub struct TrafficData {
    pub ips:     Vec<u64>,
    pub alerts:  Vec<u64>,
    pub domains: Vec<u64>,
    pub probes:  Vec<u64>,
}

/// Called by pipeline worker per IP processed.
pub fn inc_traffic_ips(conn: &Connection, ts: i64, n: i64) -> Result<()> {
    inc_bucket(conn, ts, n, 0, 0, 0)
}

/// Called by pipeline worker per domain resolved.
pub fn inc_traffic_domains(conn: &Connection, ts: i64, n: i64) -> Result<()> {
    inc_bucket(conn, ts, 0, 0, n, 0)
}

fn inc_bucket(conn: &Connection, ts: i64, ips: i64, alerts: i64, domains: i64, probes: i64) -> Result<()> {
    let minute = ts - (ts % 60);
    conn.execute(
        "INSERT INTO traffic_buckets (minute,ips,alerts,domains,probes) VALUES (?1,?2,?3,?4,?5)
         ON CONFLICT(minute) DO UPDATE SET
           ips=ips+excluded.ips,
           alerts=alerts+excluded.alerts,
           domains=domains+excluded.domains,
           probes=probes+excluded.probes",
        params![minute, ips, alerts, domains, probes],
    )?;
    Ok(())
}

pub fn traffic_data(conn: &Connection, minutes: usize) -> TrafficData {
    use std::collections::HashMap;
    let now = now_secs();
    let cutoff = now - (minutes as i64 * 60);
    let current_minute = now - (now % 60);

    let mut stmt = match conn.prepare(
        "SELECT minute,ips,alerts,domains,probes FROM traffic_buckets WHERE minute>=?1",
    ) {
        Ok(s)  => s,
        Err(_) => return TrafficData { ips: vec![0; minutes], alerts: vec![0; minutes], domains: vec![0; minutes], probes: vec![0; minutes] },
    };

    let buckets: HashMap<i64, (u64, u64, u64, u64)> =
        match stmt.query_map([cutoff], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
                r.get::<_, i64>(4)? as u64,
            ))
        }) {
            Ok(rows) => rows
                .filter_map(|r| r.ok())
                .map(|(m, i, a, d, p)| (m, (i, a, d, p)))
                .collect(),
            Err(_) => HashMap::new(),
        };

    let mut ips     = Vec::with_capacity(minutes);
    let mut alerts  = Vec::with_capacity(minutes);
    let mut domains = Vec::with_capacity(minutes);
    let mut probes  = Vec::with_capacity(minutes);

    for i in (0..minutes as i64).rev() {
        let minute = current_minute - (i * 60);
        let (ip, al, do_, pr) = buckets.get(&minute).copied().unwrap_or((0, 0, 0, 0));
        ips.push(ip); alerts.push(al); domains.push(do_); probes.push(pr);
    }

    TrafficData { ips, alerts, domains, probes }
}

