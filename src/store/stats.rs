use std::collections::HashMap;

use rusqlite::{Connection, Result, params};

use crate::time::now_secs;

use super::types::{Pipeline, PrefilterStats, TrafficData};

pub fn prefilter_stats(conn: &Connection) -> PrefilterStats {
    let q = |t: &str| -> u64 {
        conn.query_row("SELECT COUNT(*) FROM alerts WHERE alert_type=?1", [t], |r| r.get::<_, i64>(0))
            .unwrap_or(0).max(0) as u64
    };
    PrefilterStats {
        malicious:  q("PREFILTER_MALICIOUS"),
        unknown:    q("PREFILTER_UNKNOWN"),
        classified: q("PREFILTER_CLASSIFIED"),
    }
}

pub fn severity_counts(conn: &Connection) -> Vec<(u8, u64)> {
    super::alerts::severity_counts(conn)
}

pub fn pipeline_status(conn: &Connection) -> Pipeline {
    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(0);
    let page_size:  i64 = conn.query_row("PRAGMA page_size",  [], |r| r.get(0)).unwrap_or(4096);
    let db_size_kb = ((page_count * page_size) / 1024) as u64;

    conn.query_row(
        "SELECT total_skip,total_watch,total_probe,queue_depth,last_probe_ts
         FROM pipeline_stats WHERE id=1",
        [],
        |r| Ok(Pipeline {
            total_skip:    r.get::<_, i64>(0)? as u64,
            total_watch:   r.get::<_, i64>(1)? as u64,
            total_probe:   r.get::<_, i64>(2)? as u64,
            queue_depth:   r.get::<_, i64>(3)? as u64,
            last_probe_ts: r.get(4)?,
            db_size_kb,
        }),
    )
    .unwrap_or(Pipeline {
        total_skip: 0, total_watch: 0, total_probe: 0,
        queue_depth: 0, last_probe_ts: None, db_size_kb,
    })
}

pub fn inc_filter_decision(conn: &Connection, decision: &str) -> Result<()> {
    let col = match decision {
        "skip"  => "total_skip",
        "watch" => "total_watch",
        "probe" => "total_probe",
        _       => return Ok(()),
    };
    conn.execute(&format!("UPDATE pipeline_stats SET {col}={col}+1 WHERE id=1"), [])?;
    Ok(())
}

pub fn inc_traffic_ips(conn: &Connection, ts: i64, n: i64) -> Result<()> {
    super::inc_bucket(conn, ts, n, 0, 0, 0)
}

pub fn inc_traffic_domains(conn: &Connection, ts: i64, n: i64) -> Result<()> {
    super::inc_bucket(conn, ts, 0, 0, n, 0)
}

pub fn inc_traffic_alerts(conn: &Connection, ts: i64, n: i64) -> Result<()> {
    super::inc_bucket(conn, ts, 0, n, 0, 0)
}

pub fn traffic_data(conn: &Connection, minutes: usize) -> TrafficData {
    let now     = now_secs();
    let cutoff  = now - (minutes as i64 * 60);
    let current = now - (now % 60);

    let mut stmt = match conn.prepare(
        "SELECT minute,ips,alerts,domains,probes FROM traffic_buckets WHERE minute>=?1",
    ) {
        Ok(s)  => s,
        Err(_) => return TrafficData { ips: vec![0; minutes], alerts: vec![0; minutes], domains: vec![0; minutes], probes: vec![0; minutes] },
    };

    let buckets: HashMap<i64, (u64, u64, u64, u64)> =
        stmt.query_map([cutoff], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64, r.get::<_, i64>(3)? as u64,
                r.get::<_, i64>(4)? as u64))
        })
        .ok()
        .map(|rows| rows.filter_map(|r| r.ok()).map(|(m, i, a, d, p)| (m, (i, a, d, p))).collect())
        .unwrap_or_default();

    let mut ips = Vec::with_capacity(minutes);
    let mut alerts = Vec::with_capacity(minutes);
    let mut domains = Vec::with_capacity(minutes);
    let mut probes = Vec::with_capacity(minutes);

    for i in (0..minutes as i64).rev() {
        let minute = current - (i * 60);
        let (ip, al, do_, pr) = buckets.get(&minute).copied().unwrap_or((0, 0, 0, 0));
        ips.push(ip); alerts.push(al); domains.push(do_); probes.push(pr);
    }

    TrafficData { ips, alerts, domains, probes }
}
