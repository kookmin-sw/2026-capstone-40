mod alerts;
mod domains;
mod snapshots;
mod stats;
mod types;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, Result, params};

use crate::paths::expand_tilde;

pub use alerts::{ack_alert, all_alerts, domain_alerts, insert_alert, recent_alerts, severity_counts};
pub use domains::{
    all_domains, domain_detail, domain_ip_history, domain_risk, recent_domains,
    stats, update_domain_risk, upsert_domain,
};
pub use snapshots::{get_fingerprints, record_probe_run, save_fingerprint};
pub use stats::{
    inc_filter_decision, inc_traffic_alerts, inc_traffic_domains, inc_traffic_ips,
    pipeline_status, prefilter_stats, traffic_data,
};
pub use types::{
    Alert, Domain, Pipeline, PrefilterStats, Stats, StoredFingerprint, TrafficData,
};

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
            h1_text        TEXT,
            has_login_form INTEGER NOT NULL DEFAULT 0,
            redirect_depth INTEGER NOT NULL DEFAULT 0,
            html_hash      TEXT,
            simhash_text   INTEGER
        );
        CREATE TABLE IF NOT EXISTS pipeline_stats (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            total_skip    INTEGER NOT NULL DEFAULT 0,
            total_watch   INTEGER NOT NULL DEFAULT 0,
            total_probe   INTEGER NOT NULL DEFAULT 0,
            queue_depth   INTEGER NOT NULL DEFAULT 0,
            last_probe_ts INTEGER
        );
        CREATE TABLE IF NOT EXISTS traffic_buckets (
            minute  INTEGER PRIMARY KEY,
            ips     INTEGER NOT NULL DEFAULT 0,
            alerts  INTEGER NOT NULL DEFAULT 0,
            domains INTEGER NOT NULL DEFAULT 0,
            probes  INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO pipeline_stats (id) VALUES (1);

        CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_domain ON alerts(domain);
        CREATE INDEX IF NOT EXISTS idx_domain_ips_domain ON domain_ips(domain_id);
        CREATE INDEX IF NOT EXISTS idx_snapshots_domain ON snapshots(domain_id, ts DESC);
    ")?;
    // Non-destructive migrations for columns added after initial deploy.
    conn.execute("ALTER TABLE snapshots ADD COLUMN simhash_text INTEGER", []).ok();
    conn.execute("ALTER TABLE snapshots ADD COLUMN h1_text TEXT", []).ok();
    Ok(())
}

// ── shared primitive: traffic time-series bucket ──────────────────────────────
// Called from alerts.rs, snapshots.rs, stats.rs via super::inc_bucket.

pub(super) fn inc_bucket(
    conn: &Connection,
    ts: i64,
    ips: i64,
    alerts: i64,
    domains: i64,
    probes: i64,
) -> Result<()> {
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
