//! Background prober for suspicious domains.
//!
//! Two trigger paths:
//!   1. Immediate: flow.rs sends a domain via channel when inline probe fails.
//!      Worker deduplicates and probes right away.
//!   2. Periodic (5 min): scans DB for high-risk domains with no recent snapshot
//!      in case something was missed.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::store::{self, Db};
use crate::time::now_secs;

use super::probe;

const PERIODIC_INTERVAL: Duration = Duration::from_secs(300);
const FAIL_COOLDOWN: Duration = Duration::from_secs(300); // 5 min before retrying a failed domain

/// Returns a sender that callers use to trigger immediate probing.
pub fn spawn(db: Db, probe_threshold: u32, cache_secs: i64) -> Sender<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::Builder::new()
        .name("suspect-prober".into())
        .spawn(move || run(rx, db, probe_threshold, cache_secs))
        .ok();
    tx
}

fn run(rx: Receiver<String>, db: Db, probe_threshold: u32, cache_secs: i64) {
    let mut last_periodic = Instant::now();
    let mut pending: HashSet<String> = HashSet::new();
    // Domain → time of last failed probe attempt (for backoff)
    let mut fail_cooldown: HashMap<String, Instant> = HashMap::new();

    loop {
        // Drain channel — collect immediate requests.
        loop {
            match rx.try_recv() {
                Ok(domain) => { pending.insert(domain); }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // Periodic DB scan — add any missed high-risk domains.
        if last_periodic.elapsed() >= PERIODIC_INTERVAL {
            last_periodic = Instant::now();
            let now = now_secs();
            let conn = match db.lock() { Ok(c) => c, Err(_) => { std::thread::sleep(Duration::from_secs(1)); continue } };
            let missed = store::domains_needing_probe(&conn, probe_threshold, cache_secs, now);
            drop(conn);
            for d in missed { pending.insert(d); }
        }

        if pending.is_empty() {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }

        let batch: Vec<String> = pending.drain().collect();
        for domain in &batch {
            // Skip if still in fail cooldown.
            if let Some(&t) = fail_cooldown.get(domain.as_str()) {
                if t.elapsed() < FAIL_COOLDOWN {
                    log::debug!("suspect-prober: skip {domain} (fail cooldown)");
                    continue;
                }
                fail_cooldown.remove(domain.as_str());
            }
            // Skip if cache is still fresh.
            if !cache_stale(domain, &db, cache_secs) {
                log::debug!("suspect-prober: skip {domain} (cache fresh)");
                continue;
            }

            log::info!("suspect-prober: probing {domain}");
            let before = {
                let conn = db.lock().ok();
                conn.and_then(|c| store::snapshot_count(&c, domain).into()).unwrap_or(0usize)
            };
            probe::probe_baseline(domain, &db, now_secs());
            let after = {
                let conn = db.lock().ok();
                conn.and_then(|c| store::snapshot_count(&c, domain).into()).unwrap_or(0usize)
            };
            // If snapshot count didn't increase, probe failed → start cooldown.
            if after <= before {
                log::warn!("suspect-prober: {domain} probe failed, cooling down {}s", FAIL_COOLDOWN.as_secs());
                fail_cooldown.insert(domain.clone(), Instant::now());
            }
        }
    }
}

fn cache_stale(domain: &str, db: &Db, cache_secs: i64) -> bool {
    let conn = match db.lock() { Ok(c) => c, Err(_) => return true };
    match store::last_probe_ts(&conn, domain) {
        Some(ts) => now_secs() - ts >= cache_secs,
        None     => store::snapshot_count(&conn, domain) == 0,
    }
}
