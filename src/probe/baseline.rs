//! Proactive baseline prober.
//!
//! On startup: reads typical_domains from all Malicious/Known label entries,
//! probes any domain whose last successful probe is older than `probe_interval_days`.
//! Then loops, re-checking every 6 hours so weekly probes stay fresh.
//!
//! This populates the snapshots table so that live `probe_and_compare()` calls
//! have a reference baseline to compare against instead of an empty DB.

use std::time::Duration;

use crate::prefilter::{ClassKind, LabelMap};
use crate::store::{self, Db};
use crate::time::now_secs;

use super::probe_baseline;

const RETRY_INTERVAL: Duration = Duration::from_secs(3600);      // 1h retry for no-baseline
const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 3600); // 6h check for stale

pub fn spawn(labels: LabelMap, db: Db, probe_interval_days: u64) {
    std::thread::Builder::new()
        .name("baseline-prober".into())
        .spawn(move || run(labels, db, probe_interval_days))
        .ok();
}

fn run(labels: LabelMap, db: Db, probe_interval_days: u64) {
    let stale_secs = (probe_interval_days * 86400) as i64;
    let mut last_stale_check = std::time::Instant::now();

    loop {
        let domains = collect_domains(&labels);
        let now_inst = std::time::Instant::now();
        let check_stale = now_inst.duration_since(last_stale_check) >= REFRESH_INTERVAL;

        if check_stale {
            last_stale_check = now_inst;
            log::info!("baseline: stale-check {} domains (interval={}d)", domains.len(), probe_interval_days);
        }

        let mut probed = 0u32;
        for domain in &domains {
            let needs = {
                let conn = match db.lock() { Ok(c) => c, Err(_) => continue };
                let count = store::snapshot_count(&conn, domain);
                if count == 0 {
                    true // always retry no-baseline domains
                } else if check_stale {
                    match store::last_probe_ts(&conn, domain) {
                        None => false,
                        Some(last) => now_secs() - last >= stale_secs,
                    }
                } else {
                    false
                }
            };

            if needs {
                log::info!("baseline: probing {domain}");
                let now = now_secs();
                if let Ok(conn) = db.lock() {
                    store::upsert_domain(&conn, domain, "", now).ok();
                }
                probe_baseline(domain, &db, now, None);
                probed += 1;
            }
        }

        if probed > 0 {
            log::info!("baseline: probed {probed} domain(s)");
        }

        std::thread::sleep(RETRY_INTERVAL);
    }
}

/// Collect unique domain names from typical_domains of Malicious + Known entries.
fn collect_domains(labels: &LabelMap) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for entry in &labels.entries {
        if matches!(entry.kind, ClassKind::Malicious | ClassKind::Known) {
            for d in &entry.typical_domains {
                if !d.is_empty() && seen.insert(d.clone()) {
                    out.push(d.clone());
                }
            }
        }
    }
    out
}

fn should_probe(domain: &str, db: &Db, stale_secs: i64) -> bool {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return false,
    };
    // No snapshot at all → must probe regardless of probe_runs table.
    if store::snapshot_count(&conn, domain) == 0 {
        return true;
    }
    // Has snapshots: probe again only when stale (weekly refresh).
    match store::last_probe_ts(&conn, domain) {
        None => false, // snapshots exist but no probe_run record — still usable, skip
        Some(last) => now_secs() - last >= stale_secs,
    }
}
