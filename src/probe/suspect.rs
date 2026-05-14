//! Background prober for suspicious domains.
//!
//! Two trigger paths:
//!   1. Immediate: flow.rs sends a domain via channel when inline probe fails.
//!      Worker deduplicates and probes right away.
//!   2. Periodic (5 min): scans DB for high-risk domains with no recent snapshot
//!      in case something was missed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crate::store::{self, Db};
use crate::time::now_secs;

use super::probe_baseline;

const PERIODIC_INTERVAL: Duration = Duration::from_secs(300);
const FAIL_COOLDOWN: Duration = Duration::from_secs(300);

/// Message sent to the suspect prober. Priority=true puts domain at front of queue.
pub struct ProbeMsg {
    pub domain: String,
    pub priority: bool,
}

impl From<String> for ProbeMsg {
    fn from(s: String) -> Self {
        Self {
            domain: s,
            priority: false,
        }
    }
}

/// Returns a sender that callers use to trigger immediate probing.
pub fn spawn(db: Db, probe_threshold: u32, cache_secs: i64) -> Sender<ProbeMsg> {
    let (tx, rx) = mpsc::channel::<ProbeMsg>();
    std::thread::Builder::new()
        .name("suspect-prober".into())
        .spawn(move || run(rx, db, probe_threshold, cache_secs))
        .ok();
    tx
}

fn run(rx: Receiver<ProbeMsg>, db: Db, probe_threshold: u32, cache_secs: i64) {
    let mut last_periodic = Instant::now();
    // Two-tier queue: priority (front) and normal (back).
    // Priority items (class-relevant CDN domains) always probe before junk EC2/CDN.
    let mut hi_queue: VecDeque<String> = VecDeque::new();
    let mut lo_queue: VecDeque<String> = VecDeque::new();
    let mut pending_set: HashSet<String> = HashSet::new();
    let mut fail_cooldown: HashMap<String, Instant> = HashMap::new();

    loop {
        // Drain channel into appropriate tier.
        loop {
            match rx.try_recv() {
                Ok(msg) => {
                    if pending_set.insert(msg.domain.clone()) {
                        if msg.priority {
                            hi_queue.push_back(msg.domain);
                        } else {
                            lo_queue.push_back(msg.domain);
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        // Periodic DB scan — add any missed high-risk domains.
        if last_periodic.elapsed() >= PERIODIC_INTERVAL {
            last_periodic = Instant::now();
            let now = now_secs();
            let conn = match db.lock() {
                Ok(c) => c,
                Err(_) => {
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            let missed = store::domains_needing_probe(&conn, probe_threshold, cache_secs, now);
            drop(conn);
            for d in missed {
                if pending_set.insert(d.clone()) {
                    lo_queue.push_back(d);
                }
            }
        }

        if hi_queue.is_empty() && lo_queue.is_empty() {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }

        // Priority queue first, then normal queue.
        let domain = if let Some(d) = hi_queue.pop_front() {
            pending_set.remove(&d);
            d
        } else if let Some(d) = lo_queue.pop_front() {
            pending_set.remove(&d);
            d
        } else {
            continue;
        };

        // Skip if still in fail cooldown (domain is dropped — will be re-queued
        // by the next flow that triggers CDN probe queue for this IP).
        if let Some(&t) = fail_cooldown.get(domain.as_str()) {
            if t.elapsed() < FAIL_COOLDOWN {
                log::debug!("suspect-prober: skip {domain} (fail cooldown)");
                continue;
            }
            fail_cooldown.remove(domain.as_str());
        }
        // Skip if cache is still fresh.
        if !cache_stale(&domain, &db, cache_secs) {
            log::debug!("suspect-prober: skip {domain} (cache fresh)");
            continue;
        }

        log::info!("suspect-prober: probing {domain}");
        let before = {
            let conn = db.lock().ok();
            conn.and_then(|c| store::snapshot_count(&c, &domain).into())
                .unwrap_or(0usize)
        };
        probe_baseline(&domain, &db, now_secs(), None);
        let after = {
            let conn = db.lock().ok();
            conn.and_then(|c| store::snapshot_count(&c, &domain).into())
                .unwrap_or(0usize)
        };
        if after <= before {
            log::warn!(
                "suspect-prober: {domain} probe failed, cooling down {}s",
                FAIL_COOLDOWN.as_secs()
            );
            fail_cooldown.insert(domain, Instant::now());
        }
    }
}

fn cache_stale(domain: &str, db: &Db, cache_secs: i64) -> bool {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return true,
    };
    match store::last_probe_ts(&conn, domain) {
        Some(ts) => now_secs() - ts >= cache_secs,
        None => store::snapshot_count(&conn, domain) == 0,
    }
}
