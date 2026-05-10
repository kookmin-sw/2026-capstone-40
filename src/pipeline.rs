//! Worker pool: receives capture events, resolves domains, stores in DB.
//!
//! Spawns `config.api.workers` threads. Each thread:
//!   1. Blocks on `rx.recv()`
//!   2. For `CaptureEvent::Ip` → `ip_to_domain::lookup()` → upsert
//!   3. For `CaptureEvent::Flow` → log prefilter verdict (risk-score wiring is
//!      Phase P-4 in `prefilter.md`)

use std::net::IpAddr;
use std::sync::{mpsc::Receiver, Arc, Mutex};

use crate::capture::CaptureEvent;
use crate::config::Config;
use crate::ip_to_domain::{lookup, LookupConfig, PassiveDnsCache, DEFAULT_DNS_CACHE};
use crate::store::{self, Db};
use crate::time::now_secs;

pub fn spawn_workers(
    rx: Receiver<CaptureEvent>,
    db: Db,
    config: &Config,
    passive_dns: PassiveDnsCache,
) {
    let n = (config.api.workers as usize).max(1);
    let rx = Arc::new(Mutex::new(rx));

    let lookup_cfg = Arc::new(LookupConfig {
        sources: config.ip_to_domain.sources.clone(),
        verify: config.ip_to_domain.verify_doh,
        timeout_s: config.probe.timeout_s,
        cache_path: config
            .ip_to_domain
            .cache_path
            .clone()
            .unwrap_or_else(|| DEFAULT_DNS_CACHE.into()),
        cache_ttl_days: config.ip_to_domain.cache_ttl_days,
        passive_dns: Some(passive_dns),
    });

    for _ in 0..n {
        let rx = Arc::clone(&rx);
        let db = db.clone();
        let lookup_cfg = Arc::clone(&lookup_cfg);

        std::thread::spawn(move || {
            loop {
                let evt = match rx.lock().unwrap().recv() {
                    Ok(e) => e,
                    Err(_) => break,
                };

                match evt {
                    CaptureEvent::Ip(ip) => handle_ip(ip, &db, &lookup_cfg),
                    CaptureEvent::Flow(key, out) => {
                        log::info!(
                            "flow {:?} class={} conf={:.2} guessed_dir={} {:?}",
                            out.verdict, out.class_name, out.confidence,
                            out.direction_guessed, key
                        );
                    }
                }
            }
            log::info!("worker exiting");
        });
    }
}

fn handle_ip(ip: IpAddr, db: &Db, lookup_cfg: &LookupConfig) {
    let ip_str = ip.to_string();
    let now = now_secs();

    if let Ok(conn) = db.lock() {
        store::inc_traffic_ips(&conn, now, 1).ok();
    }

    log::debug!("lookup {ip_str}");

    match lookup(&ip_str, lookup_cfg) {
        Ok(result) => {
            let conn = match db.lock() {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut new_domains: i64 = 0;
            for entry in &result.domains {
                if store::upsert_domain(&conn, &entry.domain, &ip_str, now).is_ok() {
                    new_domains += 1;
                }
            }
            if new_domains > 0 {
                store::inc_traffic_domains(&conn, now, new_domains).ok();
            }
            if !result.domains.is_empty() {
                log::info!(
                    "{ip_str} → {} domain(s): {}",
                    result.count,
                    result.domains.iter().map(|d| d.domain.as_str()).collect::<Vec<_>>().join(", ")
                );
            }
        }
        Err(e) => log::warn!("lookup failed {ip_str}: {e}"),
    }
}
