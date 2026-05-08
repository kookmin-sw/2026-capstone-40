//! Worker pool: receives IPs from the capture thread, resolves domains, stores in DB.
//!
//! Spawns `config.api.workers` threads. Each thread:
//!   1. Blocks on `rx.recv()`
//!   2. Calls `ip_to_domain::lookup()`
//!   3. Upserts every resolved domain into the store
//!   4. Increments traffic buckets for charting

use std::net::IpAddr;
use std::sync::{Arc, Mutex, mpsc::Receiver};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::ip_to_domain::{LookupConfig, lookup};
use crate::store::{self, Db};

pub fn spawn_workers(rx: Receiver<IpAddr>, db: Db, config: &Config) {
    let n = (config.api.workers as usize).max(1);
    let rx = Arc::new(Mutex::new(rx));

    let lookup_cfg = Arc::new(LookupConfig {
        sources:    config.ip_to_domain.sources.clone(),
        verify:     config.ip_to_domain.verify_doh,
        timeout_s:  config.probe.timeout_s,
        cache_path: config
            .ip_to_domain
            .cache_path
            .clone()
            .unwrap_or_else(|| "~/.cache/capstone/dns_cache.sqlite3".into()),
    });

    for _ in 0..n {
        let rx        = Arc::clone(&rx);
        let db        = db.clone();
        let lookup_cfg = Arc::clone(&lookup_cfg);

        std::thread::spawn(move || {
            loop {
                let ip: IpAddr = match rx.lock().unwrap().recv() {
                    Ok(ip) => ip,
                    Err(_) => break, // capture sender dropped → shutdown
                };

                let ip_str = ip.to_string();
                let now    = now_secs();

                // Count the IP in traffic buckets
                if let Ok(conn) = db.lock() {
                    store::inc_traffic_ips(&conn, now, 1).ok();
                }

                log::debug!("lookup {ip_str}");

                match lookup(&ip_str, &lookup_cfg) {
                    Ok(result) => {
                        let conn = match db.lock() {
                            Ok(c)  => c,
                            Err(_) => continue,
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
            log::info!("worker exiting");
        });
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
