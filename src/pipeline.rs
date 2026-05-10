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
use crate::prefilter::{PrefilterOutput, Verdict};
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
                    CaptureEvent::Flow(_key, out) => handle_flow(out, &db, &lookup_cfg),
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

fn handle_flow(out: PrefilterOutput, db: &Db, lookup_cfg: &LookupConfig) {
    let ip_str = out.server_ip.to_string();
    let now = now_secs();

    // Resolve domain for server IP — passive DNS hits first.
    let domain = match lookup(&ip_str, lookup_cfg) {
        Ok(r) if !r.domains.is_empty() => {
            let conn = db.lock().ok();
            if let Some(ref c) = conn {
                for entry in &r.domains {
                    store::upsert_domain(c, &entry.domain, &ip_str, now).ok();
                }
            }
            r.domains[0].domain.clone()
        }
        _ => ip_str.clone(), // fall back to raw IP as domain key
    };

    let (severity, alert_type, risk_delta) = match out.verdict {
        Verdict::Malicious => (4u8, "PREFILTER_MALICIOUS", 60u32),
        Verdict::Unknown   => (2u8, "PREFILTER_UNKNOWN",   15u32),
        Verdict::Known     => (1u8, "PREFILTER_CLASSIFIED", 0u32),
        Verdict::Benign    => return, // benign_skip should have dropped these
    };

    let detail = format!(
        "class={} conf={:.0}%{}",
        out.class_name,
        out.confidence * 100.0,
        if out.direction_guessed { " [dir?]" } else { "" },
    );

    log::info!(
        "prefilter {} sev={} {} → {} ({})",
        alert_type, severity, ip_str, domain, detail
    );

    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };

    store::upsert_domain(&conn, &domain, &ip_str, now).ok();

    if risk_delta > 0 {
        // Read current score, add delta, cap at 100.
        let current = store::domain_risk(&conn, &domain).unwrap_or(0);
        let new_score = (current + risk_delta).min(100);
        let decision = if new_score >= 60 { "probe" } else if new_score >= 30 { "watch" } else { "skip" };
        store::update_domain_risk(&conn, &domain, new_score, decision).ok();
    }

    store::insert_alert(&conn, &domain, severity, alert_type, Some(detail.as_str()), now).ok();
    store::inc_traffic_alerts(&conn, now, 1).ok();
}
