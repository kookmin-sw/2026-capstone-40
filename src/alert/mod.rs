mod flow;
mod ip;

use std::sync::{mpsc::Receiver, Arc, Mutex};

use crate::capture::CaptureEvent;
use crate::config::Config;
use crate::prefilter::LabelMap;
use crate::probe::{baseline, suspect};
use crate::resolver::{LookupConfig, PassiveDnsCache, DEFAULT_DNS_CACHE};
use crate::store::Db;

pub fn spawn_workers(
    rx: Receiver<CaptureEvent>,
    db: Db,
    config: &Config,
    passive_dns: PassiveDnsCache,
    labels: Option<LabelMap>,
) {
    let n = (config.api.workers as usize).max(1);
    let rx = Arc::new(Mutex::new(rx));

    let lookup_cfg = Arc::new(LookupConfig {
        sources: config.ip_to_domain.sources.clone(),
        verify: config.ip_to_domain.verify_doh,
        timeout_s: config.probe.timeout_s,
        cache_path: config.ip_to_domain.cache_path.clone()
            .unwrap_or_else(|| DEFAULT_DNS_CACHE.into()),
        cache_ttl_days: config.ip_to_domain.cache_ttl_days,
        passive_dns: Some(passive_dns),
        skip_domain_suffixes: config.prefilter.skip_domain_suffixes.clone(),
        probe_cache_secs: (config.probe.cache_days * 86400) as i64,
    });

    if let Some(lm) = labels {
        baseline::spawn(lm, db.clone(), 7);
    }

    let probe_cache_secs = (config.probe.cache_days * 86400) as i64;
    let probe_tx = Arc::new(suspect::spawn(db.clone(), config.filter.probe_threshold, probe_cache_secs));

    for _ in 0..n {
        let rx         = Arc::clone(&rx);
        let db         = db.clone();
        let lookup_cfg = Arc::clone(&lookup_cfg);
        let probe_tx   = Arc::clone(&probe_tx);

        std::thread::spawn(move || {
            loop {
                let evt = match rx.lock().unwrap().recv() {
                    Ok(e)  => e,
                    Err(_) => break,
                };
                match evt {
                    CaptureEvent::Ip(ip_addr) => ip::handle(ip_addr, &db, &lookup_cfg),
                    CaptureEvent::Flow(_, out) => flow::handle(out, &db, &lookup_cfg, &probe_tx),
                }
            }
            log::info!("worker exiting");
        });
    }
}
