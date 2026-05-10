pub mod capture;
pub mod config;
pub mod html_fingerprint;
pub mod ip_to_domain;
pub mod logger;
pub mod paths;
pub mod pipeline;
pub mod prefilter;
pub mod store;
pub mod time;
pub mod web;
// pub mod passive_filter;  // Phase 3
// pub mod active_probe;    // Phase 2
// pub mod fingerprint;     // Phase 2
// pub mod detector;        // Phase 4

/// Start the full capture → pipeline → frontend server stack.
pub fn serve(bind: String, cfg: config::Config) {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    let db = store::open(&cfg.store.db_path).unwrap_or_else(|e| {
        log::error!("failed to open DB: {e}");
        std::process::exit(1);
    });

    let cfg = Arc::new(cfg);
    let (evt_tx, evt_rx) = std::sync::mpsc::channel();
    let capture_running = Arc::new(AtomicBool::new(false));

    // Passive DNS cache — shared between capture thread (writes) and workers (reads).
    let passive_dns = ip_to_domain::PassiveDnsCache::new();

    let prefilter = if cfg.prefilter.enabled {
        match prefilter::Prefilter::load(&cfg.prefilter) {
            Ok(pf) => {
                log::info!("prefilter loaded ({} flow cap)", cfg.prefilter.max_flows);
                Some(pf)
            }
            Err(e) => {
                log::error!("prefilter disabled: {e}");
                None
            }
        }
    } else {
        None
    };

    let cap_cfg = cfg.capture.clone();
    let capture_running_for_thread = Arc::clone(&capture_running);
    let passive_dns_for_capture = passive_dns.clone();
    std::thread::spawn(move || {
        capture_running_for_thread.store(true, Ordering::Release);
        capture::run(&cap_cfg, evt_tx, prefilter, Some(passive_dns_for_capture));
        capture_running_for_thread.store(false, Ordering::Release);
    });

    pipeline::spawn_workers(evt_rx, db.clone(), &cfg, passive_dns);

    web::Server::new(bind, cfg, db, capture_running)
        .run()
        .unwrap();
}
