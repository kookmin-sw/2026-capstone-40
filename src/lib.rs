pub mod capture;
pub mod config;
pub mod html_fingerprint;
pub mod ip_to_domain;
pub mod logger;
pub mod paths;
pub mod pipeline;
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
    let (ip_tx, ip_rx) = std::sync::mpsc::channel();
    let capture_running = Arc::new(AtomicBool::new(false));

    let cap_cfg = cfg.capture.clone();
    let capture_running_for_thread = Arc::clone(&capture_running);
    std::thread::spawn(move || {
        capture_running_for_thread.store(true, Ordering::Release);
        capture::run(&cap_cfg, ip_tx);
        capture_running_for_thread.store(false, Ordering::Release);
    });

    pipeline::spawn_workers(ip_rx, db.clone(), &cfg);

    web::Server::new(bind, cfg, db, capture_running)
        .run()
        .unwrap();
}
