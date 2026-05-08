pub mod capture;
pub mod config;
pub mod frontend;
pub mod html_sim;
pub mod ip_to_domain;
pub mod logger;
pub mod paths;
pub mod pipeline;
pub mod store;
pub mod time;
// pub mod passive_filter;  // Phase 3
// pub mod active_probe;    // Phase 2
// pub mod fingerprint;     // Phase 2
// pub mod detector;        // Phase 4

/// Start the full capture → pipeline → frontend server stack.
pub fn serve(bind: String, cfg: config::Config) {
    let db = store::open(&cfg.store.db_path).unwrap_or_else(|e| {
        log::error!("failed to open DB: {e}");
        std::process::exit(1);
    });

    let cfg = std::sync::Arc::new(cfg);
    let (ip_tx, ip_rx) = std::sync::mpsc::channel();

    let cap_cfg = cfg.capture.clone();
    std::thread::spawn(move || capture::run(&cap_cfg, ip_tx));

    pipeline::spawn_workers(ip_rx, db.clone(), &cfg);

    frontend::Server::new(bind, cfg, db).run().unwrap();
}
