mod capture;
mod config;
mod frontend;
mod ip_to_domain;
mod logger;
mod paths;
mod pipeline;
mod store;
mod time;
// mod passive_filter;  // Phase 3
// mod active_probe;    // Phase 2
// mod fingerprint;     // Phase 2
// mod detector;        // Phase 4

fn main() {
    logger::init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("capture") => todo!("Phase 4: packet_capture::run()"),
        Some("probe")   => todo!("Phase 2: active_probe::probe()"),
        Some("serve")   => {
            let cfg = config::Config::load();

            // --bind flag overrides config
            let bind = args.get(2)
                .map(String::as_str)
                .unwrap_or(&cfg.api.bind)
                .to_owned();

            let db = store::open(&cfg.store.db_path).unwrap_or_else(|e| {
                log::error!("failed to open DB: {e}");
                std::process::exit(1);
            });

            let cfg = std::sync::Arc::new(cfg);

            let (ip_tx, ip_rx) = std::sync::mpsc::channel();

            let cap_cfg = cfg.capture.clone();
            std::thread::spawn(move || {
                capture::run(&cap_cfg, ip_tx);
            });

            pipeline::spawn_workers(ip_rx, db.clone(), &cfg);

            frontend::Server::new(bind, cfg, db).run().unwrap();
        }
        Some("import-bad") => todo!("Phase 1: store::import_known_bad()"),
        Some("score")   => todo!("Phase 3: passive_filter::score()"),
        _ => {
            eprintln!(concat!(
                "Usage: capstone <subcommand>\n",
                "\n",
                "Subcommands:\n",
                "  capture     Capture packets from NIC or PCAP file\n",
                "  probe       Actively probe a single domain\n",
                "  serve       Start API + frontend server\n",
                "  import-bad  Import known-bad indicator list\n",
                "  score       Run passive risk score on a domain",
            ));
            std::process::exit(1);
        }
    }
}
