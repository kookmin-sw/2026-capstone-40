fn main() {
    capstone::logger::init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("capture")    => todo!("Phase 4: packet_capture::run()"),
        Some("probe")      => todo!("Phase 2: active_probe::probe()"),
        Some("serve")      => {
            let cfg  = capstone::config::Config::load();
            let bind = args.get(2)
                .map(String::as_str)
                .unwrap_or(&cfg.api.bind)
                .to_owned();
            capstone::serve(bind, cfg);
        }
        Some("import-bad") => todo!("Phase 1: store::import_known_bad()"),
        Some("score")      => todo!("Phase 3: passive_filter::score()"),
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
