use crate::{app, config, resolver};

pub fn run(args: impl IntoIterator<Item = String>) {
    let args: Vec<String> = args.into_iter().collect();

    match args.first().map(String::as_str) {
        Some("capture") => todo!("Phase 4: packet_capture::run()"),
        Some("probe") => todo!("Phase 2: active_probe::probe()"),
        Some("serve") => run_serve(&args[1..]),
        Some("import-bad") => todo!("Phase 1: store::import_known_bad()"),
        Some("score") => todo!("Phase 3: passive_filter::score()"),
        Some("ip-to-domain") | Some("resolve-ip") => run_ip_to_domain(&args[1..]),
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }
}

fn run_serve(args: &[String]) {
    let cfg = config::Config::load();
    let bind = args
        .first()
        .map(String::as_str)
        .unwrap_or(&cfg.api.bind)
        .to_owned();
    app::serve(bind, cfg);
}

fn print_usage() {
    eprintln!(concat!(
        "Usage: capstone <subcommand>\n",
        "\n",
        "Subcommands:\n",
        "  capture     Capture packets from NIC or PCAP file\n",
        "  probe       Actively probe a single domain\n",
        "  serve       Start API + frontend server\n",
        "  import-bad  Import known-bad indicator list\n",
        "  score       Run passive risk score on a domain\n",
        "  ip-to-domain <ip> [--verify] [--sources=a,b] [--clear-cache|--clear-cache-all]",
    ));
}

fn run_ip_to_domain(args: &[String]) {
    let mut cfg = config::Config::load();
    let mut ip: Option<String> = None;
    let mut clear_this_ip = false;
    let mut clear_all = false;
    let mut json = false;

    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => {
                print_ip_to_domain_usage();
                return;
            }
            "--verify" => cfg.ip_to_domain.verify_doh = true,
            "--no-verify" => cfg.ip_to_domain.verify_doh = false,
            "--clear-cache" => clear_this_ip = true,
            "--clear-cache-all" => clear_all = true,
            "--json" => json = true,
            "--sources" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    die("--sources requires a comma-separated value");
                };
                cfg.ip_to_domain.sources = parse_sources(value);
            }
            "--cache" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    die("--cache requires a path");
                };
                cfg.ip_to_domain.cache_path = Some(value.clone());
            }
            "--ttl-days" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    die("--ttl-days requires a number");
                };
                cfg.ip_to_domain.cache_ttl_days = value
                    .parse()
                    .unwrap_or_else(|_| die("--ttl-days must be an integer"));
            }
            "--timeout" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    die("--timeout requires seconds");
                };
                cfg.probe.timeout_s = value
                    .parse()
                    .unwrap_or_else(|_| die("--timeout must be a number"));
            }
            _ if arg.starts_with("--sources=") => {
                cfg.ip_to_domain.sources = parse_sources(&arg["--sources=".len()..]);
            }
            _ if arg.starts_with("--cache=") => {
                cfg.ip_to_domain.cache_path = Some(arg["--cache=".len()..].to_string());
            }
            _ if arg.starts_with("--ttl-days=") => {
                cfg.ip_to_domain.cache_ttl_days = arg["--ttl-days=".len()..]
                    .parse()
                    .unwrap_or_else(|_| die("--ttl-days must be an integer"));
            }
            _ if arg.starts_with("--timeout=") => {
                cfg.probe.timeout_s = arg["--timeout=".len()..]
                    .parse()
                    .unwrap_or_else(|_| die("--timeout must be a number"));
            }
            _ if arg.starts_with('-') => die(&format!("unknown option: {arg}")),
            _ => {
                if ip.replace(arg.clone()).is_some() {
                    die("only one IP address can be resolved at a time");
                }
            }
        }
        i += 1;
    }

    let Some(ip) = ip else {
        print_ip_to_domain_usage();
        std::process::exit(1);
    };

    let cache_path = cfg
        .ip_to_domain
        .cache_path
        .clone()
        .unwrap_or_else(|| resolver::DEFAULT_DNS_CACHE.into());

    if clear_all || clear_this_ip {
        let target = if clear_all { None } else { Some(ip.as_str()) };
        match resolver::clear_cache(&cache_path, target) {
            Ok(n) if json => eprintln!("cleared_cache_rows={n}"),
            Ok(n) => eprintln!("cleared {n} cache row(s)"),
            Err(e) => die(&format!("failed to clear cache: {e}")),
        }
    }

    let lookup_cfg = resolver::LookupConfig {
        sources: cfg.ip_to_domain.sources,
        verify: cfg.ip_to_domain.verify_doh,
        timeout_s: cfg.probe.timeout_s,
        cache_path,
        cache_ttl_days: cfg.ip_to_domain.cache_ttl_days,
        passive_dns: None,
        skip_domain_suffixes: vec![],
        probe_cache_secs: 0,
    };

    let result =
        resolver::lookup(&ip, &lookup_cfg).unwrap_or_else(|e| die(&format!("lookup failed: {e}")));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .unwrap_or_else(|e| die(&format!("failed to encode JSON: {e}")))
        );
        return;
    }

    println!(
        "{} -> {} domain(s){}",
        result.ip,
        result.count,
        if result.verified {
            " (forward verified)"
        } else {
            ""
        }
    );
    for entry in result.domains {
        println!(
            "- {} [{}] confidence={}",
            entry.domain,
            entry.sources.join(","),
            entry.confidence
        );
    }
    for note in result.notes {
        eprintln!("note: {note}");
    }
}

fn parse_sources(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn print_ip_to_domain_usage() {
    eprintln!(concat!(
        "Usage: capstone ip-to-domain <ip> [options]\n",
        "\n",
        "Options:\n",
        "  --sources=a,b       Sources: ptr,hackertarget,passive-dns\n",
        "  --verify            Forward-verify candidates with DNS-over-HTTPS\n",
        "  --clear-cache       Delete cached provider rows for this IP before lookup\n",
        "  --clear-cache-all   Delete all cached provider rows before lookup\n",
        "  --cache <path>      Override cache database path\n",
        "  --ttl-days <n>      Cache freshness window\n",
        "  --timeout <secs>    Provider request timeout\n",
        "  --json              Print full JSON result",
    ));
}

fn die(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::parse_sources;

    #[test]
    fn parse_sources_trims_and_discards_empty_items() {
        assert_eq!(
            parse_sources(" ptr, ,hackertarget,passive-dns,, "),
            vec!["ptr", "hackertarget", "passive-dns"]
        );
    }
}
