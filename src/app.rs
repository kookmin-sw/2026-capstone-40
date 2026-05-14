use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{alert, capture, config, prefilter, resolver, store, web};

struct PrefilterRuntime {
    prefilter: Option<prefilter::Prefilter>,
    labels: Option<prefilter::LabelMap>,
}

/// Start the full capture -> alert pipeline -> web server.
pub fn serve(bind: String, cfg: config::Config) {
    let db = open_store(&cfg);

    let cfg = Arc::new(cfg);
    let (evt_tx, evt_rx) = std::sync::mpsc::channel();
    let capture_running = Arc::new(AtomicBool::new(false));

    let passive_dns = resolver::PassiveDnsCache::new();
    let prefilter = load_prefilter(&cfg);
    let labels_for_web = prefilter.labels.clone();

    spawn_capture_thread(
        cfg.capture.clone(),
        evt_tx,
        prefilter.prefilter,
        passive_dns.clone(),
        parse_skip_ips(&cfg),
        Arc::clone(&capture_running),
    );

    alert::spawn_workers(evt_rx, db.clone(), &cfg, passive_dns, prefilter.labels);

    web::Server::new(bind, cfg, db, capture_running, labels_for_web)
        .run()
        .unwrap();
}

fn open_store(cfg: &config::Config) -> store::Db {
    store::open(&cfg.store.db_path, &cfg.store.dns_db_path).unwrap_or_else(|e| {
        log::error!("failed to open DB: {e}");
        std::process::exit(1);
    })
}

fn load_prefilter(cfg: &config::Config) -> PrefilterRuntime {
    if cfg.prefilter.enabled {
        match prefilter::Prefilter::load(&cfg.prefilter) {
            Ok(pf) => {
                log::info!("prefilter loaded ({} flow cap)", cfg.prefilter.max_flows);
                let lm = pf.labels().clone();
                PrefilterRuntime {
                    prefilter: Some(pf),
                    labels: Some(lm),
                }
            }
            Err(e) => {
                log::error!("prefilter disabled: {e}");
                PrefilterRuntime {
                    prefilter: None,
                    labels: None,
                }
            }
        }
    } else {
        PrefilterRuntime {
            prefilter: None,
            labels: None,
        }
    }
}

fn spawn_capture_thread(
    cap_cfg: config::CaptureConfig,
    evt_tx: std::sync::mpsc::Sender<capture::CaptureEvent>,
    prefilter: Option<prefilter::Prefilter>,
    passive_dns: resolver::PassiveDnsCache,
    skip_ips: Vec<prefilter::flow_table::SkipNet>,
    capture_running: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        capture_running.store(true, Ordering::Release);
        capture::run(&cap_cfg, evt_tx, prefilter, Some(passive_dns), skip_ips);
        capture_running.store(false, Ordering::Release);
    });
}

fn parse_skip_ips(cfg: &config::Config) -> Vec<prefilter::flow_table::SkipNet> {
    cfg.prefilter
        .skip_ips
        .iter()
        .filter_map(|s| prefilter::flow_table::SkipNet::parse(s))
        .collect()
}
