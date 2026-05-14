pub mod chart;
mod handlers;
mod response;
mod router;
pub mod static_files;
mod templates;

use crate::config::Config;
use crate::prefilter::LabelMap;
use crate::store::Db;
use rusqlite::OpenFlags;
use std::sync::{atomic::AtomicBool, Arc};

pub struct Server {
    bind: String,
    config: Arc<Config>,
    db: Db,
    capture_running: Arc<AtomicBool>,
    labels: Option<Arc<LabelMap>>,
}

impl Server {
    pub fn new(
        bind: impl Into<String>,
        config: Arc<Config>,
        db: Db,
        capture_running: Arc<AtomicBool>,
        labels: Option<LabelMap>,
    ) -> Self {
        Self {
            bind: bind.into(),
            config,
            db,
            capture_running,
            labels: labels.map(Arc::new),
        }
    }

    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server = Arc::new(
            tiny_http::Server::http(&self.bind).map_err(|e| format!("bind {}: {e}", self.bind))?,
        );
        log::info!("listening on http://{}", self.bind);

        // Spawn N handler threads — web requests no longer block each other.
        // DB access still serialises through Mutex<Connection> but HTTP layer is concurrent.
        const WEB_THREADS: usize = 4;
        let mut handles = Vec::with_capacity(WEB_THREADS);

        let db_path = crate::paths::expand_tilde(&self.config.store.db_path);
        let dns_db_path = crate::paths::expand_tilde(&self.config.store.dns_db_path);

        for _ in 0..WEB_THREADS {
            let server = Arc::clone(&server);
            let config = Arc::clone(&self.config);
            let write_db = self.db.clone(); // for ACK writes
            let running = Arc::clone(&self.capture_running);
            let labels = self.labels.clone();
            let db_path = db_path.clone();
            let dns_db_path = dns_db_path.clone();

            handles.push(std::thread::spawn(move || {
                // Each web thread opens its own read-only connection.
                // WAL mode lets readers proceed concurrently without blocking writers.
                let read_conn = rusqlite::Connection::open_with_flags(
                    &db_path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .and_then(|conn| {
                    crate::store::attach_dns_database(&conn, &dns_db_path)?;
                    Ok(conn)
                });

                let read_db: Db = match read_conn {
                    Ok(c) => Arc::new(std::sync::Mutex::new(c)),
                    Err(e) => {
                        log::warn!("read-only DB connection unavailable, using writer DB: {e}");
                        write_db.clone()
                    }
                };

                loop {
                    let request = match server.recv() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    let route = router::Route::parse(request.method(), request.url());
                    // Reads use per-thread connection; writes (ack) use shared write_db.
                    let db = if matches!(route, router::Route::AckAlert(_)) {
                        &write_db
                    } else {
                        &read_db
                    };
                    let resp = handlers::dispatch(route, &config, db, &running, labels.as_deref());
                    let _ = request.respond(resp);
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }
}
