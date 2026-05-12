pub mod chart;
mod handlers;
mod pages;
mod response;
mod router;
pub mod static_files;

use crate::config::Config;
use crate::prefilter::LabelMap;
use crate::store::Db;
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
        let server =
            tiny_http::Server::http(&self.bind).map_err(|e| format!("bind {}: {e}", self.bind))?;
        log::info!("listening on http://{}", self.bind);
        for request in server.incoming_requests() {
            let route = router::Route::parse(request.method(), request.url());
            let resp = handlers::dispatch(
                route, &self.config, &self.db,
                &self.capture_running, self.labels.as_deref(),
            );
            request.respond(resp)?;
        }
        Ok(())
    }
}
