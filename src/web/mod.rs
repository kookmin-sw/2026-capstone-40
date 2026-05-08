pub mod chart;
pub mod static_files;
mod handlers;
mod pages;
mod response;
mod router;

use std::sync::Arc;
use crate::config::Config;
use crate::store::Db;

/// HTTP server. Owns its bind address; all shared state goes through handlers → store.
pub struct Server {
    bind:   String,
    config: Arc<Config>,
    db:     Db,
}

impl Server {
    pub fn new(bind: impl Into<String>, config: Arc<Config>, db: Db) -> Self {
        Self { bind: bind.into(), config, db }
    }

    /// Blocking. Spawns one thread per request (tiny_http default).
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server = tiny_http::Server::http(&self.bind)
            .map_err(|e| format!("bind {}: {e}", self.bind))?;

        log::info!("listening on http://{}", self.bind);

        for request in server.incoming_requests() {
            let route = router::Route::parse(request.method(), request.url());
            let resp  = handlers::dispatch(route, &self.config, &self.db);
            request.respond(resp)?;
        }

        Ok(())
    }
}
