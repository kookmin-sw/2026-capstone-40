mod handlers;
mod pages;
mod response;
mod router;

use std::net::ToSocketAddrs;

/// HTTP server. Owns its bind address; all shared state goes through handlers → store (Phase 1).
pub struct Server {
    bind: String,
}

impl Server {
    pub fn new(bind: impl Into<String>) -> Self {
        Self { bind: bind.into() }
    }

    /// Blocking. Spawns one thread per request (tiny_http default).
    pub fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server = tiny_http::Server::http(&self.bind)
            .map_err(|e| format!("bind {}: {e}", self.bind))?;

        eprintln!("frontend: listening on http://{}", self.bind);

        for request in server.incoming_requests() {
            let route = router::Route::parse(request.method(), request.url());
            let resp  = handlers::dispatch(route);
            request.respond(resp)?;
        }

        Ok(())
    }
}
