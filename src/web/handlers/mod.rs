mod alerts;
mod chart;
mod dashboard;
mod domain;
mod domains;
mod probe;

use crate::config::Config;
use crate::store::Db;
use crate::web::{response, router::Route};

pub use response::HttpResponse;

pub fn dispatch(route: Route, config: &Config, db: &Db) -> HttpResponse {
    match route {
        Route::Dashboard              => dashboard::handle(config, db),
        Route::Chart(ref name)        => chart::handle(name, db),
        Route::Alerts { show_acked }  => alerts::handle(show_acked, db),
        Route::Domains                => domains::handle(db),
        Route::Domain(ref d)          => domain::handle(d, db),
        Route::Probe(query)           => probe::handle(query, config, db),
        Route::AckAlert(id)           => handle_ack(id, db),
        Route::StaticFile(ref name)   => serve_static(name),
        Route::NotFound               => response::not_found(),
    }
}

fn handle_ack(id: i64, db: &Db) -> HttpResponse {
    if let Ok(conn) = db.lock() {
        let _ = crate::store::ack_alert(&conn, id);
    }
    response::redirect("/alerts")
}

fn serve_static(name: &str) -> HttpResponse {
    match name {
        "style.css" => {
            response::static_file("text/css; charset=utf-8", crate::web::static_files::STYLE_CSS.as_bytes().to_vec())
        }
        _ => response::not_found(),
    }
}
