mod alerts;
mod chart;
mod dashboard;
mod domain;
mod domains;
mod probe;

use crate::frontend::{response, router::Route};

pub use response::HttpResponse;

pub fn dispatch(route: Route) -> HttpResponse {
    match route {
        Route::Dashboard              => dashboard::handle(),
        Route::Chart(ref name)        => chart::handle(name),
        Route::Alerts { show_acked }  => alerts::handle(show_acked),
        Route::Domains                => domains::handle(),
        Route::Domain(ref d)          => domain::handle(d),
        Route::Probe(query)           => probe::handle(query),
        Route::AckAlert(id)           => handle_ack(id),
        Route::StaticFile(ref name)   => serve_static(name),
        Route::NotFound               => response::not_found(),
    }
}

fn handle_ack(id: i64) -> HttpResponse {
    // TODO(Phase 1): store::ack_alert(id)
    let _ = id;
    response::redirect("/alerts")
}

fn serve_static(name: &str) -> HttpResponse {
    match name {
        "style.css" => {
            let css = include_str!("../../../frontend/style.css");
            response::static_file("text/css; charset=utf-8", css.as_bytes().to_vec())
        }
        _ => response::not_found(),
    }
}
