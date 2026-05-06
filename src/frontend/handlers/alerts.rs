use askama::Template as _;
use crate::frontend::{pages, response};

pub fn handle(show_acked: bool) -> response::HttpResponse {
    // TODO(Phase 1): let alerts = store::list_alerts(show_acked);
    let alerts: Vec<pages::AlertRow> = vec![];

    let body = pages::AlertsPage {
        page_title: "Alerts",
        active:     "alerts",
        alerts,
        show_acked,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
