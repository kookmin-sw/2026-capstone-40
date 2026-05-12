use askama::Template as _;
use crate::store::Db;
use crate::web::{templates, response};
use crate::store;

pub fn handle(show_acked: bool, db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let alerts: Vec<templates::AlertRow> = store::all_alerts(&conn, show_acked)
        .into_iter()
        .map(|a| templates::AlertRow {
            id:           a.id,
            severity:     a.severity,
            alert_type:   a.alert_type,
            domain:       a.domain,
            detail:       a.detail,
            ts:           a.ts,
            acknowledged: a.acknowledged,
        })
        .collect();

    let body = templates::AlertsPage {
        page_title: "Alerts",
        active:     "alerts",
        alerts,
        show_acked,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
