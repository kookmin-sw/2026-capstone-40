use crate::store;
use crate::store::Db;
use crate::web::{response, templates};
use askama::Template as _;

const PAGE_SIZE: usize = 200;

pub fn handle(show_acked: bool, min_severity: u8, page: usize, db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let total = store::alert_count(&conn, show_acked, min_severity);
    let total_pages = total.div_ceil(PAGE_SIZE);
    let page = page.min(total_pages.max(1));
    let offset = (page - 1) * PAGE_SIZE;

    let alerts: Vec<templates::AlertRow> =
        store::paged_alerts(&conn, show_acked, min_severity, offset, PAGE_SIZE)
            .into_iter()
            .map(|a| templates::AlertRow {
                id: a.id,
                severity: a.severity,
                alert_type: a.alert_type,
                domain: a.domain,
                detail: a.detail,
                ts: a.ts,
                acknowledged: a.acknowledged,
            })
            .collect();

    let body = templates::AlertsPage {
        page_title: "Alerts",
        active: "alerts",
        alerts,
        show_acked,
        min_severity,
        page,
        total_pages,
        total,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
