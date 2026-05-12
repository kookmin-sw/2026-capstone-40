use askama::Template as _;
use crate::store::Db;
use crate::web::{templates, response};
use crate::store;

pub fn handle(db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let domains: Vec<templates::DomainRow> = store::all_domains(&conn)
        .into_iter()
        .map(|d| templates::DomainRow {
            domain:      d.domain,
            risk_score:  d.risk_score,
            decision:    d.decision,
            ips:         d.ips,
            last_seen:   d.last_seen,
            alert_count: d.alert_count,
        })
        .collect();

    let body = templates::DomainsPage {
        page_title: "Domains",
        active:     "domains",
        domains,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
