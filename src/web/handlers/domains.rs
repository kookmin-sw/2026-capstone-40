use askama::Template as _;
use crate::store::Db;
use crate::web::{pages, response};
use crate::store;

pub fn handle(db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let domains: Vec<pages::DomainRow> = store::all_domains(&conn)
        .into_iter()
        .map(|d| pages::DomainRow {
            domain:      d.domain,
            risk_score:  d.risk_score,
            decision:    d.decision,
            ips:         d.ips,
            last_seen:   d.last_seen,
            alert_count: d.alert_count,
        })
        .collect();

    let body = pages::DomainsPage {
        page_title: "Domains",
        active:     "domains",
        domains,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
