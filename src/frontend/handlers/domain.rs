use askama::Template as _;
use crate::frontend::{pages, response};

pub fn handle(domain: &str) -> response::HttpResponse {
    // TODO(Phase 1): fetch from store
    // let ip_history = store::ip_history(domain);
    // let signals    = store::last_risk_signals(domain);
    // let alerts     = store::domain_alerts(domain);
    // let snapshots  = store::domain_snapshots(domain);

    let risk_score: Option<u32> = None;
    let risk_class = pages::DomainRow {
        domain:      domain.to_string(),
        risk_score,
        decision:    None,
        ips:         vec![],
        last_seen:   0,
        alert_count: 0,
    }
    .risk_class();

    let body = pages::DomainPage {
        page_title: "Domain",
        active:     "domains",
        domain:     domain.to_string(),
        risk_score,
        risk_class,
        ip_history: vec![],
        signals:    vec![],
        alerts:     vec![],
        snapshots:  vec![],
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
