use askama::Template as _;
use crate::store::Db;
use crate::frontend::{pages, response};
use crate::store;

pub fn handle(domain: &str, db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let (risk_score, _decision) = store::domain_detail(&conn, domain)
        .unwrap_or((None, None));

    let risk_class = pages::DomainRow {
        domain:      domain.to_string(),
        risk_score,
        decision:    None,
        ips:         vec![],
        last_seen:   0,
        alert_count: 0,
    }
    .risk_class();

    let ip_history: Vec<pages::IpRecord> = store::domain_ip_history(&conn, domain)
        .into_iter()
        .map(|(ip, first_seen, last_seen)| pages::IpRecord { ip, first_seen, last_seen })
        .collect();

    let alerts: Vec<pages::AlertRow> = store::domain_alerts(&conn, domain)
        .into_iter()
        .map(|a| pages::AlertRow {
            id:           a.id,
            severity:     a.severity,
            alert_type:   a.alert_type,
            domain:       a.domain,
            detail:       a.detail,
            ts:           a.ts,
            acknowledged: a.acknowledged,
        })
        .collect();

    let body = pages::DomainPage {
        page_title: "Domain",
        active:     "domains",
        domain:     domain.to_string(),
        risk_score,
        risk_class,
        ip_history,
        signals:   vec![], // Phase 3: passive filter signals
        alerts,
        snapshots: vec![], // Phase 2: probe snapshots
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
