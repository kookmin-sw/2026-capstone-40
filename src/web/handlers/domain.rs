use askama::Template as _;
use crate::store::Db;
use crate::web::{templates, response};
use crate::store;

pub fn handle(domain: &str, db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let (risk_score, _decision) = store::domain_detail(&conn, domain)
        .unwrap_or((None, None));

    let risk_class = templates::DomainRow {
        domain:      domain.to_string(),
        risk_score,
        decision:    None,
        ips:         vec![],
        last_seen:   0,
        alert_count: 0,
    }
    .risk_class();

    let ip_history: Vec<templates::IpRecord> = store::domain_ip_history(&conn, domain)
        .into_iter()
        .map(|(ip, first_seen, last_seen)| templates::IpRecord { ip, first_seen, last_seen })
        .collect();

    let alerts: Vec<templates::AlertRow> = store::domain_alerts(&conn, domain)
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

    let snapshots: Vec<templates::SnapshotRow> = store::get_fingerprints(&conn, domain, 20)
        .into_iter()
        .map(|fp| templates::SnapshotRow {
            ts:             fp.ts,
            status_code:    None,
            title:          fp.title,
            has_login_form: false,
            redirect_depth: 0,
            html_hash_short: fp.html_hash.chars().take(12).collect(),
        })
        .collect();

    let body = templates::DomainPage {
        page_title: "Domain",
        active:     "domains",
        domain:     domain.to_string(),
        risk_score,
        risk_class,
        ip_history,
        signals:   vec![],
        alerts,
        snapshots,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
