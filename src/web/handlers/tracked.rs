use askama::Template as _;

use crate::prefilter::{ClassKind, LabelMap};
use crate::store::{self, Db};
use crate::web::{templates, response};

const PROBE_INTERVAL_DAYS: u64 = 7;

pub fn handle(labels: Option<&LabelMap>, db: &Db) -> response::HttpResponse {
    let rows = match labels {
        None => vec![],
        Some(lm) => {
            let conn = match db.lock() {
                Ok(c) => c,
                Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
            };
            let mut seen = std::collections::HashSet::new();
            let mut rows = Vec::new();
            for entry in &lm.entries {
                if matches!(entry.kind, ClassKind::Benign) {
                    continue;
                }
                for domain in &entry.typical_domains {
                    if domain.is_empty() || !seen.insert(domain.clone()) {
                        continue; // deduplicate — show each domain once
                    }
                    let last_probed    = store::last_probe_ts(&conn, domain);
                    let snapshot_count = store::snapshot_count(&conn, domain);
                    let latest_title   = store::get_fingerprints(&conn, domain, 1)
                        .into_iter().next()
                        .and_then(|fp| fp.title);
                    let kind = match entry.kind {
                        ClassKind::Malicious => "malicious",
                        ClassKind::Known     => "known",
                        ClassKind::Benign    => "benign",
                    };
                    rows.push(templates::TrackedRow {
                        class_name: entry.name.clone(),
                        kind: kind.into(),
                        domain: domain.clone(),
                        last_probed,
                        snapshot_count,
                        latest_title,
                        probe_interval_days: PROBE_INTERVAL_DAYS,
                    });
                }
            }
            rows
        }
    };

    let body = templates::TrackedPage {
        page_title: "Tracked",
        active: "tracked",
        rows,
        probe_interval_days: PROBE_INTERVAL_DAYS,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
