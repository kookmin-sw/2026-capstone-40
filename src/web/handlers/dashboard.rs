use crate::config::Config;
use crate::store;
use crate::store::Db;
use crate::web::{pages, response};
use askama::Template as _;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn handle(config: &Config, db: &Db, capture_running: &AtomicBool) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return response::html(500, "<pre>DB lock poisoned</pre>".into()),
    };

    let s = store::stats(&conn);
    let pl = store::pipeline_status(&conn);
    let sev = store::severity_counts(&conn);
    let alerts = store::recent_alerts(&conn, 10);
    let domains = store::recent_domains(&conn, 10);
    let pf_stats = store::prefilter_stats(&conn);

    let stats = pages::DashboardStats {
        total_domains: s.total_domains,
        active_alerts: s.active_alerts,
        ips_captured: s.ips_captured,
        probes_run: s.probes_run,
    };

    let capture_source = match (&config.capture.interface, &config.capture.pcap_file) {
        (Some(iface), _) => Some(format!("interface {iface}")),
        (_, Some(pcap)) => Some(format!("pcap {pcap}")),
        _ => None,
    };

    let pipeline = pages::PipelineStatus {
        capture_running: capture_running.load(Ordering::Acquire),
        capture_source,
        queue_depth: pl.queue_depth,
        total_skip: pl.total_skip,
        total_watch: pl.total_watch,
        total_probe: pl.total_probe,
        last_probe_ts: pl.last_probe_ts,
        db_size_kb: pl.db_size_kb,
    };

    let severity_counts = severity_breakdown(&sev);

    let recent_alerts: Vec<pages::AlertRow> = alerts
        .into_iter()
        .map(|a| pages::AlertRow {
            id: a.id,
            severity: a.severity,
            alert_type: a.alert_type,
            domain: a.domain,
            detail: a.detail,
            ts: a.ts,
            acknowledged: a.acknowledged,
        })
        .collect();

    let recent_domains: Vec<pages::DomainRow> = domains
        .into_iter()
        .map(|d| pages::DomainRow {
            domain: d.domain,
            risk_score: d.risk_score,
            decision: d.decision,
            ips: d.ips,
            last_seen: d.last_seen,
            alert_count: d.alert_count,
        })
        .collect();

    let prefilter = pages::PrefilterPanel {
        malicious:  pf_stats.malicious,
        unknown:    pf_stats.unknown,
        classified: pf_stats.classified,
        enabled:    config.prefilter.enabled,
    };

    let body = pages::DashboardPage {
        page_title: "Dashboard",
        active: "dashboard",
        stats,
        severity_counts,
        pipeline,
        prefilter,
        recent_alerts,
        recent_domains,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}

fn severity_breakdown(rows: &[(u8, u64)]) -> Vec<pages::SeverityCount> {
    const LABELS: [&str; 5] = ["info", "low", "medium", "high", "critical"];
    let max = rows.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
    (1u8..=5)
        .map(|sev| {
            let count = rows
                .iter()
                .find(|(s, _)| *s == sev)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            pages::SeverityCount {
                severity: sev,
                label: LABELS[(sev - 1) as usize],
                count,
                pct: count * 100 / max,
            }
        })
        .collect()
}
