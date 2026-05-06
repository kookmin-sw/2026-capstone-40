use askama::Template as _;
use crate::frontend::{pages, response};

pub fn handle() -> response::HttpResponse {
    // TODO(Phase 1): query store for real data
    let stats = pages::DashboardStats {
        total_domains: 0,
        active_alerts: 0,
        ips_captured:  0,
        probes_run:    0,
    };

    let severity_counts = severity_breakdown(&[]);
    let pipeline = pages::PipelineStatus {
        capture_running: false,
        queue_depth:     0,
        total_skip:      0,
        total_watch:     0,
        total_probe:     0,
        last_probe_ts:   None,
        db_size_kb:      0,
    };

    let body = pages::DashboardPage {
        page_title:     "Dashboard",
        active:         "dashboard",
        stats,
        severity_counts,
        pipeline,
        recent_alerts:  vec![],
        recent_domains: vec![],
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}

/// Build per-severity counts with relative percentages.
/// `rows` will come from store::alert_severity_counts() in Phase 1.
fn severity_breakdown(rows: &[(u8, u64)]) -> Vec<pages::SeverityCount> {
    const LABELS: [&str; 5] = ["info", "low", "medium", "high", "critical"];

    let mut counts: Vec<(u8, u64)> = (1u8..=5)
        .map(|sev| {
            let n = rows.iter().find(|(s, _)| *s == sev).map(|(_, n)| *n).unwrap_or(0);
            (sev, n)
        })
        .collect();

    let max = counts.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);

    counts
        .into_iter()
        .map(|(sev, count)| pages::SeverityCount {
            severity: sev,
            label:    LABELS[(sev - 1) as usize],
            count,
            pct:      count * 100 / max,
        })
        .collect()
}
