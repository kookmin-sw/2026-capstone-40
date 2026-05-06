//! All askama Template structs live here so the `filters` module below
//! is automatically in scope for every template.

use askama::Template;

// ---- custom filters ----------------------------------------

mod filters {
    /// Unix timestamp → "YYYY-MM-DD HH:MM" (UTC, no external crate).
    pub fn fmt_ts(ts: &i64) -> askama::Result<String> {
        Ok(fmt_unix(*ts as u64))
    }

    /// `{{ opt|default("fallback") }}` — renders Option<T> with a fallback string.
    pub fn default<T: std::fmt::Display>(
        opt: &Option<T>,
        fallback: &str,
    ) -> askama::Result<String> {
        Ok(opt
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| fallback.to_string()))
    }

    /// `{{ s|truncate(n) }}` — truncates to n chars, appends "…" if cut.
    pub fn truncate(s: &str, len: &usize) -> askama::Result<String> {
        if s.chars().count() <= *len {
            Ok(s.to_string())
        } else {
            Ok(s.chars().take(*len).collect::<String>() + "…")
        }
    }

    fn fmt_unix(s: u64) -> String {
        // Rata Die day count from Unix epoch (1970-01-01)
        let days  = s / 86400;
        let rem   = s % 86400;
        let hh    = rem / 3600;
        let mm    = (rem % 3600) / 60;

        let (y, m, d) = days_to_ymd(days);
        format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
    }

    fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
        // Proleptic Gregorian: algorithm by Henry Fliegel & Thomas Van Flandern
        let z  = days + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y   = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp  = (5 * doy + 2) / 153;
        let d   = doy - (153 * mp + 2) / 5 + 1;
        let m   = if mp < 10 { mp + 3 } else { mp - 9 };
        let y   = if m <= 2 { y + 1 } else { y };
        (y, m, d)
    }
}

// ---- shared view data types --------------------------------

pub struct AlertRow {
    pub id:           i64,
    pub severity:     u8,
    pub alert_type:   String,
    pub domain:       String,
    pub detail:       Option<String>,
    pub ts:           i64,
    pub acknowledged: bool,
}

impl AlertRow {
    pub fn severity_label(&self) -> &'static str {
        match self.severity {
            1 => "info", 2 => "low", 3 => "medium", 4 => "high", 5 => "critical", _ => "?",
        }
    }
}

pub struct DomainRow {
    pub domain:      String,
    pub risk_score:  Option<u32>,
    pub decision:    Option<String>,
    pub ips:         Vec<String>,
    pub last_seen:   i64,
    pub alert_count: u32,
}

impl DomainRow {
    pub fn risk_class(&self) -> &'static str {
        match self.risk_score {
            Some(s) if s >= 60 => "risk-high",
            Some(s) if s >= 30 => "risk-med",
            Some(_)            => "risk-low",
            None               => "",
        }
    }
}

pub struct ProbeResult {
    pub ip:       String,
    pub count:    usize,
    pub verified: bool,
    pub domains:  Vec<ProbeEntry>,
    pub notes:    Vec<String>,
}

pub struct ProbeEntry {
    pub domain:  String,
    pub sources: Vec<String>,
}

pub struct IpRecord {
    pub ip:         String,
    pub first_seen: i64,
    pub last_seen:  i64,
}

pub struct SignalRow {
    pub name:   String,
    pub points: u32,
    pub pct:    u32, // 0–100, relative to max signal in this score
}

pub struct SnapshotRow {
    pub ts:              i64,
    pub status_code:     Option<u16>,
    pub title:           Option<String>,
    pub has_login_form:  bool,
    pub redirect_depth:  u32,
    /// First 12 chars of html_hash, or "—" if none.
    pub html_hash_short: String,
}

impl SnapshotRow {
    pub fn status_badge_class(&self) -> &'static str {
        match self.status_code {
            Some(c) if c < 400 => "sev-1",
            Some(_)            => "sev-4",
            None               => "sev-1",
        }
    }
}

// ---- dashboard data types ----------------------------------

pub struct DashboardStats {
    pub total_domains:  u64,
    pub active_alerts:  u64,
    pub ips_captured:   u64,
    pub probes_run:     u64,
}

/// Per-severity unacknowledged alert count for the breakdown bars.
pub struct SeverityCount {
    pub severity: u8,
    pub label:    &'static str,
    pub count:    u64,
    /// 0–100, relative to the highest count among all severities.
    pub pct:      u64,
}

pub struct PipelineStatus {
    pub capture_running: bool,
    pub queue_depth:     u64,
    pub total_skip:      u64,
    pub total_watch:     u64,
    pub total_probe:     u64,
    pub last_probe_ts:   Option<i64>,
    pub db_size_kb:      u64,
}

impl PipelineStatus {
    pub fn total_decisions(&self) -> u64 {
        self.total_skip + self.total_watch + self.total_probe
    }
}

// ---- templates ---------------------------------------------

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub page_title:      &'static str,
    pub active:          &'static str,
    pub stats:           DashboardStats,
    pub severity_counts: Vec<SeverityCount>,
    pub pipeline:        PipelineStatus,
    pub recent_alerts:   Vec<AlertRow>,
    pub recent_domains:  Vec<DomainRow>,
}

#[derive(Template)]
#[template(path = "alerts.html")]
pub struct AlertsPage {
    pub page_title: &'static str,
    pub active:     &'static str,
    pub alerts:     Vec<AlertRow>,
    pub show_acked: bool,
}

#[derive(Template)]
#[template(path = "domains.html")]
pub struct DomainsPage {
    pub page_title: &'static str,
    pub active:     &'static str,
    pub domains:    Vec<DomainRow>,
}

#[derive(Template)]
#[template(path = "probe.html")]
pub struct ProbePage {
    pub page_title:  &'static str,
    pub active:      &'static str,
    pub query_ip:    String,
    pub sources_ptr: bool,
    pub sources_ht:  bool,
    pub verify:      bool,
    pub probe_result: Option<ProbeResult>,
}

#[derive(Template)]
#[template(path = "domain.html")]
pub struct DomainPage {
    pub page_title: &'static str,
    pub active:     &'static str,
    pub domain:     String,
    pub risk_score: Option<u32>,
    pub risk_class: &'static str,
    pub ip_history: Vec<IpRecord>,
    pub signals:    Vec<SignalRow>,
    pub alerts:     Vec<AlertRow>,
    pub snapshots:  Vec<SnapshotRow>,
}
