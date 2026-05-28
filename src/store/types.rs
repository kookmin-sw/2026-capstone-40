pub struct Stats {
    pub total_domains: u64,
    pub active_alerts: u64,
    pub ips_captured:  u64,
    pub probes_run:    u64,
}

pub struct Alert {
    pub id:           i64,
    pub severity:     u8,
    pub alert_type:   String,
    pub domain:       String,
    pub detail:       Option<String>,
    pub ts:           i64,
    pub acknowledged: bool,
}

pub struct Domain {
    pub domain:      String,
    pub risk_score:  Option<u32>,
    pub decision:    Option<String>,
    pub ips:         Vec<String>,
    pub last_seen:   i64,
    pub alert_count: u32,
}

pub struct Pipeline {
    pub total_skip:    u64,
    pub total_watch:   u64,
    pub total_probe:   u64,
    pub queue_depth:   u64,
    pub last_probe_ts: Option<i64>,
    pub db_size_kb:    u64,
}

pub struct PrefilterStats {
    pub malicious:  u64,
    pub unknown:    u64,
    pub classified: u64,
}

pub struct StoredFingerprint {
    pub simhash:     u64,
    pub html_hash:   String,
    pub title:       Option<String>,
    pub h1:          Option<String>,
    pub ts:          i64,
    pub tag_bigrams: std::collections::HashSet<String>,
    pub css_classes: std::collections::HashSet<String>,
    pub word_tokens: std::collections::HashSet<String>,
}

/// Owned fingerprint payload written to the snapshots table. Set fields are
/// newline-joined before insert; callers build it from a `PageFingerprint`.
pub struct FingerprintWrite<'a> {
    pub title:       Option<&'a str>,
    pub h1:          Option<&'a str>,
    pub simhash:     u64,
    pub html_hash:   &'a str,
    pub tag_bigrams: String,
    pub css_classes: String,
    pub word_tokens: String,
}

pub struct TrafficData {
    pub ips:     Vec<u64>,
    pub alerts:  Vec<u64>,
    pub domains: Vec<u64>,
    pub probes:  Vec<u64>,
}
