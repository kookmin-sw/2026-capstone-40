use std::collections::HashSet;

use serde::Serialize;

// ── domain string helpers ─────────────────────────────────────────────────────

pub fn looks_like_domain(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return false;
    }
    if s.eq_ignore_ascii_case("localhost") {
        return false;
    }
    for label in s.trim_end_matches('.').split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    true
}

pub fn norm_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_lowercase()
}

pub fn sorted_vec(set: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<_> = set.iter().cloned().collect();
    v.sort();
    v
}

pub fn cache_fresh(now: i64, ts: i64, ttl_s: i64) -> bool {
    ttl_s > 0 && now.saturating_sub(ts) < ttl_s
}

pub fn cache_ttl_secs(days: u64) -> i64 {
    days.saturating_mul(24 * 3600).min(i64::MAX as u64) as i64
}

// ── provider result ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct ProviderResult {
    pub provider: String,
    pub domains: HashSet<String>,
    pub note: Option<String>,
    pub cache_stale: bool,
}

// ── public output types ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DomainEntry {
    pub domain: String,
    pub sources: Vec<String>,
    pub confidence: u8,
}

#[derive(Debug, Serialize)]
pub struct LookupResult {
    pub ip: String,
    pub sources: Vec<String>,
    pub verified: bool,
    pub count: usize,
    pub domains: Vec<DomainEntry>,
    pub notes: Vec<String>,
}
