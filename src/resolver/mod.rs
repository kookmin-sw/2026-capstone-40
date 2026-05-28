//! IP → domain resolution pipeline.
//!
//! Three providers, tried in order of `LookupConfig::sources`:
//!   - `passive-dns`   — in-process cache of DNS A/AAAA responses sniffed off wire (fastest)
//!   - `ptr`           — reverse DNS (OS resolver)
//!   - `hackertarget`  — HackerTarget reverse-IP API
//!
//! Results are merged across providers. Optional DoH verification filters to
//! only domains whose forward resolution matches the queried IP.

mod api_cache;
mod dns_parser;
mod doh_verify;
mod hackertarget;
mod passive_dns;
mod rdns;
mod types;

use std::collections::{HashMap, HashSet};

pub use passive_dns::PassiveDnsCache;
pub use types::{DomainEntry, LookupResult};

use api_cache::Cache;
use types::{cache_ttl_secs, ProviderResult};
use doh_verify::verify_domains;

pub const DEFAULT_DNS_CACHE: &str = "~/.cache/capstone/dns_cache.sqlite3";
pub const DEFAULT_CACHE_TTL_DAYS: u64 = 7;

/// Hardcoded IP→domain seeds for CDN/ECH-fronted sites whose SNI we can't sniff.
/// Cloudflare/AWS anycast hides the real host (TLS-1.3 ECH + DoT bypass capture),
/// so passive DNS never sees the mapping. Seeding lets flow attribution and the
/// HTML-match probe still confirm the site. The probe's HTML comparison re-gates,
/// so a stale/wrong seed cannot raise an alert on its own.
/// NOTE: Cloudflare anycast IPs rotate — refresh if attribution stops working.
pub const SEED_IPS: &[(&str, &str)] = &[
    // ohli365.org — Cloudflare-fronted Korean piracy streaming site.
    ("104.21.8.244", "ohli365.org"),
    ("172.67.130.198", "ohli365.org"),
    ("2606:4700:3036::6815:8f4", "ohli365.org"),
    ("2606:4700:3036::ac43:82c6", "ohli365.org"),
];

// ── config ────────────────────────────────────────────────────────────────────

pub struct LookupConfig {
    pub sources: Vec<String>,
    pub verify: bool,
    pub timeout_s: f64,
    pub cache_path: String,
    pub cache_ttl_days: u64,
    pub passive_dns: Option<PassiveDnsCache>,
    /// Domain suffixes (e.g. ".tailscale.com") dropped after resolution in flow pipeline.
    pub skip_domain_suffixes: Vec<String>,
    /// Reuse cached probe fingerprint if within this many seconds (from [probe] cache_days).
    pub probe_cache_secs: i64,
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self {
            sources: vec!["passive-dns".into(), "ptr".into(), "hackertarget".into()],
            verify: false,
            timeout_s: 15.0,
            cache_path: DEFAULT_DNS_CACHE.into(),
            cache_ttl_days: DEFAULT_CACHE_TTL_DAYS,
            passive_dns: None,
            skip_domain_suffixes: vec![".tailscale.com".into()],
            probe_cache_secs: 7 * 86400,
        }
    }
}

// ── public API ────────────────────────────────────────────────────────────────

pub fn clear_cache(
    cache_path: &str,
    ip: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let cache = Cache::new(cache_path)?;
    let removed = match ip {
        Some(ip) => cache.clear_key(ip)?,
        None => cache.clear_all()?,
    };
    Ok(removed)
}

pub fn lookup(ip: &str, config: &LookupConfig) -> Result<LookupResult, Box<dyn std::error::Error>> {
    let cache = Cache::new(&config.cache_path)?;
    let ttl_s = cache_ttl_secs(config.cache_ttl_days);

    let mut all_domains: HashSet<String> = HashSet::new();
    let mut dom_sources: HashMap<String, HashSet<String>> = HashMap::new();
    let mut notes: Vec<String> = Vec::new();

    for source in &config.sources {
        let res: ProviderResult = match source.as_str() {
            "passive-dns" => match &config.passive_dns {
                Some(c) => c.as_provider(ip),
                None => continue,
            },
            "ptr" => rdns::fetch(ip, &cache, ttl_s),
            "hackertarget" => hackertarget::fetch(ip, &cache, config.timeout_s, ttl_s),
            other => {
                notes.push(format!("unknown source '{other}'"));
                continue;
            }
        };

        if let Some(ref n) = res.note {
            let suffix = if res.cache_stale {
                " (stale cache)"
            } else {
                ""
            };
            notes.push(format!("{}: {n}{suffix}", res.provider));
        }
        for d in res.domains {
            dom_sources
                .entry(d.clone())
                .or_default()
                .insert(res.provider.clone());
            all_domains.insert(d);
        }
    }

    let final_set: HashSet<String> = if config.verify && !all_domains.is_empty() {
        let verified = verify_domains(&all_domains, ip, config.timeout_s);
        dom_sources.retain(|d, _| verified.contains(d));
        verified
    } else {
        all_domains
    };

    let mut ranked: Vec<(String, Vec<String>, u8)> = final_set
        .into_iter()
        .map(|d| {
            let mut srcs: Vec<_> = dom_sources.get(&d).into_iter().flatten().cloned().collect();
            srcs.sort();
            let confidence = confidence_for_sources(&srcs, config.verify);
            (d, srcs, confidence)
        })
        .collect();

    ranked.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

    let count = ranked.len();
    let domains = ranked
        .into_iter()
        .map(|(domain, sources, confidence)| DomainEntry {
            domain,
            sources,
            confidence,
        })
        .collect();

    Ok(LookupResult {
        ip: ip.into(),
        sources: config.sources.clone(),
        verified: config.verify,
        count,
        domains,
        notes,
    })
}

fn confidence_for_sources(sources: &[String], verified: bool) -> u8 {
    let has_passive = sources.iter().any(|s| s == "passive-dns");
    let has_ptr = sources.iter().any(|s| s == "ptr");
    let has_reverse_ip = sources.iter().any(|s| s == "hackertarget");
    let has_stale = sources.iter().any(|s| s.ends_with("-stale"));

    let mut score: u8 = if has_passive {
        90
    } else if has_ptr && has_reverse_ip {
        65
    } else if has_reverse_ip {
        55
    } else if has_ptr {
        40
    } else {
        25
    };

    if verified {
        score = (score + 15).min(100);
    }
    if has_stale {
        score = score.saturating_sub(25);
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_prefers_passive_dns_for_firewall_attribution() {
        assert!(
            confidence_for_sources(&["passive-dns".into()], false)
                > confidence_for_sources(&["hackertarget".into(), "ptr".into()], false)
        );
    }

    #[test]
    fn confidence_penalizes_stale_external_cache() {
        assert!(
            confidence_for_sources(&["hackertarget".into()], false)
                > confidence_for_sources(&["hackertarget-stale".into()], false)
        );
    }
}
