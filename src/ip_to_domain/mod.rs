//! IP → domain resolution pipeline.
//!
//! Three providers, tried in order of `LookupConfig::sources`:
//!   - `passive-dns`   — in-process cache of DNS A/AAAA responses sniffed off wire (fastest)
//!   - `ptr`           — reverse DNS (OS resolver)
//!   - `hackertarget`  — HackerTarget reverse-IP API
//!
//! Results are merged across providers. Optional DoH verification filters to
//! only domains whose forward resolution matches the queried IP.

mod cache;
mod hackertarget;
mod passive_dns;
mod ptr;
mod types;
mod verify;

use std::collections::{HashMap, HashSet};

pub use passive_dns::PassiveDnsCache;
pub use types::{DomainEntry, LookupResult};

use cache::Cache;
use types::{cache_ttl_secs, ProviderResult};
use verify::verify_domains;

pub const DEFAULT_DNS_CACHE: &str = "~/.cache/capstone/dns_cache.sqlite3";
pub const DEFAULT_CACHE_TTL_DAYS: u64 = 7;

// ── config ────────────────────────────────────────────────────────────────────

pub struct LookupConfig {
    pub sources: Vec<String>,
    pub verify: bool,
    pub timeout_s: f64,
    pub cache_path: String,
    pub cache_ttl_days: u64,
    /// Passive DNS cache shared with the capture thread. Set to `Some` to
    /// enable the `passive-dns` provider.
    pub passive_dns: Option<PassiveDnsCache>,
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
        }
    }
}

// ── public API ────────────────────────────────────────────────────────────────

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
            "ptr"          => ptr::fetch(ip, &cache, ttl_s),
            "hackertarget" => hackertarget::fetch(ip, &cache, config.timeout_s, ttl_s),
            other => {
                notes.push(format!("unknown source '{other}'"));
                continue;
            }
        };

        if let Some(ref n) = res.note {
            let suffix = if res.cache_stale { " (stale cache)" } else { "" };
            notes.push(format!("{}: {n}{suffix}", res.provider));
        }
        for d in res.domains {
            dom_sources.entry(d.clone()).or_default().insert(res.provider.clone());
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

    let mut sorted: Vec<String> = final_set.into_iter().collect();
    sorted.sort();

    let domains = sorted.iter().map(|d| {
        let mut srcs: Vec<_> = dom_sources.get(d).into_iter().flatten().cloned().collect();
        srcs.sort();
        DomainEntry { domain: d.clone(), sources: srcs }
    }).collect();

    Ok(LookupResult {
        ip: ip.into(),
        sources: config.sources.clone(),
        verified: config.verify,
        count: sorted.len(),
        domains,
        notes,
    })
}
