//! Passive DNS cache: in-memory IP→domain mapping built from sniffed DNS responses.
//!
//! The capture thread calls `PassiveDnsCache::ingest_frame()` for every packet.
//! The resolver lookup thread calls `PassiveDnsCache::lookup()`.
//!
//! Records expire lazily after `ttl_s` seconds (clamped to 30–3600 s).
//! Wire-format parsing lives in `dns_parser`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::dns_parser::parse_dns_from_frame;
use super::types::ProviderResult;

#[derive(Clone)]
pub struct PassiveDnsCache(Arc<RwLock<HashMap<IpAddr, Vec<Record>>>>);

#[derive(Clone)]
struct Record {
    domain: String,
    expires: Instant,
}

impl PassiveDnsCache {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Insert a (ip, domain) mapping observed from a DNS response.
    pub fn insert(&self, ip: IpAddr, domain: String, ttl_s: u32) {
        let ttl = Duration::from_secs(ttl_s.clamp(30, 3600) as u64);
        let rec = Record {
            domain,
            expires: Instant::now() + ttl,
        };
        if let Ok(mut m) = self.0.write() {
            m.entry(ip).or_default().push(rec);
        }
    }

    /// Return fresh domain names for an IP. Expired records are lazily removed.
    pub fn lookup(&self, ip: &IpAddr) -> Vec<String> {
        let now = Instant::now();
        if let Ok(mut m) = self.0.write()
            && let Some(recs) = m.get_mut(ip)
        {
            recs.retain(|r| r.expires > now);
            return recs.iter().map(|r| r.domain.clone()).collect();
        }
        vec![]
    }

    /// Parse raw Ethernet frame, extract any DNS A/AAAA answers, insert them.
    pub fn ingest_frame(&self, data: &[u8]) {
        for (ip, domain, ttl) in parse_dns_from_frame(data) {
            self.insert(ip, domain, ttl);
        }
    }

    pub fn as_provider(&self, ip: &str) -> ProviderResult {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => {
                return ProviderResult {
                    provider: "passive-dns".into(),
                    ..Default::default()
                };
            }
        };
        let domains = self.lookup(&addr).into_iter().collect();
        ProviderResult {
            provider: "passive-dns".into(),
            domains,
            ..Default::default()
        }
    }
}

impl Default for PassiveDnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_lookup_expiry() {
        let c = PassiveDnsCache::new();
        c.insert("1.2.3.4".parse().unwrap(), "example.com".into(), 3600);
        let hits = c.lookup(&"1.2.3.4".parse().unwrap());
        assert!(hits.contains(&"example.com".to_string()));
        let miss = c.lookup(&"9.9.9.9".parse().unwrap());
        assert!(miss.is_empty());
    }
}
