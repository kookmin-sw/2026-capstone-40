use std::collections::HashSet;
use std::net::IpAddr;

use serde_json::Value;

use crate::time::now_secs;

use super::cache::Cache;
use super::types::{cache_fresh, looks_like_domain, norm_domain, sorted_vec, ProviderResult};

pub fn fetch(ip: &str, cache: &Cache, ttl_s: i64) -> ProviderResult {
    let now = now_secs();

    if let Some((ts, _, Some(body))) = cache.get("ptr", ip) {
        if cache_fresh(now, ts, ttl_s) {
            if let Ok(s) = String::from_utf8(body) {
                if let Ok(v) = serde_json::from_str::<Value>(&s) {
                    let domains = v["domains"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_str())
                        .map(String::from)
                        .collect();
                    return ProviderResult { provider: "ptr".into(), domains, ..Default::default() };
                }
            }
        }
    }

    let mut domains: HashSet<String> = HashSet::new();
    if let Ok(addr) = ip.parse::<IpAddr>() {
        if let Ok(host) = dns_lookup::lookup_addr(&addr) {
            if looks_like_domain(&host) {
                domains.insert(norm_domain(&host));
            }
        }
    }

    let body = serde_json::json!({ "domains": sorted_vec(&domains) }).to_string();
    cache.put("ptr", ip, now, 200, Some(body.as_bytes()));

    ProviderResult { provider: "ptr".into(), domains, ..Default::default() }
}
