use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::time::now_secs;

use super::cache::Cache;
use super::types::{cache_fresh, looks_like_domain, norm_domain, sorted_vec, ProviderResult};

static HT_LAST: OnceLock<Mutex<Instant>> = OnceLock::new();

pub fn fetch(ip: &str, cache: &Cache, timeout_s: f64, ttl_s: i64) -> ProviderResult {
    let now = now_secs();
    let cached = cache.get("hackertarget", ip);

    if let Some((ts, _, Some(ref body))) = cached {
        if cache_fresh(now, ts, ttl_s) {
            let domains = String::from_utf8_lossy(body)
                .lines()
                .filter(|l| looks_like_domain(l))
                .map(norm_domain)
                .collect();
            return ProviderResult {
                provider: "hackertarget".into(),
                domains,
                ..Default::default()
            };
        }
    }

    // 1-second throttle between live calls
    let last = HT_LAST.get_or_init(|| Mutex::new(Instant::now() - Duration::from_secs(10)));
    {
        let mut guard = last.lock().unwrap();
        let elapsed = guard.elapsed();
        if elapsed < Duration::from_secs(1) {
            thread::sleep(Duration::from_secs(1) - elapsed);
        }
        *guard = Instant::now();
    }

    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={}", ip);
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout_s))
        .build();

    match agent.get(&url).call() {
        Ok(resp) => {
            let text = resp.into_string().unwrap_or_default();
            let trimmed = text.trim();
            if trimmed.to_ascii_lowercase().starts_with("error")
                || trimmed.to_ascii_lowercase().contains("quota")
            {
                let note: String = trimmed.chars().take(200).collect();
                return stale_or_empty("hackertarget", cached.as_ref(), note);
            }
            let mut domains = std::collections::HashSet::new();
            for line in trimmed.lines() {
                let d = line.trim().splitn(2, ',').next().unwrap_or("").trim();
                if looks_like_domain(d) {
                    domains.insert(norm_domain(d));
                }
            }
            cache.put(
                "hackertarget",
                ip,
                now,
                200,
                Some(sorted_vec(&domains).join("\n").as_bytes()),
            );
            ProviderResult {
                provider: "hackertarget".into(),
                domains,
                ..Default::default()
            }
        }
        Err(e) => stale_or_empty(
            "hackertarget",
            cached.as_ref(),
            format!("request failed: {e}"),
        ),
    }
}

fn stale_or_empty(
    provider: &str,
    cached: Option<&(i64, i64, Option<Vec<u8>>)>,
    note: String,
) -> ProviderResult {
    if let Some((_, _, Some(body))) = cached {
        let domains = String::from_utf8_lossy(body)
            .lines()
            .filter(|l| looks_like_domain(l))
            .map(norm_domain)
            .collect();
        return ProviderResult {
            provider: format!("{provider}-stale"),
            domains,
            note: Some(note),
            cache_stale: true,
        };
    }
    ProviderResult {
        provider: provider.into(),
        note: Some(note),
        ..Default::default()
    }
}
