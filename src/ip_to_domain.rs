use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::paths::expand_tilde;
use crate::time::now_secs;

pub const DEFAULT_DNS_CACHE: &str = "~/.cache/capstone/dns_cache.sqlite3";

use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::Value;

// ── domain helpers ────────────────────────────────────────────────────────────

fn looks_like_domain(s: &str) -> bool {
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

fn norm_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_lowercase()
}

// ── SQLite cache ──────────────────────────────────────────────────────────────

struct Cache {
    conn: Connection,
}

impl Cache {
    fn new(path: &str) -> rusqlite::Result<Self> {
        let path = expand_tilde(path);
        if let Some(p) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(p).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                provider TEXT NOT NULL,
                key      TEXT NOT NULL,
                ts       INTEGER NOT NULL,
                status   INTEGER NOT NULL,
                body     BLOB,
                PRIMARY KEY (provider, key)
            );",
        )?;
        Ok(Self { conn })
    }

    fn get(&self, provider: &str, key: &str) -> Option<(i64, i64, Option<Vec<u8>>)> {
        self.conn
            .query_row(
                "SELECT ts, status, body FROM cache WHERE provider=?1 AND key=?2",
                params![provider, key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .ok()
    }

    fn put(&self, provider: &str, key: &str, ts: i64, status: i64, body: Option<&[u8]>) {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO cache(provider,key,ts,status,body) VALUES(?1,?2,?3,?4,?5)",
                params![provider, key, ts, status, body],
            )
            .ok();
    }
}

// ---- provider result ----

#[derive(Default)]
struct ProviderResult {
    provider: String,
    domains: HashSet<String>,
    note: Option<String>,
    cache_stale: bool,
}

fn sorted_vec(set: &HashSet<String>) -> Vec<String> {
    let mut v: Vec<_> = set.iter().cloned().collect();
    v.sort();
    v
}

// ---- PTR provider ----

fn ptr_fetch(ip: &str, cache: &Cache) -> ProviderResult {
    const TTL: i64 = 6 * 3600;
    let now = now_secs();

    if let Some((ts, _, Some(body))) = cache.get("ptr", ip) {
        if now - ts < TTL {
            if let Ok(s) = String::from_utf8(body) {
                if let Ok(v) = serde_json::from_str::<Value>(&s) {
                    let domains = v["domains"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_str())
                        .map(String::from)
                        .collect();
                    return ProviderResult {
                        provider: "ptr".into(),
                        domains,
                        ..Default::default()
                    };
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

    ProviderResult {
        provider: "ptr".into(),
        domains,
        ..Default::default()
    }
}

// ---- HackerTarget provider ----

static HT_LAST: OnceLock<Mutex<Instant>> = OnceLock::new();

fn hackertarget_fetch(ip: &str, cache: &Cache, timeout_s: f64) -> ProviderResult {
    const TTL: i64 = 24 * 3600;
    let now = now_secs();
    let cached = cache.get("hackertarget", ip);

    if let Some((ts, _, Some(ref body))) = cached {
        if now - ts < TTL {
            let domains = String::from_utf8_lossy(body)
                .lines()
                .filter(|l| looks_like_domain(l))
                .map(|l| norm_domain(l))
                .collect();
            return ProviderResult {
                provider: "hackertarget".into(),
                domains,
                ..Default::default()
            };
        }
    }

    // polite 1-second throttle between live calls
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
            let mut domains: HashSet<String> = HashSet::new();
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
        Err(e) => stale_or_empty("hackertarget", cached.as_ref(), format!("request failed: {e}")),
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
            .map(|l| norm_domain(l))
            .collect();
        return ProviderResult {
            provider: provider.into(),
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

// ---- DoH verification (Cloudflare dns-json) ----

fn doh_lookup(name: &str, rtype: &str, timeout_s: f64) -> HashSet<String> {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type={}",
        name, rtype
    );
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout_s))
        .build();
    match agent
        .get(&url)
        .set("Accept", "application/dns-json")
        .call()
    {
        Ok(resp) => resp
            .into_json::<Value>()
            .ok()
            .and_then(|v| v["Answer"].as_array().cloned())
            .into_iter()
            .flatten()
            .filter_map(|a| a["data"].as_str().map(|s| s.trim().to_string()))
            .collect(),
        Err(_) => HashSet::new(),
    }
}

pub fn verify_domains(
    domains: &HashSet<String>,
    target_ip: &str,
    timeout_s: f64,
) -> HashSet<String> {
    let target: IpAddr = match target_ip.parse() {
        Ok(a) => a,
        Err(_) => return HashSet::new(),
    };

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let handles: Vec<_> = domains
        .iter()
        .cloned()
        .map(|d| {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut addrs = doh_lookup(&d, "A", timeout_s);
                addrs.extend(doh_lookup(&d, "AAAA", timeout_s));
                let ok = addrs
                    .iter()
                    .any(|a| a.parse::<IpAddr>().ok() == Some(target));
                if ok {
                    tx.send(d).ok();
                }
            })
        })
        .collect();

    drop(tx);
    for h in handles {
        h.join().ok();
    }
    rx.iter().collect()
}

// ---- public API ----

pub struct LookupConfig {
    pub sources: Vec<String>,
    pub verify: bool,
    pub timeout_s: f64,
    pub cache_path: String,
}

impl Default for LookupConfig {
    fn default() -> Self {
        Self {
            sources: vec!["ptr".into(), "hackertarget".into()],
            verify: false,
            timeout_s: 15.0,
            cache_path: "~/.cache/reverse_ip_domains/cache.sqlite3".into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DomainEntry {
    pub domain: String,
    pub sources: Vec<String>,
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

pub fn lookup(
    ip: &str,
    config: &LookupConfig,
) -> Result<LookupResult, Box<dyn std::error::Error>> {
    let cache = Cache::new(&config.cache_path)?;
    let mut all_domains: HashSet<String> = HashSet::new();
    let mut dom_sources: HashMap<String, HashSet<String>> = HashMap::new();
    let mut notes: Vec<String> = Vec::new();

    for source in &config.sources {
        let res = match source.as_str() {
            "ptr" => ptr_fetch(ip, &cache),
            "hackertarget" => hackertarget_fetch(ip, &cache, config.timeout_s),
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

    let mut sorted: Vec<String> = final_set.into_iter().collect();
    sorted.sort();

    let domains = sorted
        .iter()
        .map(|d| {
            let mut srcs: Vec<_> = dom_sources
                .get(d)
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            srcs.sort();
            DomainEntry {
                domain: d.clone(),
                sources: srcs,
            }
        })
        .collect();

    Ok(LookupResult {
        ip: ip.into(),
        sources: config.sources.clone(),
        verified: config.verify,
        count: sorted.len(),
        domains,
        notes,
    })
}
