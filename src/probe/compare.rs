use std::net::IpAddr;
use std::time::Duration;

use crate::fingerprint::{self, hamming};
use crate::resolver::PassiveDnsCache;
use crate::store::{self, Db};

#[derive(Debug)]
pub enum ProbeVerdict {
    Match(String),
    NoMatch,
    NoBaseline,
    Unreachable,
}

/// Probe `domain`, save fingerprint, compare against any stored baseline from
/// `reference_domains` (tried in order — first with snapshots wins).
/// Uses cached simhash if one exists within `cache_secs` to avoid repeat fetches.
pub fn probe_and_compare(
    domain: &str,
    reference_domains: &[String],
    db: &Db,
    now: i64,
    cache_secs: i64,
    passive_dns: Option<&PassiveDnsCache>,
) -> ProbeVerdict {
    if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
        return ProbeVerdict::NoBaseline;
    }

    // ── 1. Get or fetch simhash for the suspicious domain ────────────────────

    let simhash: u64 = {
        // Check cache first.
        if cache_secs > 0 {
            if let Ok(conn) = db.lock() {
                if let Some(fp) = store::get_fingerprints(&conn, domain, 1).into_iter().next() {
                    if now - fp.ts < cache_secs {
                        log::debug!("probe: cache hit for {domain} (age {}s)", now - fp.ts);
                        let h = fp.simhash;
                        drop(conn);
                        return compare_refs(h as i64, domain, reference_domains, db);
                    }
                }
            }
        }

        // Cache miss — fetch fresh HTML.
        let html = match fetch_html(domain) {
            Some(h) => h,
            None    => return ProbeVerdict::Unreachable,
        };
        // Enrich passive DNS: resolve domain → IPs and inject into cache.
        enrich_dns(domain, passive_dns);
        let fp = crate::fingerprint::fingerprint(&html);
        let hash = fp.simhash as u64;
        let html_hash = format!("{:016x}", hash);

        // Race-dedup: if another thread saved within the last 60s, skip save.
        let already_saved = if let Ok(conn) = db.lock() {
            store::last_probe_ts(&conn, domain)
                .map_or(false, |ts| now - ts < 60)
        } else {
            false
        };

        if !already_saved {
            if let Ok(conn) = db.lock() {
                store::save_fingerprint(
                    &conn, domain,
                    fp.title.as_deref(), fp.h1.as_deref(),
                    hash, &html_hash, now,
                ).ok();
                store::record_probe_run(&conn, domain, now, true).ok();
            }
        }
        hash
    };

    // ── 2. Compare against reference baselines ────────────────────────────────
    compare_refs(simhash as i64, domain, reference_domains, db)
}

fn compare_refs(
    simhash: i64,
    domain: &str,
    reference_domains: &[String],
    db: &Db,
) -> ProbeVerdict {
    let refs: Vec<&String> = reference_domains.iter()
        .filter(|r| r.as_str() != domain && !r.is_empty())
        .collect();

    if refs.is_empty() {
        return ProbeVerdict::NoBaseline;
    }

    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return ProbeVerdict::NoBaseline,
    };

    for reference_domain in &refs {
        let baselines = store::get_fingerprints(&conn, reference_domain, 5);
        if baselines.is_empty() {
            continue;
        }
        for b in &baselines {
            let dist = hamming(simhash, b.simhash as i64);
            let label = match dist {
                0      => "EXACT",
                1..=3  => "HIGH",
                4..=6  => "MODERATE",
                _      => continue,
            };
            log::info!("probe: '{domain}' vs '{reference_domain}' → {label} dist={dist}");
            return ProbeVerdict::Match(
                format!("[{}match dist={} ref={}]", label, dist, reference_domain)
            );
        }
        log::info!("probe: '{domain}' vs '{reference_domain}' → no match");
        return ProbeVerdict::NoMatch;
    }

    log::debug!("probe: no baselines for any reference domain");
    ProbeVerdict::NoBaseline
}

/// Probe domain for baseline storage only — no comparison.
pub fn probe_baseline(domain: &str, db: &Db, now: i64, passive_dns: Option<&PassiveDnsCache>) {
    if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let Some(html) = fetch_html(domain) else { return };
    enrich_dns(domain, passive_dns);
    let fp = crate::fingerprint::fingerprint(&html);
    let simhash = fp.simhash as u64;
    let html_hash = format!("{:016x}", simhash);
    let Ok(conn) = db.lock() else { return };
    store::save_fingerprint(
        &conn, domain,
        fp.title.as_deref(), fp.h1.as_deref(),
        simhash, &html_hash, now,
    ).ok();
    store::record_probe_run(&conn, domain, now, true).ok();
    log::info!("baseline: saved {domain} simhash={simhash:016x}");
}

/// Resolve domain → IPs via system DNS and inject into passive DNS cache.
/// Gives the resolver a direct forward-confirmed ip→domain mapping from our probe.
fn enrich_dns(domain: &str, passive_dns: Option<&PassiveDnsCache>) {
    let Some(cache) = passive_dns else { return };
    use std::net::ToSocketAddrs;
    let addrs = match (domain, 443u16).to_socket_addrs() {
        Ok(a)  => a,
        Err(_) => return,
    };
    for addr in addrs {
        let ip: IpAddr = addr.ip();
        log::debug!("probe dns: {domain} → {ip}");
        cache.insert(ip, domain.to_string(), 3600);
    }
}

fn fetch_html(domain: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build();
    for scheme in &["https", "http"] {
        let url = format!("{scheme}://{domain}");
        match agent.get(&url)
            .set("User-Agent", "Mozilla/5.0 (compatible; Capstone/1.0)")
            .call()
            .and_then(|r| r.into_string()
                .map_err(|e| ureq::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e))))
        {
            Ok(h) => {
                log::debug!("probe {domain}: fetched via {scheme} ({} bytes)", h.len());
                return Some(h);
            }
            Err(e) => log::warn!("probe {domain} [{scheme}] failed: {e}"),
        }
    }
    None
}
