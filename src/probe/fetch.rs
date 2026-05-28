use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use crate::fingerprint::PageFingerprint;
use crate::resolver::PassiveDnsCache;
use crate::store::{self, Db, FingerprintWrite};

/// Probe domain for baseline storage only — no comparison.
pub fn probe_baseline(domain: &str, db: &Db, now: i64, passive_dns: Option<&PassiveDnsCache>) {
    if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let Some(html) = fetch_html(domain) else {
        return;
    };
    enrich_dns(domain, passive_dns);
    sync_domain_ips_to_db(domain, db, now);
    let fp = crate::fingerprint::fingerprint(&html);

    // Never store a generic/default page as a baseline — they produce stable but
    // content-free simhashes that other generic pages match at dist 0, yielding
    // false EXACT-match criticals. Live probe filters these too; the baseline
    // path must filter symmetrically or the cache poisons every comparison.
    if is_generic_page(fp.title.as_deref(), fp.h1.as_deref(), &fp, &html) {
        log::debug!("baseline {domain}: generic/default page, skipping fingerprint");
        if let Ok(conn) = db.lock() {
            store::record_probe_run(&conn, domain, now, true).ok();
        }
        return;
    }

    let simhash = fp.simhash as u64;
    let html_hash = format!("{:016x}", simhash);
    let Ok(conn) = db.lock() else { return };
    let fw = fp_to_write(&fp, &html_hash);
    store::save_fingerprint(&conn, domain, &fw, now).ok();
    store::record_probe_run(&conn, domain, now, true).ok();
    log::info!("baseline: saved {domain} simhash={simhash:016x}");
}

/// Build the snapshots-table payload from a fingerprint, joining set fields with
/// newlines. Shared by the baseline and live-compare probe paths.
pub(crate) fn fp_to_write<'a>(fp: &'a PageFingerprint, html_hash: &'a str) -> FingerprintWrite<'a> {
    FingerprintWrite {
        title: fp.title.as_deref(),
        h1: fp.h1.as_deref(),
        simhash: fp.simhash as u64,
        html_hash,
        tag_bigrams: join_set(&fp.tag_bigrams),
        css_classes: join_set(&fp.css_classes),
        word_tokens: join_set(&fp.word_tokens),
    }
}

fn join_set(s: &HashSet<String>) -> String {
    let mut v: Vec<&str> = s.iter().map(String::as_str).collect();
    v.sort_unstable();
    v.join("\n")
}

/// Resolve domain → IPs via system DNS and inject into passive DNS cache.
pub(crate) fn enrich_dns(domain: &str, passive_dns: Option<&PassiveDnsCache>) {
    let Some(cache) = passive_dns else { return };
    use std::net::ToSocketAddrs;
    let addrs = match (domain, 443u16).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return,
    };
    for addr in addrs {
        let ip: IpAddr = addr.ip();
        log::debug!("probe dns: {domain} → {ip}");
        cache.insert(ip, domain.to_string(), 3600);
    }
}

/// Resolve domain → current IPs and persist to domain_ips table.
pub(crate) fn sync_domain_ips_to_db(domain: &str, db: &Db, now: i64) {
    use std::net::ToSocketAddrs;
    let addrs = match (domain, 443u16).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return,
    };
    for addr in addrs {
        let ip = addr.ip().to_string();
        if let Ok(conn) = db.lock() {
            store::upsert_domain(&conn, domain, &ip, now).ok();
        }
    }
}

pub(crate) fn fetch_html(domain: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build();
    for scheme in &["https", "http"] {
        let url = format!("{scheme}://{domain}");
        match agent
            .get(&url)
            .set("User-Agent", "Mozilla/5.0 (compatible; Capstone/1.0)")
            .call()
            .and_then(|r| {
                r.into_string()
                    .map_err(|e| ureq::Error::from(std::io::Error::other(e)))
            }) {
            Ok(h) => {
                log::debug!("probe {domain}: fetched via {scheme} ({} bytes)", h.len());
                return Some(h);
            }
            Err(e) => log::warn!("probe {domain} [{scheme}] failed: {e}"),
        }
    }
    None
}

/// Detect generic/default pages that produce meaningless fingerprints.
///
/// Real sites have rich DOM structure (many tag bigrams), diverse CSS classes,
/// and meaningful text. Generic server default pages, bot challenges, and blank
/// pages fail all three. Additionally checks title/h1 keyword overlap with
/// known generic page vocabulary using token intersection.
pub(crate) fn is_generic_page(
    title: Option<&str>,
    h1: Option<&str>,
    fp: &crate::fingerprint::PageFingerprint,
    html: &str,
) -> bool {
    // Real sites: tag_bigrams ≥ 8, word_tokens ≥ 15, css_classes ≥ 2.
    // All three must be weak to call it generic (avoids false positives on
    // minimalist sites that still have real CSS or structure).
    let structurally_poor =
        fp.tag_bigrams.len() < 8 && fp.word_tokens.len() < 15 && fp.css_classes.len() < 2;

    const GENERIC_KEYWORDS: &[&str] = &[
        "nginx",
        "apache",
        "iis",
        "lighttpd",
        "forbidden",
        "unauthorized",
        "gateway",
        "timeout",
        "cloudflare",
        "captcha",
        "challenge",
        "verification",
        "just",
        "moment",
        "waiting",
        "checking",
        "default",
        "placeholder",
        "coming soon",
    ];
    let title_tokens: Vec<String> = title
        .unwrap_or("")
        .split_whitespace()
        .map(|w| {
            w.to_lowercase()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_string()
        })
        .collect();
    let h1_tokens: Vec<String> = h1
        .unwrap_or("")
        .split_whitespace()
        .map(|w| {
            w.to_lowercase()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_string()
        })
        .collect();

    let keyword_hit = title_tokens
        .iter()
        .chain(h1_tokens.iter())
        .any(|tok| GENERIC_KEYWORDS.iter().any(|kw| tok.contains(kw)));

    if html.len() < 100 {
        return true;
    }
    if structurally_poor && (keyword_hit || html.len() < 500) {
        return true;
    }
    // High-confidence keyword hit even on fuller pages (e.g. Cloudflare CAPTCHA
    // pages can be large but are clearly generic).
    if keyword_hit && fp.word_tokens.len() < 30 {
        return true;
    }
    false
}
