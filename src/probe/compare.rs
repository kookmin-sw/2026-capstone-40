use std::net::IpAddr;
use std::time::Duration;

use crate::fingerprint::hamming;
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
        // Check cache first — covers both successful probes (has fingerprint) and
        // cached-unreachable (probe_run recorded but no fingerprint).
        if cache_secs > 0
            && let Ok(conn) = db.lock()
            && let Some(ts) = store::last_probe_ts(&conn, domain)
            && now - ts < cache_secs
        {
            // Recent probe: do we have a fingerprint?
            if let Some(fp) = store::get_fingerprints(&conn, domain, 1).into_iter().next() {
                log::debug!("probe: cache hit for {domain} (age {}s)", now - ts);
                let h = fp.simhash;
                drop(conn);
                return compare_refs(h as i64, domain, reference_domains, db);
            } else {
                // Probe ran recently but fetched nothing — still unreachable.
                log::debug!(
                    "probe: cached unreachable for {domain} (age {}s)",
                    now - ts
                );
                return ProbeVerdict::Unreachable;
                }
        }

        // Cache miss — fetch fresh HTML.
        let html = match fetch_html(domain) {
            Some(h) => h,
            None => {
                // Cache the unreachable result so we don't hammer the site every flow.
                if let Ok(conn) = db.lock() {
                    store::record_probe_run(&conn, domain, now, false).ok();
                }
                return ProbeVerdict::Unreachable;
            }
        };
        // Enrich passive DNS: resolve domain → IPs and inject into cache.
        enrich_dns(domain, passive_dns);
        let fp = crate::fingerprint::fingerprint(&html);

        // Skip storing fingerprint for generic default pages — they produce
        // stable but meaningless simhashes that cause false EXACT-match verdicts.
        if is_generic_page(fp.title.as_deref(), fp.h1.as_deref(), &fp, &html) {
            log::debug!("probe {domain}: generic/default page, skipping fingerprint");
            if let Ok(conn) = db.lock() {
                store::record_probe_run(&conn, domain, now, true).ok();
            }
            return ProbeVerdict::NoBaseline;
        }

        let hash = fp.simhash as u64;
        let html_hash = format!("{:016x}", hash);

        if let Ok(conn) = db.lock() {
            store::save_fingerprint(
                &conn,
                domain,
                fp.title.as_deref(),
                fp.h1.as_deref(),
                hash,
                &html_hash,
                now,
            )
            .ok();
            store::record_probe_run(&conn, domain, now, true).ok();
        }
        hash
    };

    // ── 2. Compare against reference baselines ────────────────────────────────
    compare_refs(simhash as i64, domain, reference_domains, db)
}

fn compare_refs(simhash: i64, domain: &str, reference_domains: &[String], db: &Db) -> ProbeVerdict {
    // If domain IS one of the reference domains, it's the original site itself.
    // Compare its simhash against its own stored baseline to confirm identity.
    if reference_domains.iter().any(|r| r.as_str() == domain) {
        if let Ok(conn) = db.lock() {
            let baselines = store::get_fingerprints(&conn, domain, 1);
            if let Some(b) = baselines.first() {
                let dist = crate::fingerprint::hamming(simhash, b.simhash as i64);
                let label = match dist {
                    0 => "EXACT",
                    1..=3 => "HIGH",
                    4..=6 => "MODERATE",
                    _ => "",
                };
                if !label.is_empty() {
                    return ProbeVerdict::Match(format!(
                        "[{}match dist={} ref={}]",
                        label, dist, domain
                    ));
                }
            }
        }
        return ProbeVerdict::NoBaseline;
    }

    let refs: Vec<&String> = reference_domains
        .iter()
        .filter(|r| r.as_str() != domain && !r.is_empty())
        .collect();

    if refs.is_empty() {
        return ProbeVerdict::NoBaseline;
    }

    let conn = match db.lock() {
        Ok(c) => c,
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
                0 => "EXACT",
                1..=3 => "HIGH",
                4..=6 => "MODERATE",
                _ => continue,
            };
            log::info!("probe: '{domain}' vs '{reference_domain}' → {label} dist={dist}");
            return ProbeVerdict::Match(format!(
                "[{}match dist={} ref={}]",
                label, dist, reference_domain
            ));
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
    let Some(html) = fetch_html(domain) else {
        return;
    };
    enrich_dns(domain, passive_dns);
    // Persist domain→IP mappings so reverse lookups stay current after DNS changes.
    sync_domain_ips_to_db(domain, db, now);
    let fp = crate::fingerprint::fingerprint(&html);
    let simhash = fp.simhash as u64;
    let html_hash = format!("{:016x}", simhash);
    let Ok(conn) = db.lock() else { return };
    store::save_fingerprint(
        &conn,
        domain,
        fp.title.as_deref(),
        fp.h1.as_deref(),
        simhash,
        &html_hash,
        now,
    )
    .ok();
    store::record_probe_run(&conn, domain, now, true).ok();
    log::info!("baseline: saved {domain} simhash={simhash:016x}");
}

/// Resolve domain → IPs via system DNS and inject into passive DNS cache.
/// Gives the resolver a direct forward-confirmed ip→domain mapping from our probe.
fn enrich_dns(domain: &str, passive_dns: Option<&PassiveDnsCache>) {
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
/// Keeps reverse lookups correct when a domain's DNS changes (e.g. CDN migration).
fn sync_domain_ips_to_db(domain: &str, db: &Db, now: i64) {
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

fn fetch_html(domain: &str) -> Option<String> {
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
                r.into_string().map_err(|e| {
                    ureq::Error::from(std::io::Error::other(e))
                })
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

/// Detect generic server default pages that produce meaningless fingerprints.
/// These include web-server test pages, blank sites, and error pages that
/// would generate stable but content-free simhashes, causing false EXACT matches.
/// Detect generic/default pages using multi-signal richness scoring.
///
/// Mirrors the ShapeContentWeighted insight: real sites have rich DOM structure
/// (many tag bigrams), diverse CSS classes, and meaningful text. Generic server
/// default pages, bot challenges, and blank pages fail all three.
///
/// Additionally checks title/h1 keyword overlap with known generic page vocabulary
/// using token intersection (not exact match) so language variants are covered.
fn is_generic_page(
    title: Option<&str>,
    h1: Option<&str>,
    fp: &crate::fingerprint::PageFingerprint,
    html: &str,
) -> bool {
    // ── 1. Structural richness from fingerprint signals ───────────────────────
    // Real sites: tag_bigrams ≥ 8, word_tokens ≥ 15, css_classes ≥ 2.
    // All three signals must be weak to call it generic (avoids false positives
    // on minimalist/short sites that still have real CSS or structure).
    let structurally_poor =
        fp.tag_bigrams.len() < 8 && fp.word_tokens.len() < 15 && fp.css_classes.len() < 2;

    // ── 2. Title/h1 keyword signal ────────────────────────────────────────────
    // Token-level match against generic page vocabulary.
    // "Welcome to nginx!" → tokens {"welcome","to","nginx"} → hits {"nginx"}.
    // "Atención requerida | Cloudflare" → hits {"cloudflare","attention"}.
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

    // ── 3. Decision ───────────────────────────────────────────────────────────
    // Generic if: structurally poor AND (keyword hit OR nearly empty html).
    // OR: keyword hit alone on a very sparse page (handles error pages with rich CSS).
    if html.len() < 100 {
        return true;
    }
    if structurally_poor && (keyword_hit || html.len() < 500) {
        return true;
    }
    // High-confidence keyword hit even on fuller pages (Cloudflare CAPTCHA pages
    // can be quite large but are clearly generic).
    if keyword_hit && fp.word_tokens.len() < 30 {
        return true;
    }
    false
}
