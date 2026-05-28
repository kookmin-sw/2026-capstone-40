use crate::fingerprint::{classify, hamming, PageFingerprint, Similarity};
use crate::resolver::PassiveDnsCache;
use crate::store::{self, Db, StoredFingerprint};

use super::fetch::{enrich_dns, fetch_html, fp_to_write, is_generic_page};

#[derive(Debug)]
pub enum ProbeVerdict {
    Match(String),
    NoMatch,
    NoBaseline,
    Unreachable,
}

/// Probe `domain`, save fingerprint, compare against any stored baseline from
/// `reference_domains` (tried in order — first with snapshots wins).
/// Uses cached fingerprint if one exists within `cache_secs` to avoid repeat fetches.
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

    // ── 1. Get or fetch the fingerprint for the suspicious domain ─────────────
    let probed: PageFingerprint = if cache_secs > 0
        && let Ok(conn) = db.lock()
        && let Some(ts) = store::last_probe_ts(&conn, domain)
        && now - ts < cache_secs
    {
        // Recent probe: reuse the stored fingerprint if one exists.
        if let Some(sf) = store::get_fingerprints(&conn, domain, 1).into_iter().next() {
            log::debug!("probe: cache hit for {domain} (age {}s)", now - ts);
            drop(conn);
            stored_to_fp(sf)
        } else {
            // Probe ran recently but stored nothing (unreachable or generic).
            log::debug!("probe: cached unreachable for {domain} (age {}s)", now - ts);
            return ProbeVerdict::Unreachable;
        }
    } else {
        // Cache miss — fetch fresh HTML.
        let html = match fetch_html(domain) {
            Some(h) => h,
            None => {
                if let Ok(conn) = db.lock() {
                    store::record_probe_run(&conn, domain, now, false).ok();
                }
                return ProbeVerdict::Unreachable;
            }
        };
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

        let html_hash = format!("{:016x}", fp.simhash as u64);
        if let Ok(conn) = db.lock() {
            let fw = fp_to_write(&fp, &html_hash);
            store::save_fingerprint(&conn, domain, &fw, now).ok();
            store::record_probe_run(&conn, domain, now, true).ok();
        }
        fp
    };

    // ── 2. Compare against reference baselines ────────────────────────────────
    compare_refs(&probed, domain, reference_domains, db)
}

fn compare_refs(
    probed: &PageFingerprint,
    domain: &str,
    reference_domains: &[String],
    db: &Db,
) -> ProbeVerdict {
    // If domain IS one of the reference domains, compare against its own stored
    // baseline to confirm identity.
    if reference_domains.iter().any(|r| r.as_str() == domain) {
        if let Ok(conn) = db.lock()
            && let Some(sf) = store::get_fingerprints(&conn, domain, 1).into_iter().next()
        {
            let base = stored_to_fp(sf);
            if let Some((label, dist)) = match_label(probed, &base) {
                return ProbeVerdict::Match(format!("[{}match dist={} ref={}]", label, dist, domain));
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
        for sf in baselines {
            let base = stored_to_fp(sf);
            if let Some((label, dist)) = match_label(probed, &base) {
                log::info!("probe: '{domain}' vs '{reference_domain}' → {label} dist={dist}");
                return ProbeVerdict::Match(format!(
                    "[{}match dist={} ref={}]",
                    label, dist, reference_domain
                ));
            }
        }
        log::info!("probe: '{domain}' vs '{reference_domain}' → no match");
        return ProbeVerdict::NoMatch;
    }

    log::debug!("probe: no baselines for any reference domain");
    ProbeVerdict::NoBaseline
}

/// Map the shape-content classification to a probe match label + simhash distance.
/// Uses `classify()` (0.85·tag-bigram-Jaccard + 0.15·content, gated on shape) so a
/// simhash collision on a sparse page can no longer fake an EXACT match.
fn match_label(probed: &PageFingerprint, baseline: &PageFingerprint) -> Option<(&'static str, u32)> {
    // Without structural signal on BOTH sides the shape gate can't apply, and
    // jaccard's empty-set identity (∅∩∅ → 1.0) would fake an EXACT match. Stale
    // pre-migration baselines have no tag_bigrams — refuse to match them so they
    // get re-probed with a full fingerprint instead of false-confirming.
    if probed.tag_bigrams.is_empty() || baseline.tag_bigrams.is_empty() {
        return None;
    }
    let dist = hamming(probed.simhash, baseline.simhash);
    match classify(probed, baseline) {
        Similarity::Identical => Some(("EXACT", dist)),
        Similarity::High => Some(("HIGH", dist)),
        Similarity::Moderate | Similarity::Corroborated => Some(("MODERATE", dist)),
        Similarity::Distinct => None,
    }
}

fn stored_to_fp(sf: StoredFingerprint) -> PageFingerprint {
    PageFingerprint {
        simhash: sf.simhash as i64,
        title: sf.title,
        h1: sf.h1,
        word_tokens: sf.word_tokens,
        tag_bigrams: sf.tag_bigrams,
        css_classes: sf.css_classes,
    }
}
