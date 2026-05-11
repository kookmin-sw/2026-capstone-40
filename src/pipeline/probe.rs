use std::time::Duration;

use crate::html_fingerprint::{self, hamming};
use crate::store::{self, Db};

/// Fetch HTML from domain, compute SimHash fingerprint, compare with stored
/// snapshots. Saves the new snapshot. Returns similarity annotation if notable.
pub fn probe_and_compare(domain: &str, db: &Db, now: i64) -> Option<String> {
    // Skip raw IPs and non-domain strings.
    if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let html = fetch_html(domain)?;
    let fp = html_fingerprint::fingerprint(&html);
    let simhash = fp.simhash;
    let html_hash = format!("{:016x}", simhash);

    let conn = db.lock().ok()?;
    store::save_fingerprint(
        &conn, domain,
        fp.title.as_deref(), fp.h1.as_deref(),
        simhash as u64, &html_hash, now,
    ).ok();
    store::record_probe_run(&conn, domain, now, true).ok();

    // Compare against previous snapshots (skip the one we just wrote).
    let prev = store::get_fingerprints(&conn, domain, 5);
    for p in &prev {
        if p.html_hash == html_hash && p.ts == now { continue; }
        let dist = hamming(simhash as i64, p.simhash as i64);
        let label = match dist {
            0 => "EXACT",
            1..=3 => "HIGH",
            4..=6 => "MODERATE",
            _ => continue,
        };
        return Some(format!("[{}match dist={}]", label, dist));
    }
    None
}

fn fetch_html(domain: &str) -> Option<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build();
    let url = format!("https://{domain}");
    match agent.get(&url)
        .set("User-Agent", "Mozilla/5.0 (compatible; Capstone/1.0)")
        .call()
        .and_then(|r| r.into_string()
            .map_err(|e| ureq::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e))))
    {
        Ok(h) => Some(h),
        Err(e) => { log::debug!("probe {domain} failed: {e}"); None }
    }
}
