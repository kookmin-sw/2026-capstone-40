use crate::config::Config;
use crate::resolver::DEFAULT_DNS_CACHE;
use crate::resolver::{lookup, LookupConfig};
use crate::store::{self, Db};
use crate::time::now_secs;
use crate::web::{response, router::ProbeQuery, templates};
use askama::Template as _;

pub fn handle(query: Option<ProbeQuery>, config: &Config, db: &Db) -> response::HttpResponse {
    let probe_result = query.as_ref().map(|q| run_probe(q, config, db));

    let (query_ip, sources_ptr, sources_ht, verify) = match &query {
        Some(q) => (
            q.ip.clone(),
            q.sources.iter().any(|s| s == "ptr"),
            q.sources.iter().any(|s| s == "hackertarget"),
            q.verify,
        ),
        None => (String::new(), true, true, false),
    };

    let body = templates::ProbePage {
        page_title: "Probe",
        active: "probe",
        query_ip,
        sources_ptr,
        sources_ht,
        verify,
        probe_result,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}

fn run_probe(q: &ProbeQuery, config: &Config, db: &Db) -> templates::ProbeResult {
    let cache_path = config
        .ip_to_domain
        .cache_path
        .clone()
        .unwrap_or_else(|| DEFAULT_DNS_CACHE.into());

    let cfg = LookupConfig {
        sources: q.sources.clone(),
        verify: q.verify,
        timeout_s: config.probe.timeout_s,
        cache_path,
        cache_ttl_days: config.ip_to_domain.cache_ttl_days,
        passive_dns: None,
        skip_domain_suffixes: vec![],
        probe_cache_secs: 0, // probe page always fetches fresh
    };

    let (live_result, db_domains) = match db.lock() {
        Ok(conn) => {
            let db_domains = store::domains_by_ip(&conn, &q.ip);
            let result = lookup(&q.ip, &cfg);
            if let Ok(ref r) = result {
                let now = now_secs();
                for entry in &r.domains {
                    store::upsert_domain(&conn, &entry.domain, &q.ip, now).ok();
                }
            }
            (result, db_domains)
        }
        Err(_) => (lookup(&q.ip, &cfg), vec![]),
    };

    match live_result {
        Ok(r) => {
            // Merge DB-known domains — deduplicated, marked with "dns-cache" source.
            let mut entries: Vec<templates::ProbeEntry> = r
                .domains
                .into_iter()
                .map(|d| templates::ProbeEntry {
                    domain: d.domain,
                    sources: d.sources,
                })
                .collect();
            let known: std::collections::HashSet<String> =
                entries.iter().map(|e| e.domain.clone()).collect();
            for d in db_domains {
                if !known.contains(&d) {
                    entries.push(templates::ProbeEntry {
                        domain: d,
                        sources: vec!["dns-cache".into()],
                    });
                }
            }

            templates::ProbeResult {
                ip: r.ip,
                count: entries.len(),
                verified: r.verified,
                domains: entries,
                notes: r.notes,
            }
        }
        Err(e) => {
            // Live lookup failed — still show DB-cached domains.
            let domains: Vec<templates::ProbeEntry> = db_domains
                .into_iter()
                .map(|d| templates::ProbeEntry {
                    domain: d,
                    sources: vec!["dns-cache".into()],
                })
                .collect();
            templates::ProbeResult {
                ip: q.ip.clone(),
                count: domains.len(),
                verified: false,
                domains,
                notes: vec![format!("live lookup error: {e}")],
            }
        }
    }
}
