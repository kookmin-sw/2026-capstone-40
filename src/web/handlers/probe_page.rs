use crate::config::Config;
use crate::ip_to_domain::DEFAULT_DNS_CACHE;
use crate::ip_to_domain::{lookup, LookupConfig};
use crate::store::{self, Db};
use crate::time::now_secs;
use crate::web::{pages, response, router::ProbeQuery};
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

    let body = pages::ProbePage {
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

fn run_probe(q: &ProbeQuery, config: &Config, db: &Db) -> pages::ProbeResult {
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

    match lookup(&q.ip, &cfg) {
        Ok(r) => {
            match db.lock() {
                Ok(conn) => {
                    let now = now_secs();
                    for entry in &r.domains {
                        if let Err(e) = store::upsert_domain(&conn, &entry.domain, &q.ip, now) {
                            log::warn!("probe: upsert {}: {e}", entry.domain);
                        }
                    }
                }
                Err(e) => log::error!("probe: db lock poisoned: {e}"),
            }

            pages::ProbeResult {
                ip: r.ip,
                count: r.count,
                verified: r.verified,
                domains: r
                    .domains
                    .into_iter()
                    .map(|d| pages::ProbeEntry {
                        domain: d.domain,
                        sources: d.sources,
                    })
                    .collect(),
                notes: r.notes,
            }
        }
        Err(e) => pages::ProbeResult {
            ip: q.ip.clone(),
            count: 0,
            verified: false,
            domains: vec![],
            notes: vec![format!("error: {e}")],
        },
    }
}
