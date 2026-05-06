use askama::Template as _;
use crate::frontend::{pages, response, router::ProbeQuery};

pub fn handle(query: Option<ProbeQuery>) -> response::HttpResponse {
    let probe_result = query.as_ref().map(run_probe);

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
        active:     "probe",
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

fn run_probe(q: &ProbeQuery) -> pages::ProbeResult {
    use crate::ip_to_domain::{lookup, LookupConfig};

    let config = LookupConfig {
        sources:    q.sources.clone(),
        verify:     q.verify,
        timeout_s:  15.0,
        cache_path: "~/.cache/reverse_ip_domains/cache.sqlite3".into(),
    };

    match lookup(&q.ip, &config) {
        Ok(r) => pages::ProbeResult {
            ip:       r.ip,
            count:    r.count,
            verified: r.verified,
            domains:  r.domains.into_iter().map(|d| pages::ProbeEntry {
                domain:  d.domain,
                sources: d.sources,
            }).collect(),
            notes: r.notes,
        },
        Err(e) => pages::ProbeResult {
            ip:       q.ip.clone(),
            count:    0,
            verified: false,
            domains:  vec![],
            notes:    vec![format!("error: {e}")],
        },
    }
}
