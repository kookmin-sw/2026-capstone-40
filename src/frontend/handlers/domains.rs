use askama::Template as _;
use crate::frontend::{pages, response};

pub fn handle() -> response::HttpResponse {
    // TODO(Phase 1): let domains = store::list_domains();
    let domains: Vec<pages::DomainRow> = vec![];

    let body = pages::DomainsPage {
        page_title: "Domains",
        active:     "domains",
        domains,
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>"));

    response::html(200, body)
}
