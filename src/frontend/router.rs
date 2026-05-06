/// Parsed representation of every URL the server handles.
/// Built once per request; handlers receive a concrete variant, no string matching.
#[derive(Debug)]
pub enum Route {
    Dashboard,
    Alerts { show_acked: bool },
    Domains,
    Domain(String),
    Probe(Option<ProbeQuery>),
    AckAlert(i64),
    Chart(String),
    StaticFile(String),
    NotFound,
}

#[derive(Debug)]
pub struct ProbeQuery {
    pub ip:      String,
    pub sources: Vec<String>,
    pub verify:  bool,
}

impl Route {
    /// Parse method + URL (path + optional query string) into a Route.
    pub fn parse(method: &tiny_http::Method, url: &str) -> Self {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        match (method, segs.as_slice()) {
            (tiny_http::Method::Get, [""]) =>
                Route::Dashboard,

            (tiny_http::Method::Get, ["dashboard"]) =>
                Route::Dashboard,

            (tiny_http::Method::Get, ["alerts"]) =>
                Route::Alerts { show_acked: query.contains("ack=show") },

            (tiny_http::Method::Get, ["domains"]) =>
                Route::Domains,

            (tiny_http::Method::Get, ["domains", domain]) =>
                Route::Domain(url_decode(domain)),

            (tiny_http::Method::Get, ["probe"]) =>
                Route::Probe(parse_probe_query(query)),

            (tiny_http::Method::Post, ["alerts", id, "ack"]) =>
                id.parse::<i64>().map(Route::AckAlert).unwrap_or(Route::NotFound),

            (tiny_http::Method::Get, ["chart", name]) =>
                Route::Chart((*name).to_string()),

            (tiny_http::Method::Get, [file]) if is_static(file) =>
                Route::StaticFile((*file).to_string()),

            _ => Route::NotFound,
        }
    }
}

fn is_static(name: &str) -> bool {
    matches!(name, "style.css" | "favicon.ico")
}

fn parse_probe_query(query: &str) -> Option<ProbeQuery> {
    let mut ip = String::new();
    let mut sources = vec!["ptr".to_string(), "hackertarget".to_string()];
    let mut verify = false;

    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "ip"      => ip = url_decode(v),
            "sources" => sources = v.split(',').map(url_decode).collect(),
            "verify"  => verify = matches!(v, "on" | "1"),
            _         => {}
        }
    }

    if ip.is_empty() { None } else { Some(ProbeQuery { ip, sources, verify }) }
}

pub fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        match b {
            b'%' => {
                let h1 = chars.next().unwrap_or(b'0');
                let h2 = chars.next().unwrap_or(b'0');
                out.push((hex_val(h1) << 4 | hex_val(h2)) as char);
            }
            b'+' => out.push(' '),
            _    => out.push(b as char),
        }
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _           => 0,
    }
}
