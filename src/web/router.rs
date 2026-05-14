/// Parsed representation of every URL the server handles.
/// Built once per request; handlers receive a concrete variant, no string matching.
#[derive(Debug)]
pub enum Route {
    Dashboard,
    Alerts {
        show_acked: bool,
        min_severity: u8,
        page: usize,
    },
    Domains,
    Domain(String),
    Tracked,
    Probe(Option<ProbeQuery>),
    AckAlert(i64),
    Chart(String),
    RiskChart(String),
    StaticFile(String),
    NotFound,
}

#[derive(Debug)]
pub struct ProbeQuery {
    pub ip: String,
    pub sources: Vec<String>,
    pub verify: bool,
}

impl Route {
    /// Parse method + URL (path + optional query string) into a Route.
    pub fn parse(method: &tiny_http::Method, url: &str) -> Self {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        match (method, segs.as_slice()) {
            (tiny_http::Method::Get, [""]) => Route::Dashboard,

            (tiny_http::Method::Get, ["dashboard"]) => Route::Dashboard,

            (tiny_http::Method::Get, ["alerts"]) => {
                let show_acked = query.contains("ack=show");
                let min_severity = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("sev=").and_then(|v| v.parse::<u8>().ok()))
                    .unwrap_or(0);
                let page = query
                    .split('&')
                    .find_map(|p| {
                        p.strip_prefix("page=")
                            .and_then(|v| v.parse::<usize>().ok())
                    })
                    .unwrap_or(1)
                    .max(1);
                Route::Alerts {
                    show_acked,
                    min_severity,
                    page,
                }
            }

            (tiny_http::Method::Get, ["domains"]) => Route::Domains,

            (tiny_http::Method::Get, ["domains", domain]) => Route::Domain(url_decode(domain)),

            (tiny_http::Method::Get, ["tracked"]) => Route::Tracked,

            (tiny_http::Method::Get, ["probe"]) => Route::Probe(parse_probe_query(query)),

            (tiny_http::Method::Post, ["alerts", id, "ack"]) => id
                .parse::<i64>()
                .map(Route::AckAlert)
                .unwrap_or(Route::NotFound),

            (tiny_http::Method::Get, ["chart", name]) => Route::Chart((*name).to_string()),

            (tiny_http::Method::Get, ["chart", "risk", domain]) => {
                Route::RiskChart(url_decode(domain))
            }

            (tiny_http::Method::Get, [file]) if is_static(file) => {
                Route::StaticFile((*file).to_string())
            }

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
            "ip" => ip = url_decode(v),
            "sources" => sources = v.split(',').map(url_decode).collect(),
            "verify" => verify = matches!(v, "on" | "1"),
            _ => {}
        }
    }

    if ip.is_empty() {
        None
    } else {
        Some(ProbeQuery {
            ip,
            sources,
            verify,
        })
    }
}

pub fn url_decode(s: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut iter = s.bytes();
    while let Some(b) = iter.next() {
        match b {
            b'%' => {
                let h1 = iter.next().unwrap_or(b'0');
                let h2 = iter.next().unwrap_or(b'0');
                bytes.push(hex_val(h1) << 4 | hex_val(h2));
            }
            b'+' => bytes.push(b' '),
            _ => bytes.push(b),
        }
    }
    String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
