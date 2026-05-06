use crate::frontend::{chart::{self, Series}, response};

pub fn handle(name: &str) -> response::HttpResponse {
    let svg_bytes = match name {
        "traffic" => chart::traffic_chart(&[
            // TODO(Phase 1): feed real per-minute buckets from store
            Series { label: "IPs",     color: "#3b82f6", values: &[] },
            Series { label: "Alerts",  color: "#ef4444", values: &[] },
            Series { label: "Domains", color: "#10b981", values: &[] },
        ]),
        "alerts"  => chart::sparkline(&[], "#ef4444"),
        "domains" => chart::sparkline(&[], "#10b981"),
        "ips"     => chart::sparkline(&[], "#3b82f6"),
        "probes"  => chart::sparkline(&[], "#4f46e5"),
        _         => return response::not_found(),
    };

    response::svg(svg_bytes)
}
