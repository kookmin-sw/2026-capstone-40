use crate::store::{self, Db};
use crate::web::{chart::{self, Series}, response};

pub fn handle(name: &str, db: &Db) -> response::HttpResponse {
    let conn = match db.lock() {
        Ok(c)  => c,
        Err(_) => return response::svg(chart::sparkline(&[], "#94a3b8")),
    };

    let td = store::traffic_data(&conn, 60);

    let svg_bytes = match name {
        "traffic" => chart::traffic_chart(&[
            Series { label: "IPs",     color: "#3b82f6", values: &td.ips     },
            Series { label: "Alerts",  color: "#ef4444", values: &td.alerts  },
            Series { label: "Domains", color: "#10b981", values: &td.domains },
        ]),
        "alerts"  => chart::sparkline(&td.alerts,  "#ef4444"),
        "domains" => chart::sparkline(&td.domains, "#10b981"),
        "ips"     => chart::sparkline(&td.ips,     "#3b82f6"),
        "probes"  => chart::sparkline(&td.probes,  "#4f46e5"),
        _         => return response::not_found(),
    };

    response::svg(svg_bytes)
}
