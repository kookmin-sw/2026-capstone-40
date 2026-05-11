use std::net::IpAddr;

use crate::ip_to_domain::{lookup, LookupConfig};
use crate::passive_filter;
use crate::store::{self, Db};
use crate::time::now_secs;

pub fn handle(ip: IpAddr, db: &Db, lookup_cfg: &LookupConfig) {
    let ip_str = ip.to_string();
    let now = now_secs();

    if let Ok(conn) = db.lock() {
        store::inc_traffic_ips(&conn, now, 1).ok();
    }

    log::debug!("lookup {ip_str}");

    match lookup(&ip_str, lookup_cfg) {
        Ok(result) => {
            {
                let conn = match db.lock() { Ok(c) => c, Err(_) => return };
                let mut new_domains: i64 = 0;
                for entry in &result.domains {
                    if store::upsert_domain(&conn, &entry.domain, &ip_str, now).is_ok() {
                        new_domains += 1;
                    }
                }
                if new_domains > 0 {
                    store::inc_traffic_domains(&conn, now, new_domains).ok();
                }
                if !result.domains.is_empty() {
                    log::info!(
                        "{ip_str} → {} domain(s): {}",
                        result.count,
                        result.domains.iter().map(|d| d.domain.as_str()).collect::<Vec<_>>().join(", ")
                    );
                }
            }
            // Heuristic scoring runs after the conn is released.
            for entry in &result.domains {
                passive_filter::score_and_persist(&entry.domain, db);
            }
        }
        Err(e) => log::warn!("lookup failed {ip_str}: {e}"),
    }
}
