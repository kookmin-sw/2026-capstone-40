use std::net::IpAddr;

use crate::ip_to_domain::{lookup, LookupConfig};
use crate::passive_filter;
use crate::prefilter::{PrefilterOutput, Verdict};
use crate::store::{self, Db};
use crate::time::now_secs;

use super::probe;

pub fn handle(out: PrefilterOutput, db: &Db, lookup_cfg: &LookupConfig) {
    if is_private_ip(out.server_ip) { return; }

    // Unknown / Benign → silent drop. No domain lookup, no alert.
    match out.verdict {
        Verdict::Unknown | Verdict::Benign => return,
        Verdict::Known | Verdict::Malicious => {}
    }

    let ip_str = out.server_ip.to_string();
    let now = now_secs();

    // Domain resolution — passive DNS first, then PTR / HackerTarget.
    let domain = match lookup(&ip_str, lookup_cfg) {
        Ok(r) if !r.domains.is_empty() => {
            if let Ok(ref conn) = db.lock() {
                for entry in &r.domains {
                    store::upsert_domain(conn, &entry.domain, &ip_str, now).ok();
                }
            }
            let primary = r.domains[0].domain.clone();
            for entry in &r.domains {
                passive_filter::score_and_persist(&entry.domain, db);
            }
            primary
        }
        _ => ip_str.clone(),
    };

    let (mut severity, alert_type, risk_delta) = match out.verdict {
        Verdict::Malicious => (4u8, "PREFILTER_MALICIOUS",  60u32),
        Verdict::Known     => (2u8, "PREFILTER_CLASSIFIED", 10u32),
        _                  => return,
    };

    let conf_str = format!("{:.0}%{}", out.confidence * 100.0,
        if out.direction_guessed { " ·dir?" } else { "" });

    // Active probe → fingerprint → severity escalation.
    let probe_note = probe::probe_and_compare(&domain, db, now);
    if let Some(ref note) = probe_note {
        if note.contains("EXACT")    { severity = 5; }
        else if note.contains("HIGH")     { severity = (severity + 1).min(5); }
        else if note.contains("MODERATE") { severity = (severity + 1).min(4); }
    }

    let detail = format!("→ {} ({}) {}",
        out.class_name, conf_str, probe_note.as_deref().unwrap_or("")).trim_end().to_owned();

    log::info!("prefilter {} sev={} {} → {} | {}", alert_type, severity, ip_str, domain, detail);

    let conn = match db.lock() { Ok(c) => c, Err(_) => return };

    store::upsert_domain(&conn, &domain, &ip_str, now).ok();

    let current = store::domain_risk(&conn, &domain).unwrap_or(0);
    let new_score = (current + risk_delta).min(100);
    let decision = match new_score {
        60.. => "probe",
        30.. => "watch",
        _     => "skip",
    };
    store::update_domain_risk(&conn, &domain, new_score, decision).ok();
    store::insert_alert(&conn, &domain, severity, alert_type, Some(&detail), now).ok();
    store::inc_traffic_alerts(&conn, now, 1).ok();
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
                || o[0] >= 224
        }
        IpAddr::V6(a) => {
            let b = a.octets();
            b == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
                || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
                || b[0] == 0xff
                || (b[0] & 0xfe) == 0xfc
        }
    }
}
