use std::net::IpAddr;
use std::sync::mpsc::Sender;

use crate::resolver::{lookup, LookupConfig};
use crate::prefilter::{PrefilterOutput, Verdict};
use crate::store::{self, Db};
use crate::time::now_secs;

use crate::probe::{probe_and_compare, ProbeVerdict};

pub fn handle(out: PrefilterOutput, db: &Db, lookup_cfg: &LookupConfig, probe_tx: &Sender<String>) {
    if is_private_ip(out.server_ip) { return; }

    match out.verdict {
        Verdict::Unknown | Verdict::Benign => return,
        Verdict::Known | Verdict::Malicious => {}
    }

    let ip_str = out.server_ip.to_string();
    let now = now_secs();

    let domain = match lookup(&ip_str, lookup_cfg) {
        Ok(r) if !r.domains.is_empty() => {
            if let Ok(ref conn) = db.lock() {
                for entry in &r.domains {
                    store::upsert_domain(conn, &entry.domain, &ip_str, now).ok();
                }
            }
            r.domains[0].domain.clone()
        }
        _ => ip_str.clone(),
    };

    // Drop flows that resolve to known infrastructure domain suffixes.
    if is_infra_domain(&domain, &lookup_cfg.skip_domain_suffixes) {
        log::debug!("flow: drop infra domain {domain}");
        return;
    }

    let conf = out.confidence;
    let (mut severity, alert_type) = match out.verdict {
        Verdict::Malicious => {
            let sev = if conf >= 0.90 { 5 } else if conf >= 0.75 { 4 } else { 3 };
            (sev, "PREFILTER_MALICIOUS")
        }
        Verdict::Known => {
            let sev = if conf >= 0.90 { 3 } else if conf >= 0.75 { 2 } else { 1 };
            (sev, "PREFILTER_CLASSIFIED")
        }
        _ => return,
    };

    let conf_str = format!("{:.0}%{}", conf * 100.0,
        if out.direction_guessed { " ·mid-flow" } else { "" });

    // Active probe: compare suspicious domain's HTML against reference baseline.
    // Verdict determines severity adjustment:
    //   Match    → escalate (clone / mirror confirmed)
    //   NoMatch  → downgrade (model says X, HTML says no → probably false positive)
    //   NoBaseline / Unreachable → cap at medium (uncertain)
    // Build reference list: class_name first, then any additional typical_domains.
    let mut reference_domains = vec![out.class_name.clone()];
    for d in &out.typical_domains {
        if !reference_domains.contains(d) {
            reference_domains.push(d.clone());
        }
    }
    let probe_verdict = probe_and_compare(&domain, &reference_domains, db, now, lookup_cfg.probe_cache_secs, lookup_cfg.passive_dns.as_ref());

    // ── Risk delta + severity based on probe verdict ──────────────────────────
    // Probe result is ground truth; ARI alone is uncertain.
    //
    //  Match (EXACT/HIGH/MODERATE) → confirmed similar to piracy site → high risk
    //  NoMatch                     → HTML clearly different → likely FP → low risk
    //  NoBaseline / Unreachable    → uncertain → moderate risk, retry probe
    let (risk_delta, score_cap) = match &probe_verdict {
        ProbeVerdict::Match(note) => {
            if note.contains("EXACT") {
                severity = 5;
                (60u32, 100u32)
            } else if note.contains("HIGH") {
                severity = (severity + 1).min(5);
                (45, 100)
            } else {
                severity = (severity + 1).min(4);
                (30, 100)
            }
        }
        ProbeVerdict::NoMatch => {
            // HTML different from reference → probable ARI false positive.
            // Add minimal risk, cap score so it stays in "watch" band.
            severity = severity.min(2);
            (5, 35)
        }
        ProbeVerdict::NoBaseline => {
            // No reference yet — uncertain. Moderate risk, do not let it
            // accumulate to probe threshold on ARI alone.
            severity = severity.min(3);
            for r in &reference_domains { probe_tx.send(r.clone()).ok(); }
            probe_tx.send(domain.clone()).ok();
            if matches!(out.verdict, Verdict::Malicious) { (20, 65) } else { (8, 40) }
        }
        ProbeVerdict::Unreachable => {
            // Suspicious domain unreachable — uncertain.
            severity = severity.min(3);
            probe_tx.send(domain.clone()).ok();
            if matches!(out.verdict, Verdict::Malicious) { (15, 65) } else { (5, 40) }
        }
    };

    let probe_note = match &probe_verdict {
        ProbeVerdict::Match(n) => Some(n.clone()),
        ProbeVerdict::NoMatch  => Some("[no HTML match]".to_string()),
        _                      => None,
    };

    let detail = format!("→ {} ({}) {}",
        out.class_name, conf_str, probe_note.as_deref().unwrap_or("")).trim_end().to_owned();

    log::info!("prefilter {} sev={} {} → {} | {}", alert_type, severity, ip_str, domain, detail);

    let conn = match db.lock() { Ok(c) => c, Err(_) => return };

    store::upsert_domain(&conn, &domain, &ip_str, now).ok();

    let current = store::domain_risk(&conn, &domain).unwrap_or(0);
    let new_score = (current + risk_delta).min(score_cap);
    let decision = match new_score {
        60.. => "probe",
        30.. => "watch",
        _    => "skip",
    };
    store::update_domain_risk(&conn, &domain, new_score, decision).ok();
    store::insert_alert(&conn, &domain, severity, alert_type, Some(&detail), now).ok();
    store::inc_traffic_alerts(&conn, now, 1).ok();
}

fn is_infra_domain(domain: &str, skip_suffixes: &[String]) -> bool {
    skip_suffixes.iter().any(|s| domain == s.trim_start_matches('.') || domain.ends_with(s.as_str()))
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
