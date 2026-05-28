use crate::probe::alert_worker::ProbeMsg;
use std::net::IpAddr;
use std::sync::mpsc::Sender;

use crate::prefilter::{PrefilterOutput, Verdict};
use crate::resolver::{lookup, LookupConfig};
use crate::store::{self, Db};
use crate::time::now_secs;

use crate::probe::{probe_and_compare, ProbeVerdict};

pub fn handle(
    mut out: PrefilterOutput,
    db: &Db,
    lookup_cfg: &LookupConfig,
    probe_tx: &Sender<ProbeMsg>,
) {
    if is_private_ip(out.server_ip) {
        return;
    }

    // Hardcoded watchlist: flows to a seeded known-malicious IP (CDN/ECH-fronted
    // sites ARI under-scores) are promoted so they get PROBED — but because the
    // IP is a shared Cloudflare anycast hosting many sites, a promoted flow only
    // alerts if the probe HTML-matches the seed domain's baseline. Non-matching
    // sites on the same IP stay silent (no false positives).
    let watchlist_only = apply_seed_watchlist(&mut out);

    match out.verdict {
        Verdict::Unknown | Verdict::Benign => return,
        Verdict::Known | Verdict::Malicious => {}
    }

    let ip_str = out.server_ip.to_string();
    let now = now_secs();

    // Resolve IP → candidate domains (passive DNS + PTR + HackerTarget + DB domain_ips).
    // If total candidates > CDN_THRESHOLD the IP is a shared CDN — alerting all would
    // cause false-positive explosions. Instead: pick the passive-DNS hit (most accurate)
    // as the sole alert candidate, and queue ALL candidates for background probing so
    // enrich_dns() populates the passive DNS cache for future flows.
    const CDN_THRESHOLD: usize = 5;

    let lookup_result = lookup(&ip_str, lookup_cfg);
    let live_lookup_domains: Vec<String> = match &lookup_result {
        Ok(r) if !r.domains.is_empty() => {
            if let Ok(ref conn) = db.lock() {
                for entry in &r.domains {
                    store::upsert_domain(conn, &entry.domain, &ip_str, now).ok();
                }
            }
            r.domains.iter().map(|d| d.domain.clone()).collect()
        }
        _ => vec![],
    };

    // DB-cached domains from previous successful lookups (HackerTarget/PTR).
    // Used as fallback when live lookup fails (quota exceeded, API down).
    let db_domains: Vec<String> = if let Ok(ref conn) = db.lock() {
        store::domains_by_ip(conn, &ip_str)
    } else {
        vec![]
    };

    let live_empty = live_lookup_domains.is_empty();

    // When live lookup empty, promote DB cache as the lookup source.
    let lookup_domains: Vec<String> = if live_empty {
        db_domains.clone()
    } else {
        live_lookup_domains
    };

    // Passive DNS (in-memory) — sniffed from wire or injected by enrich_dns().
    let passive_hit: Option<String> = lookup_cfg.passive_dns.as_ref().and_then(|c| {
        use std::net::IpAddr;
        ip_str
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| c.lookup(&ip).into_iter().next())
    });

    // Merge: when fallback path, lookup_domains == db_domains so no merge needed.
    let mut all_domains: Vec<String> = lookup_domains.clone();
    if !live_empty {
        for d in &db_domains {
            if !all_domains.contains(d) {
                all_domains.push(d.clone());
            }
        }
    }

    // CDN detection: too many domains → shared IP.
    let (candidates, cdn_probe_queue): (Vec<String>, Vec<String>) = if all_domains.len()
        > CDN_THRESHOLD
    {
        // Shared CDN: pick the best attribution candidate.
        // Priority: passive DNS hit (wire-sniffed, most specific)
        //   → class-root match in all_domains (DB-backed, e.g. vl.nornity.com for nornity class)
        //   → first lookup domain
        //   → raw IP fallback.
        //
        // class_etld: registrable domain (last 2 labels) of the classified class.
        // "nornity.com" → "nornity.com", "ani.ohli24.com" → "ohli24.com"
        let class_etld: String = {
            let mut parts = out.class_name.rsplitn(3, '.');
            let tld = parts.next().unwrap_or("");
            let sld = parts.next().unwrap_or("");
            if sld.is_empty() {
                out.class_name.clone()
            } else {
                format!("{sld}.{tld}")
            }
        };
        let class_match = all_domains
            .iter()
            .find(|d| *d == &class_etld || d.ends_with(&format!(".{class_etld}")))
            .cloned();
        let alert_domain = passive_hit
            .or(class_match)
            .or_else(|| lookup_domains.first().cloned())
            .unwrap_or_else(|| ip_str.clone());
        let alert_candidates = if is_infra_domain(&alert_domain, &lookup_cfg.skip_domain_suffixes) {
            vec![]
        } else {
            vec![alert_domain]
        };
        (alert_candidates, all_domains)
    } else {
        // Dedicated IP: alert all non-infra candidates, no background probe queue.
        let c: Vec<String> = all_domains
            .into_iter()
            .filter(|d| !is_infra_domain(d, &lookup_cfg.skip_domain_suffixes))
            .collect();
        (c, vec![])
    };

    // If still no alert candidates and it's infra, drop.
    if candidates.is_empty()
        && cdn_probe_queue.is_empty()
        && is_infra_domain(&ip_str, &lookup_cfg.skip_domain_suffixes)
    {
        return;
    }
    // If candidates empty but probe queue has items, we'll still queue probes below.
    // If everything empty, use raw IP as fallback alert domain.
    let candidates = if candidates.is_empty() && cdn_probe_queue.is_empty() {
        vec![ip_str.clone()]
    } else {
        candidates
    };

    let conf = out.confidence;
    let (base_severity, alert_type) = match out.verdict {
        Verdict::Malicious => {
            let sev = if conf >= 0.90 {
                5
            } else if conf >= 0.75 {
                4
            } else {
                3
            };
            (sev, "PREFILTER_MALICIOUS")
        }
        Verdict::Known => {
            let sev = if conf >= 0.90 {
                3
            } else if conf >= 0.75 {
                2
            } else {
                1
            };
            (sev, "PREFILTER_CLASSIFIED")
        }
        _ => return,
    };

    let conf_str = format!(
        "{:.0}%{}",
        conf * 100.0,
        if out.direction_guessed {
            " ·mid-flow"
        } else {
            ""
        }
    );

    // Build reference list: class_name first, then any additional typical_domains.
    let mut reference_domains = vec![out.class_name.clone()];
    for d in &out.typical_domains {
        if !reference_domains.contains(d) {
            reference_domains.push(d.clone());
        }
    }

    // For shared CDN IPs: queue all DB domains for background probing, class-relevant first.
    // Each probe → enrich_dns() → passive DNS cache updated → future lookup() finds domain.
    if !cdn_probe_queue.is_empty() {
        let ref_roots: Vec<&str> = reference_domains
            .iter()
            .filter_map(|r| r.split_once('.').map(|(_, root)| root))
            .collect();
        let (relevant, rest): (Vec<_>, Vec<_>) = cdn_probe_queue.iter().partition(|d| {
            ref_roots
                .iter()
                .any(|root| d.ends_with(root) || d.as_str() == *root)
        });
        for d in relevant {
            probe_tx
                .send(ProbeMsg {
                    domain: d.clone(),
                    priority: true,
                })
                .ok();
        }
        for d in rest {
            probe_tx
                .send(ProbeMsg {
                    domain: d.clone(),
                    priority: false,
                })
                .ok();
        }
    }

    // Alert ALL candidate domains — each gets its own probe + risk update.
    // Probing each domain also enriches passive DNS cache and domain_ips DB.
    let mut total_alerts = 0u32;
    for domain in &candidates {
        sync_domain_ips(domain, db, now, lookup_cfg.passive_dns.as_ref());

        // Include resolved domain itself so its own stored baseline can confirm identity.
        let mut refs_with_self = reference_domains.clone();
        if !refs_with_self.contains(domain) {
            refs_with_self.push(domain.clone());
        }

        let probe_verdict = probe_and_compare(
            domain,
            &refs_with_self,
            db,
            now,
            lookup_cfg.probe_cache_secs,
            lookup_cfg.passive_dns.as_ref(),
        );

        // Watchlist-promoted flows only alert when the probe confirms the page is
        // the seed site. Other sites on the shared Cloudflare IP probe to NoMatch/
        // NoBaseline and are dropped silently — no false positives.
        if watchlist_only && !matches!(probe_verdict, ProbeVerdict::Match(_)) {
            log::debug!("watchlist: {domain} probe={probe_verdict:?}, no match — suppressing alert");
            continue;
        }

        let mut severity = base_severity;
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
                // HTML mismatch means different site, not necessarily benign —
                // for Malicious classification still escalate (just slower than a Match).
                if matches!(out.verdict, Verdict::Malicious) {
                    severity = severity.min(3);
                    (20, 65)
                } else {
                    severity = severity.min(2);
                    (5, 35)
                }
            }
            ProbeVerdict::NoBaseline => {
                severity = severity.min(3);
                for r in &reference_domains {
                    probe_tx
                        .send(ProbeMsg {
                            domain: r.clone(),
                            priority: false,
                        })
                        .ok();
                }
                probe_tx
                    .send(ProbeMsg {
                        domain: domain.clone(),
                        priority: false,
                    })
                    .ok();
                if matches!(out.verdict, Verdict::Malicious) {
                    (20, 65)
                } else {
                    (8, 40)
                }
            }
            ProbeVerdict::Unreachable => {
                severity = severity.min(3);
                probe_tx
                    .send(ProbeMsg {
                        domain: domain.clone(),
                        priority: false,
                    })
                    .ok();
                if matches!(out.verdict, Verdict::Malicious) {
                    (15, 65)
                } else {
                    (5, 40)
                }
            }
        };

        let probe_note = match &probe_verdict {
            ProbeVerdict::Match(n) => Some(n.clone()),
            ProbeVerdict::NoMatch => Some("[no HTML match]".to_string()),
            _ => None,
        };

        let detail = format!(
            "→ {} ({}) {}",
            out.class_name,
            conf_str,
            probe_note.as_deref().unwrap_or("")
        )
        .trim_end()
        .to_owned();

        log::info!(
            "prefilter {} sev={} {} → {} | {}",
            alert_type,
            severity,
            ip_str,
            domain,
            detail
        );

        let conn = match db.lock() {
            Ok(c) => c,
            Err(_) => continue,
        };
        store::upsert_domain(&conn, domain, &ip_str, now).ok();
        store::increment_domain_risk(&conn, domain, risk_delta, score_cap).ok();
        store::insert_alert(&conn, domain, severity, alert_type, Some(&detail), now).ok();
        total_alerts += 1;
    }

    if total_alerts > 0 && let Ok(conn) = db.lock() {
        store::inc_traffic_alerts(&conn, now, total_alerts as i64).ok();
    }
}

/// Resolve domain → current IPs via system DNS, upsert into domain_ips, and
/// inject into passive DNS cache. Keeps DB and cache in sync when DNS changes.
fn sync_domain_ips(
    domain: &str,
    db: &crate::store::Db,
    now: i64,
    passive_dns: Option<&crate::resolver::PassiveDnsCache>,
) {
    use std::net::ToSocketAddrs;
    let addrs = match (domain, 443u16).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return,
    };
    for addr in addrs {
        let ip = addr.ip();
        let ip_str = ip.to_string();
        if let Ok(conn) = db.lock() {
            store::upsert_domain(&conn, domain, &ip_str, now).ok();
        }
        if let Some(cache) = passive_dns {
            cache.insert(ip, domain.to_string(), 3600);
        }
    }
}

/// Promote flows to a hardcoded known-malicious IP so they enter the probe path,
/// attributing them to the seed domain. Returns `true` if this flow was promoted
/// off the watchlist (not a genuine ARI verdict) — the caller then only alerts on
/// a probe Match, since the seeded Cloudflare IP is shared by many other sites.
/// No-op (returns `false`) for IPs not on the list or already-Malicious flows.
fn apply_seed_watchlist(out: &mut PrefilterOutput) -> bool {
    let ip = out.server_ip.to_string();
    let Some((_, domain)) = crate::resolver::SEED_IPS.iter().find(|(sip, _)| *sip == ip) else {
        return false;
    };
    if matches!(out.verdict, Verdict::Known | Verdict::Malicious) {
        return false; // genuine ARI verdict — handle normally (alert on all)
    }
    log::info!("watchlist: probing seeded IP {ip} → {domain} (alert only if HTML matches)");
    out.verdict = Verdict::Malicious;
    out.class_name = (*domain).to_string();
    if !out.typical_domains.iter().any(|d| d == domain) {
        out.typical_domains.push((*domain).to_string());
    }
    out.confidence = out.confidence.max(0.90);
    true
}

fn is_infra_domain(domain: &str, skip_suffixes: &[String]) -> bool {
    skip_suffixes
        .iter()
        .any(|s| domain == s.trim_start_matches('.') || domain.ends_with(s.as_str()))
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
            b == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
                || b[0] == 0xff
                || (b[0] & 0xfe) == 0xfc
        }
    }
}
