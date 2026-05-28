use std::collections::HashSet;
use std::net::IpAddr;
use std::thread;
use std::time::Duration;

use serde_json::Value;

fn doh_lookup(name: &str, rtype: &str, timeout_s: f64) -> HashSet<String> {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type={}",
        name, rtype
    );
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs_f64(timeout_s))
        .build();
    match agent.get(&url).set("Accept", "application/dns-json").call() {
        Ok(resp) => resp
            .into_json::<Value>()
            .ok()
            .and_then(|v| v["Answer"].as_array().cloned())
            .into_iter()
            .flatten()
            .filter_map(|a| a["data"].as_str().map(|s| s.trim().to_string()))
            .collect(),
        Err(_) => HashSet::new(),
    }
}

pub fn verify_domains(
    domains: &HashSet<String>,
    target_ip: &str,
    timeout_s: f64,
) -> HashSet<String> {
    let target: IpAddr = match target_ip.parse() {
        Ok(a) => a,
        Err(_) => return HashSet::new(),
    };

    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let handles: Vec<_> = domains
        .iter()
        .cloned()
        .map(|d| {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut addrs = doh_lookup(&d, "A", timeout_s);
                addrs.extend(doh_lookup(&d, "AAAA", timeout_s));
                if addrs.iter().any(|a| a.parse::<IpAddr>().ok() == Some(target)) {
                    tx.send(d).ok();
                }
            })
        })
        .collect();

    drop(tx);
    for h in handles {
        h.join().ok();
    }
    rx.iter().collect()
}
