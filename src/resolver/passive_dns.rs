//! Passive DNS: sniff DNS A/AAAA responses off the wire → IP→domain mapping.
//!
//! Parse raw Ethernet frames containing UDP port-53 DNS responses.
//! No external crates — pure byte parsing of RFC 1035 wire format.
//!
//! The capture thread calls `PassiveDnsCache::ingest_frame()` for every packet.
//! The ip_to_domain lookup thread calls `PassiveDnsCache::lookup()`.
//!
//! Records expire after `ttl_s` seconds (clamped to DNS record TTL).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::types::{looks_like_domain, norm_domain, ProviderResult};

// ── shared cache ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PassiveDnsCache(Arc<RwLock<HashMap<IpAddr, Vec<Record>>>>);

#[derive(Clone)]
struct Record {
    domain: String,
    expires: Instant,
}

impl PassiveDnsCache {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Insert a (ip, domain) mapping observed from a DNS response.
    pub fn insert(&self, ip: IpAddr, domain: String, ttl_s: u32) {
        let ttl = Duration::from_secs(ttl_s.clamp(30, 3600) as u64);
        let rec = Record {
            domain,
            expires: Instant::now() + ttl,
        };
        if let Ok(mut m) = self.0.write() {
            m.entry(ip).or_default().push(rec);
        }
    }

    /// Return fresh domain names for an IP. Expired records are lazily removed.
    pub fn lookup(&self, ip: &IpAddr) -> Vec<String> {
        let now = Instant::now();
        if let Ok(mut m) = self.0.write()
            && let Some(recs) = m.get_mut(ip)
        {
            recs.retain(|r| r.expires > now);
            return recs.iter().map(|r| r.domain.clone()).collect();
        }
        vec![]
    }

    /// Parse raw Ethernet frame, extract any DNS A/AAAA answers, insert them.
    pub fn ingest_frame(&self, data: &[u8]) {
        for (ip, domain, ttl) in parse_dns_from_frame(data) {
            self.insert(ip, domain, ttl);
        }
    }

    pub fn as_provider(&self, ip: &str) -> ProviderResult {
        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => {
                return ProviderResult {
                    provider: "passive-dns".into(),
                    ..Default::default()
                };
            }
        };
        let domains = self.lookup(&addr).into_iter().collect();
        ProviderResult {
            provider: "passive-dns".into(),
            domains,
            ..Default::default()
        }
    }
}

impl Default for PassiveDnsCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── frame → DNS records ───────────────────────────────────────────────────────

fn parse_dns_from_frame(data: &[u8]) -> Vec<(IpAddr, String, u32)> {
    if data.len() < 14 {
        return vec![];
    }
    let (ether_type, ip_payload) = ether_type_and_payload(data);
    match ether_type {
        0x0800 => parse_dns_ipv4(ip_payload).unwrap_or_default(),
        0x86DD => parse_dns_ipv6(ip_payload).unwrap_or_default(),
        _ => vec![],
    }
}

fn parse_dns_ipv4(payload: &[u8]) -> Option<Vec<(IpAddr, String, u32)>> {
    if payload.len() < 20 {
        return None;
    }
    let ihl = (payload[0] & 0x0F) as usize * 4;
    if ihl < 20 || payload[9] != 17 {
        return None;
    }
    let total = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let udp = payload.get(ihl..total.min(payload.len()))?;
    Some(parse_dns_udp(udp).unwrap_or_default())
}

fn parse_dns_ipv6(payload: &[u8]) -> Option<Vec<(IpAddr, String, u32)>> {
    if payload.len() < 40 {
        return None;
    }
    if payload[6] != 17 {
        return None;
    }
    let udp_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let udp = payload.get(40..40 + udp_len.min(payload.len() - 40))?;
    Some(parse_dns_udp(udp).unwrap_or_default())
}

fn parse_dns_udp(udp: &[u8]) -> Option<Vec<(IpAddr, String, u32)>> {
    if udp.len() < 8 {
        return None;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    if sport != 53 && dport != 53 {
        return None;
    }
    let dns_msg = udp.get(8..)?;
    Some(parse_dns_response(dns_msg))
}

fn ether_type_and_payload(frame: &[u8]) -> (u16, &[u8]) {
    let mut off = 12usize;
    loop {
        if frame.len() < off + 2 {
            return (0, &[]);
        }
        let et = u16::from_be_bytes([frame[off], frame[off + 1]]);
        off += 2;
        if et == 0x8100 || et == 0x88A8 {
            off += 2;
        } else {
            return (et, &frame[off..]);
        }
    }
}

// ── DNS wire-format parser ────────────────────────────────────────────────────

/// Parse DNS response message, return (ip, domain, ttl) for A/AAAA answers.
pub fn parse_dns_response(msg: &[u8]) -> Vec<(IpAddr, String, u32)> {
    if msg.len() < 12 {
        return vec![];
    }

    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0x000F;
    if qr != 1 || rcode != 0 {
        return vec![];
    } // must be a successful response

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    parse_dns_records(msg, qdcount, ancount).unwrap_or_default()
}

fn parse_dns_records(
    msg: &[u8],
    qdcount: usize,
    ancount: usize,
) -> Option<Vec<(IpAddr, String, u32)>> {
    let mut pos = 12usize;
    let mut questions = Vec::new();

    // Capture question names. For firewall attribution these are often more
    // useful than the canonical CDN name returned later in the answer section.
    for _ in 0..qdcount {
        let (name, after_name) = read_name(msg, pos)?;
        if looks_like_domain(&name) {
            questions.push(norm_domain(&name));
        }
        pos = after_name;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
        if pos > msg.len() {
            return None;
        }
    }

    let mut addresses: Vec<(String, IpAddr, u32)> = Vec::new();
    let mut cnames: Vec<(String, String)> = Vec::new();

    for _ in 0..ancount {
        let (name, after_name) = read_name(msg, pos)?;
        pos = after_name;
        if pos + 10 > msg.len() {
            break;
        }

        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;

        let rdata_pos = pos;
        let rdata = msg.get(pos..pos + rdlength)?;
        pos += rdlength;

        let domain = if looks_like_domain(&name) {
            norm_domain(&name)
        } else {
            continue;
        };

        match rtype {
            1 if rdlength == 4 => {
                addresses.push((
                    domain,
                    IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                    ttl,
                ));
            }
            28 if rdlength == 16 => {
                let b: [u8; 16] = rdata.try_into().ok()?;
                addresses.push((domain, IpAddr::V6(Ipv6Addr::from(b)), ttl));
            }
            5 => {
                if let Some((target, _)) = read_name(msg, rdata_pos)
                    && looks_like_domain(&target)
                {
                    cnames.push((domain, norm_domain(&target)));
                }
            }
            _ => {}
        }
    }

    let mut reverse_cnames: HashMap<String, Vec<String>> = HashMap::new();
    for (alias, target) in cnames {
        reverse_cnames.entry(target).or_default().push(alias);
    }

    let mut results = Vec::new();
    for (answer_name, ip, ttl) in addresses {
        let mut domains = aliases_for_address(&answer_name, &reverse_cnames);
        for q in &questions {
            if q == &answer_name {
                domains.insert(q.clone());
            }
        }
        for domain in domains {
            results.push((ip, domain, ttl));
        }
    }

    Some(results)
}

fn aliases_for_address(
    answer_name: &str,
    reverse_cnames: &HashMap<String, Vec<String>>,
) -> HashSet<String> {
    let mut domains = HashSet::new();
    let mut stack = vec![answer_name.to_string()];

    while let Some(name) = stack.pop() {
        if !domains.insert(name.clone()) {
            continue;
        }
        if let Some(aliases) = reverse_cnames.get(&name) {
            stack.extend(aliases.iter().cloned());
        }
    }

    domains
}

/// Read a DNS name (following compression pointers) starting at `pos`.
/// Returns (name_string, position_after_this_name_field).
fn read_name(msg: &[u8], pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut cur = pos;
    let mut end_pos: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        if cur >= msg.len() {
            return None;
        }
        let len = msg[cur] as usize;

        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(cur + 1);
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if cur + 1 >= msg.len() {
                return None;
            }
            if end_pos.is_none() {
                end_pos = Some(cur + 2);
            }
            let offset = ((len & 0x3F) << 8) | msg[cur + 1] as usize;
            cur = offset;
            hops += 1;
            if hops > 64 {
                return None;
            } // loop guard
            continue;
        }
        cur += 1;
        let label = msg.get(cur..cur + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cur += len;
    }

    Some((labels.join("."), end_pos.unwrap_or(cur)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_name(msg: &mut Vec<u8>, domain: &str) {
        for label in domain.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
    }

    /// Hand-crafted DNS response for `example.com → 93.184.216.34`, TTL=300.
    fn make_dns_response(domain: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        // Header
        msg.extend_from_slice(&[0xAB, 0xCD]); // ID
        msg.extend_from_slice(&[0x81, 0x80]); // QR=1 response, RCODE=0
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        msg.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        // Question: <domain> A IN
        let qname_start = msg.len();
        write_name(&mut msg, domain);
        msg.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        // Answer: pointer back to question name, A IN, TTL, rdata
        msg.extend_from_slice(&[0xC0, qname_start as u8]); // compressed pointer
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        msg.extend_from_slice(&ip);

        msg
    }

    fn make_cname_dns_response(alias: &str, canonical: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0xAB, 0xCD]); // ID
        msg.extend_from_slice(&[0x81, 0x80]); // response, no error
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        msg.extend_from_slice(&[0x00, 0x02]); // ANCOUNT=2
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

        let qname_start = msg.len();
        write_name(&mut msg, alias);
        msg.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS IN

        msg.extend_from_slice(&[0xC0, qname_start as u8]); // alias
        msg.extend_from_slice(&[0x00, 0x05]); // TYPE CNAME
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        msg.extend_from_slice(&300u32.to_be_bytes());
        let mut cname_rdata = Vec::new();
        write_name(&mut cname_rdata, canonical);
        msg.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(&cname_rdata);

        write_name(&mut msg, canonical);
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
        msg.extend_from_slice(&ip);

        msg
    }

    #[test]
    fn parse_a_record() {
        let msg = make_dns_response("example.com", [93, 184, 216, 34], 300);
        let results = parse_dns_response(&msg);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, IpAddr::V4("93.184.216.34".parse().unwrap()));
        assert_eq!(results[0].1, "example.com");
        assert_eq!(results[0].2, 300);
    }

    #[test]
    fn parse_cname_chain_keeps_queried_domain_for_firewall_attribution() {
        let msg =
            make_cname_dns_response("video.example.com", "edge.cdn.example.net", [1, 2, 3, 4]);
        let results = parse_dns_response(&msg);
        let domains: HashSet<String> = results.into_iter().map(|(_, domain, _)| domain).collect();
        assert!(domains.contains("video.example.com"));
        assert!(domains.contains("edge.cdn.example.net"));
    }

    #[test]
    fn rejects_query_packet() {
        let mut msg = make_dns_response("example.com", [1, 2, 3, 4], 60);
        // Clear QR bit → query
        msg[2] &= 0x7F;
        assert!(parse_dns_response(&msg).is_empty());
    }

    #[test]
    fn rejects_error_response() {
        let mut msg = make_dns_response("nxdomain.example", [0, 0, 0, 0], 60);
        msg[3] = 0x83; // RCODE=3 NXDOMAIN
        assert!(parse_dns_response(&msg).is_empty());
    }

    #[test]
    fn cache_insert_lookup_expiry() {
        let c = PassiveDnsCache::new();
        c.insert("1.2.3.4".parse().unwrap(), "example.com".into(), 3600);
        let hits = c.lookup(&"1.2.3.4".parse().unwrap());
        assert!(hits.contains(&"example.com".to_string()));
        // Unknown IP
        let miss = c.lookup(&"9.9.9.9".parse().unwrap());
        assert!(miss.is_empty());
    }
}
