//! Phase 4 — live NIC / PCAP-file packet capture.
//!
//! Extracts unique public IPs from passing frames and forwards them to the
//! caller via an `mpsc::Sender<CaptureEvent>`.  All filtering (private,
//! cooldown) happens here so workers only see actionable addresses.
//!
//! When a `Prefilter` is supplied, every TCP packet is also parsed into a
//! `ParsedPkt` and fed to the prefilter's flow table. Classified flows are
//! drained periodically and forwarded as `CaptureEvent::Flow`.
//!
//! Thread topology:
//!   capture::run() [blocking, own thread]
//!     └─ Sender<CaptureEvent> ──► N worker threads

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use pcap::{Active, Capture, Offline};

use crate::config::CaptureConfig;
use crate::resolver::PassiveDnsCache;
use crate::prefilter::{FlowKey, ParsedPkt, Prefilter, PrefilterOutput, Verdict};
use crate::prefilter::flow_table::SkipNet;

// ── public types ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CaptureEvent {
    Ip(IpAddr),
    Flow(FlowKey, PrefilterOutput),
}

// ── public entry point ────────────────────────────────────────────────────────

pub fn run(
    cfg: &CaptureConfig,
    tx: Sender<CaptureEvent>,
    prefilter: Option<Prefilter>,
    passive_dns: Option<PassiveDnsCache>,
    skip_ips: Vec<SkipNet>,
) {
    let cooldown = Duration::from_secs(cfg.ip_cooldown_s);
    let skip_priv = cfg.skip_private;
    let mut seen: HashMap<IpAddr, Instant> = HashMap::new();
    let mut state = RunState { prefilter, passive_dns, last_drain: Instant::now(), skip_ips };

    match (&cfg.interface, &cfg.pcap_file) {
        (Some(iface), _) => {
            log::info!("opening interface {iface}");
            match Capture::from_device(iface.as_str())
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open())
            {
                Ok(cap)  => pump_live(cap, cfg, cooldown, skip_priv, &mut seen, &tx, &mut state),
                Err(e)   => log::error!("failed to open {iface}: {e}"),
            }
        }
        (_, Some(path)) => {
            log::info!("reading pcap {path}");
            match Capture::from_file(path) {
                Ok(cap)  => pump_file(cap, cfg, cooldown, skip_priv, &mut seen, &tx, &mut state),
                Err(e)   => log::error!("failed to open {path}: {e}"),
            }
        }
        (None, None) => {
            log::warn!("no source — set interface or pcap_file in capstone.toml");
        }
    }
}

struct RunState {
    prefilter: Option<Prefilter>,
    passive_dns: Option<PassiveDnsCache>,
    last_drain: Instant,
    skip_ips: Vec<SkipNet>,
}

const DRAIN_INTERVAL: Duration = Duration::from_millis(500);

// ── pumps ─────────────────────────────────────────────────────────────────────

fn pump_live(
    mut cap:       Capture<Active>,
    _cfg:          &CaptureConfig,
    cooldown:      Duration,
    skip_priv:     bool,
    seen:          &mut HashMap<IpAddr, Instant>,
    tx:            &Sender<CaptureEvent>,
    state:         &mut RunState,
) {
    loop {
        match cap.next_packet() {
            Ok(pkt)  => handle_packet(pkt.data, cooldown, skip_priv, seen, tx, state),
            Err(pcap::Error::TimeoutExpired) => {
                drain_prefilter(state, tx);
                continue;
            }
            Err(e)   => {
                log::error!("read error: {e}");
                break;
            }
        }
    }
}

fn pump_file(
    mut cap:   Capture<Offline>,
    _cfg:      &CaptureConfig,
    cooldown:  Duration,
    skip_priv: bool,
    seen:      &mut HashMap<IpAddr, Instant>,
    tx:        &Sender<CaptureEvent>,
    state:     &mut RunState,
) {
    while let Ok(pkt) = cap.next_packet() {
        handle_packet(pkt.data, cooldown, skip_priv, seen, tx, state);
    }
    // Final drain — pcap exhausted, surface any pending flows.
    if let Some(pf) = state.prefilter.as_mut() {
        let now = Instant::now();
        for (k, out) in pf.drain_classified(now) {
            forward_flow(tx, k, out, pf.benign_skip);
        }
    }
    log::info!("pcap file exhausted");
}

// ── per-packet logic ──────────────────────────────────────────────────────────

fn handle_packet(
    data:      &[u8],
    cooldown:  Duration,
    skip_priv: bool,
    seen:      &mut HashMap<IpAddr, Instant>,
    tx:        &Sender<CaptureEvent>,
    state:     &mut RunState,
) {
    let parsed = parse_l3l4(data);

    for ip in parsed.as_ref().map(|p| [Some(p.src), Some(p.dst)]).unwrap_or_else(|| extract_ips(data)).into_iter().flatten() {
        if skip_priv && is_private(ip) {
            continue;
        }
        if state.skip_ips.iter().any(|n| n.contains(ip)) {
            continue;
        }
        let now = Instant::now();
        if seen
            .get(&ip)
            .is_none_or(|t| now.duration_since(*t) >= cooldown)
        {
            seen.insert(ip, now);
            if tx.send(CaptureEvent::Ip(ip)).is_err() {
                return; // receiver gone
            }
        }
    }

    if let (Some(pf), Some(pkt)) = (state.prefilter.as_mut(), parsed) {
        pf.ingest(&pkt);
    }

    // Feed every frame into passive DNS — even non-TCP frames may carry DNS responses.
    if let Some(ref pdns) = state.passive_dns {
        pdns.ingest_frame(data);
    }

    let now = Instant::now();
    if now.duration_since(state.last_drain) >= DRAIN_INTERVAL {
        drain_prefilter(state, tx);
    }
}

fn drain_prefilter(state: &mut RunState, tx: &Sender<CaptureEvent>) {
    state.last_drain = Instant::now();
    let Some(pf) = state.prefilter.as_mut() else { return };
    for (k, out) in pf.drain_classified(state.last_drain) {
        forward_flow(tx, k, out, pf.benign_skip);
    }
}

fn forward_flow(tx: &Sender<CaptureEvent>, key: FlowKey, out: PrefilterOutput, benign_skip: bool) {
    if benign_skip && out.verdict == Verdict::Benign {
        log::debug!("prefilter skip benign {} ({:.2})", out.class_name, out.confidence);
        return;
    }
    log::info!(
        "prefilter {:?} class={} conf={:.2} key={:?}",
        out.verdict, out.class_name, out.confidence, key
    );
    let _ = tx.send(CaptureEvent::Flow(key, out));
}

// ── packet parsing (Ethernet → IPv4 / IPv6 → TCP) ────────────────────────────

fn parse_l3l4(data: &[u8]) -> Option<ParsedPkt> {
    if data.len() < 14 { return None; }
    let (ether_type, payload) = ether_type_and_payload(data);
    match ether_type {
        0x0800 => parse_ipv4(payload),
        0x86DD => parse_ipv6(payload),
        _ => None,
    }
}

fn parse_ipv4(payload: &[u8]) -> Option<ParsedPkt> {
    if payload.len() < 20 { return None; }
    let v_ihl = payload[0];
    if v_ihl >> 4 != 4 { return None; }
    let ihl = (v_ihl & 0x0F) as usize * 4;
    if ihl < 20 || payload.len() < ihl { return None; }
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let proto = payload[9];
    let src = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    if proto != 6 { return None; } // TCP only
    let l4 = payload.get(ihl..total_len.min(payload.len()))?;
    let (sport, dport, ack, flags, tcp_hdr_len) = parse_tcp(l4)?;
    let l4_payload_len = l4.len().saturating_sub(tcp_hdr_len);
    Some(ParsedPkt {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        sport, dport, proto,
        payload_len: l4_payload_len as u32,
        ack,
        tcp_flags: flags,
        ts: Instant::now(),
    })
}

fn parse_ipv6(payload: &[u8]) -> Option<ParsedPkt> {
    if payload.len() < 40 { return None; }
    if payload[0] >> 4 != 6 { return None; }
    let next_hdr = payload[6];
    if next_hdr != 6 { return None; } // skip extension headers — TCP-direct only
    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let src_b: [u8; 16] = payload[8..24].try_into().ok()?;
    let dst_b: [u8; 16] = payload[24..40].try_into().ok()?;
    let l4 = payload.get(40..40 + payload_len.min(payload.len() - 40))?;
    let (sport, dport, ack, flags, tcp_hdr_len) = parse_tcp(l4)?;
    let l4_payload_len = l4.len().saturating_sub(tcp_hdr_len);
    Some(ParsedPkt {
        src: IpAddr::V6(Ipv6Addr::from(src_b)),
        dst: IpAddr::V6(Ipv6Addr::from(dst_b)),
        sport, dport, proto: 6,
        payload_len: l4_payload_len as u32,
        ack,
        tcp_flags: flags,
        ts: Instant::now(),
    })
}

fn parse_tcp(l4: &[u8]) -> Option<(u16, u16, u32, u8, usize)> {
    if l4.len() < 20 { return None; }
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
    let data_off = (l4[12] >> 4) as usize * 4;
    if data_off < 20 { return None; }
    let flags = l4[13];
    Some((sport, dport, ack, flags, data_off))
}

fn extract_ips(data: &[u8]) -> [Option<IpAddr>; 2] {
    if data.len() < 14 {
        return [None, None];
    }
    let (ether_type, payload) = ether_type_and_payload(data);
    match ether_type {
        0x0800 => ipv4_ips(payload),
        0x86DD => ipv6_ips(payload),
        _ => [None, None],
    }
}

/// Walk 802.1Q VLAN tags (0x8100 / 0x88A8) and return final EtherType + payload.
fn ether_type_and_payload(frame: &[u8]) -> (u16, &[u8]) {
    let mut offset = 12usize; // after dst+src MAC
    loop {
        if frame.len() < offset + 2 {
            return (0, &[]);
        }
        let et = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        offset += 2;
        if et == 0x8100 || et == 0x88A8 {
            // 2-byte VLAN tag follows, then another EtherType
            offset += 2;
        } else {
            return (et, &frame[offset..]);
        }
    }
}

fn ipv4_ips(payload: &[u8]) -> [Option<IpAddr>; 2] {
    if payload.len() < 20 {
        return [None, None];
    }
    let src = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    [Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))]
}

fn ipv6_ips(payload: &[u8]) -> [Option<IpAddr>; 2] {
    if payload.len() < 40 {
        return [None, None];
    }
    let src = read_ipv6(&payload[8..24]);
    let dst = read_ipv6(&payload[24..40]);
    [Some(IpAddr::V6(src)), Some(IpAddr::V6(dst))]
}

fn read_ipv6(b: &[u8]) -> Ipv6Addr {
    let a: [u8; 16] = b[..16].try_into().unwrap();
    Ipv6Addr::from(a)
}

// ── private IP filter ─────────────────────────────────────────────────────────

fn is_private(ip: IpAddr) -> bool {
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
            b == [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]
            || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
            || b[0] == 0xff
            || (b[0] & 0xfe) == 0xfc
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_v4() {
        assert!(is_private("10.0.0.1".parse().unwrap()));
        assert!(is_private("192.168.1.1".parse().unwrap()));
        assert!(is_private("172.16.5.5".parse().unwrap()));
        assert!(is_private("127.0.0.1".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
        assert!(!is_private("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn private_v6() {
        assert!(is_private("::1".parse().unwrap()));
        assert!(is_private("fe80::1".parse().unwrap()));
        assert!(is_private("fc00::1".parse().unwrap()));
        assert!(!is_private("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn vlan_tag_skipped() {
        let mut frame = vec![0u8; 14 + 4 + 20];
        frame[12] = 0x81; frame[13] = 0x00;
        frame[14] = 0x00; frame[15] = 0x01;
        frame[16] = 0x08; frame[17] = 0x00;
        frame[30] = 8; frame[31] = 8; frame[32] = 8; frame[33] = 8;
        frame[34] = 1; frame[35] = 1; frame[36] = 1; frame[37] = 1;
        let ips = extract_ips(&frame);
        assert_eq!(ips[0], Some("8.8.8.8".parse().unwrap()));
        assert_eq!(ips[1], Some("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv4_tcp_extracts_ports_and_payload() {
        // Eth(14) + IPv4(20) + TCP(20) + payload(5)
        let mut f = vec![0u8; 14 + 20 + 20 + 5];
        f[12] = 0x08; f[13] = 0x00; // EtherType IPv4
        f[14] = 0x45;               // version=4, IHL=5
        let total_len = (20 + 20 + 5) as u16;
        f[16] = (total_len >> 8) as u8; f[17] = total_len as u8;
        f[23] = 6;                  // proto = TCP
        f[26] = 10; f[27] = 0; f[28] = 0; f[29] = 1;        // src 10.0.0.1
        f[30] = 8;  f[31] = 8; f[32] = 8;  f[33] = 8;       // dst 8.8.8.8
        // TCP @ offset 34
        f[34] = 0xAB; f[35] = 0xCD; // sport
        f[36] = 0x01; f[37] = 0xBB; // dport 443
        f[42] = 0; f[43] = 0; f[44] = 0; f[45] = 0x10;       // ack
        f[46] = 0x50;               // data offset = 5*4 = 20
        f[47] = 0x18;               // flags PSH+ACK
        let p = parse_l3l4(&f).unwrap();
        assert_eq!(p.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(p.sport, 0xABCD);
        assert_eq!(p.dport, 443);
        assert_eq!(p.ack, 0x10);
        assert_eq!(p.payload_len, 5);
        assert_eq!(p.tcp_flags, 0x18);
    }
}
