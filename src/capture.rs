//! Phase 4 — live NIC / PCAP-file packet capture.
//!
//! Extracts unique public IPs from passing frames and forwards them to the
//! caller via an `mpsc::Sender<IpAddr>`.  All filtering (private, cooldown)
//! happens here so workers only see actionable addresses.
//!
//! Thread topology:
//!   capture::run() [blocking, own thread]
//!     └─ Sender<IpAddr> ──► N worker threads  (Phase 3 / 4 wiring)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use pcap::{Active, Capture, Offline};

use crate::config::CaptureConfig;

// ── public entry point ────────────────────────────────────────────────────────

pub fn run(cfg: &CaptureConfig, tx: Sender<IpAddr>) {
    let cooldown = Duration::from_secs(cfg.ip_cooldown_s);
    let skip_priv = cfg.skip_private;
    let mut seen: HashMap<IpAddr, Instant> = HashMap::new();

    match (&cfg.interface, &cfg.pcap_file) {
        (Some(iface), _) => {
            log::info!("opening interface {iface}");
            match Capture::from_device(iface.as_str())
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open())
            {
                Ok(cap)  => pump_live(cap, cfg, cooldown, skip_priv, &mut seen, &tx),
                Err(e)   => log::error!("failed to open {iface}: {e}"),
            }
        }
        (_, Some(path)) => {
            log::info!("reading pcap {path}");
            match Capture::from_file(path) {
                Ok(cap)  => pump_file(cap, cfg, cooldown, skip_priv, &mut seen, &tx),
                Err(e)   => log::error!("failed to open {path}: {e}"),
            }
        }
        (None, None) => {
            log::warn!("no source — set interface or pcap_file in capstone.toml");
        }
    }
}

// ── pumps ─────────────────────────────────────────────────────────────────────

fn pump_live(
    mut cap:       Capture<Active>,
    _cfg:          &CaptureConfig,
    cooldown:      Duration,
    skip_priv:     bool,
    seen:          &mut HashMap<IpAddr, Instant>,
    tx:            &Sender<IpAddr>,
) {
    loop {
        match cap.next_packet() {
            Ok(pkt)  => handle_packet(pkt.data, cooldown, skip_priv, seen, tx),
            Err(pcap::Error::TimeoutExpired) => continue,
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
    tx:        &Sender<IpAddr>,
) {
    loop {
        match cap.next_packet() {
            Ok(pkt) => handle_packet(pkt.data, cooldown, skip_priv, seen, tx),
            Err(_)  => break, // EOF or error — done
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
    tx:        &Sender<IpAddr>,
) {
    for ip in extract_ips(data).into_iter().flatten() {
        if skip_priv && is_private(ip) {
            continue;
        }
        let now = Instant::now();
        if seen.get(&ip).map_or(true, |t| now.duration_since(*t) >= cooldown) {
            seen.insert(ip, now);
            if tx.send(ip).is_err() {
                return; // receiver gone
            }
        }
    }
}

// ── packet parsing (Ethernet → IPv4 / IPv6) ──────────────────────────────────

fn extract_ips(data: &[u8]) -> [Option<IpAddr>; 2] {
    // Ethernet II: 6 dst MAC + 6 src MAC + 2 EtherType
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
    // IPv4 header: version/IHL byte, then 11 bytes to src addr at offset 12
    if payload.len() < 20 {
        return [None, None];
    }
    let src = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    let dst = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    [Some(IpAddr::V4(src)), Some(IpAddr::V4(dst))]
}

fn ipv6_ips(payload: &[u8]) -> [Option<IpAddr>; 2] {
    // IPv6: 40-byte fixed header; src at byte 8, dst at byte 24
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
            // RFC 1918
            o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            // loopback / link-local / multicast / broadcast
            || o[0] == 127
            || (o[0] == 169 && o[1] == 254)
            || o[0] >= 224
        }
        IpAddr::V6(a) => {
            let b = a.octets();
            // loopback (::1)
            b == [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1]
            // link-local (fe80::/10)
            || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)
            // multicast (ff00::/8)
            || b[0] == 0xff
            // unique local (fc00::/7)
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
        // 802.1Q frame: dst(6) + src(6) + 0x8100 + vlan_tag(2) + 0x0800 + ipv4_hdr(20)
        let mut frame = vec![0u8; 14 + 4 + 20];
        frame[12] = 0x81; frame[13] = 0x00; // outer EtherType = 802.1Q
        frame[14] = 0x00; frame[15] = 0x01; // VLAN tag
        frame[16] = 0x08; frame[17] = 0x00; // inner EtherType = IPv4
        // src IP at offset 18+12 = 30 within frame
        frame[30] = 8; frame[31] = 8; frame[32] = 8; frame[33] = 8;
        frame[34] = 1; frame[35] = 1; frame[36] = 1; frame[37] = 1;
        let ips = extract_ips(&frame);
        assert_eq!(ips[0], Some("8.8.8.8".parse().unwrap()));
        assert_eq!(ips[1], Some("1.1.1.1".parse().unwrap()));
    }
}
