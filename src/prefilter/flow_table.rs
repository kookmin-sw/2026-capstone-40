//! Per-flow accumulator. Buffers `(len, ack, dir)` until enough `select_dir`
//! packets are seen for ARI feature extraction, then surfaces the flow for
//! classification.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::types::{FlowKey, FlowState, ParsedPkt, Side, DIR_C2S, DIR_S2C};

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

pub struct FlowTable {
    flows: HashMap<FlowKey, FlowState>,
    pub ready_dim: usize,
    pub select_dir: u8,
    pub timeout: Duration,
    pub max_flows: usize,
    skip_ports: Vec<u16>,
    skip_ips: Vec<std::net::IpAddr>,
}

impl FlowTable {
    pub fn new(
        ready_dim: usize,
        select_dir: u8,
        timeout: Duration,
        max_flows: usize,
        skip_ports: Vec<u16>,
        skip_ips: Vec<std::net::IpAddr>,
    ) -> Self {
        Self { flows: HashMap::new(), ready_dim, select_dir, timeout, max_flows, skip_ports, skip_ips }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn ingest(&mut self, pkt: &ParsedPkt) {
        if pkt.proto != 6 {
            return;
        }
        let server_port = pkt.sport.min(pkt.dport);
        if self.skip_ports.contains(&server_port) {
            return;
        }
        if self.skip_ips.contains(&pkt.src) || self.skip_ips.contains(&pkt.dst) {
            return;
        }

        let key = pkt.key();
        let now = pkt.ts;

        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.evict_oldest();
        }

        let state = self.flows.entry(key).or_insert_with(|| FlowState {
            key,
            server_side: Side::Unknown,
            guessed: true,
            lens: Vec::with_capacity(16),
            dirs: Vec::with_capacity(16),
            acks: Vec::with_capacity(16),
            last_seen: now,
            created: now,
            classified: false,
        });

        // Resolve server side. SYN-only (no ACK) → packet originator is client.
        // SYN+ACK → originator is server. Otherwise fall back to lower-port heuristic.
        if matches!(state.server_side, Side::Unknown) {
            let syn = (pkt.tcp_flags & TCP_FLAG_SYN) != 0;
            let ack = (pkt.tcp_flags & TCP_FLAG_ACK) != 0;
            if syn && !ack {
                // src = client → server is the OTHER endpoint
                state.server_side = side_of_endpoint(state.key, pkt.dst, pkt.dport);
                state.guessed = false;
            } else if syn && ack {
                state.server_side = side_of_endpoint(state.key, pkt.src, pkt.sport);
                state.guessed = false;
            } else {
                // Fallback: lower port = server. Marked guessed.
                let server_endpoint = if state.key.a_port <= state.key.b_port {
                    Side::A
                } else {
                    Side::B
                };
                state.server_side = server_endpoint;
                state.guessed = true;
            }
        }

        let dir = direction_for(pkt, state.server_side, state.key);
        state.lens.push(pkt.payload_len);
        state.acks.push(pkt.ack);
        state.dirs.push(dir);
        state.last_seen = now;
    }

    /// Drain flows that have ≥ `ready_dim` packets in `select_dir`, OR have aged out.
    /// Returns owned `FlowState`s. Aged flows are surfaced even if under-filled
    /// so the caller can decide how to score them.
    pub fn drain_ready(&mut self, now: Instant) -> Vec<FlowState> {
        let mut out = Vec::new();
        let dim = self.ready_dim;
        let select_dir = self.select_dir;
        let timeout = self.timeout;

        let keys: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, s)| {
                if s.classified {
                    return false;
                }
                let in_dir = s.dirs.iter().filter(|&&d| d == select_dir).count();
                in_dir >= dim || now.duration_since(s.last_seen) >= timeout
            })
            .map(|(k, _)| *k)
            .collect();

        for k in keys {
            if let Some(s) = self.flows.remove(&k) {
                out.push(s);
            }
        }
        out
    }

    /// Drop flows idle for longer than `timeout` without surfacing them.
    /// Useful for callers that only want classification on ready flows.
    pub fn evict_stale(&mut self, now: Instant) {
        let timeout = self.timeout;
        self.flows
            .retain(|_, s| now.duration_since(s.last_seen) < timeout);
    }

    fn evict_oldest(&mut self) {
        if let Some((k, _)) = self
            .flows
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(k, s)| (*k, s.last_seen))
        {
            self.flows.remove(&k);
        }
    }
}

fn side_of_endpoint(key: FlowKey, ip: std::net::IpAddr, port: u16) -> Side {
    if key.a_ip == ip && key.a_port == port {
        Side::A
    } else {
        Side::B
    }
}

fn direction_for(pkt: &ParsedPkt, server_side: Side, key: FlowKey) -> u8 {
    let pkt_from_a = pkt.src == key.a_ip && pkt.sport == key.a_port;
    let from_server = match server_side {
        Side::A => pkt_from_a,
        Side::B => !pkt_from_a,
        Side::Unknown => return DIR_S2C, // shouldn't happen post-resolve
    };
    if from_server { DIR_S2C } else { DIR_C2S }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    fn ipv4(s: &str) -> IpAddr { s.parse().unwrap() }

    fn pkt(
        src: IpAddr, dst: IpAddr, sport: u16, dport: u16,
        len: u32, ack: u32, flags: u8, ts: Instant,
    ) -> ParsedPkt {
        ParsedPkt {
            src, dst, sport, dport, proto: 6,
            payload_len: len, ack, tcp_flags: flags, ts,
        }
    }

    #[test]
    fn syn_resolves_server_side() {
        let mut t = FlowTable::new(3, DIR_S2C, Duration::from_secs(30), 100, vec![], vec![]);
        let now = Instant::now();
        let cli = ipv4("10.0.0.1");
        let srv = ipv4("8.8.8.8");
        // Client SYN
        t.ingest(&pkt(cli, srv, 40000, 443, 0, 0, TCP_FLAG_SYN, now));
        // Server SYN+ACK
        t.ingest(&pkt(srv, cli, 443, 40000, 0, 1, TCP_FLAG_SYN | TCP_FLAG_ACK, now));
        // Server data
        t.ingest(&pkt(srv, cli, 443, 40000, 1400, 1, TCP_FLAG_ACK, now));

        let ready = t.drain_ready(now);
        assert_eq!(ready.len(), 0); // need ≥3 server pkts at dim=3

        // Two more server pkts → ready
        t.ingest(&pkt(srv, cli, 443, 40000, 800, 1, TCP_FLAG_ACK, now));
        t.ingest(&pkt(srv, cli, 443, 40000, 600, 1, TCP_FLAG_ACK, now));
        let ready = t.drain_ready(now);
        assert_eq!(ready.len(), 1);
        let s = &ready[0];
        assert!(!s.guessed);
        let server_pkts: Vec<u32> = s.lens.iter().zip(s.dirs.iter())
            .filter_map(|(l, d)| (*d == DIR_S2C).then_some(*l)).collect();
        assert_eq!(server_pkts, vec![0, 1400, 800, 600]);
    }

    #[test]
    fn aged_flow_drains_even_underfilled() {
        let mut t = FlowTable::new(10, DIR_S2C, Duration::from_millis(10), 100, vec![], vec![]);
        let now = Instant::now();
        let cli = ipv4("10.0.0.1");
        let srv = ipv4("8.8.8.8");
        t.ingest(&pkt(cli, srv, 40000, 443, 0, 0, TCP_FLAG_SYN, now));
        t.ingest(&pkt(srv, cli, 443, 40000, 100, 1, TCP_FLAG_ACK, now));

        // No drain yet
        let later = now + Duration::from_millis(5);
        assert!(t.drain_ready(later).is_empty());

        // Past timeout
        let way_later = now + Duration::from_millis(50);
        let drained = t.drain_ready(way_later);
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn lru_evicts_when_full() {
        let mut t = FlowTable::new(3, DIR_S2C, Duration::from_secs(30), 2, vec![], vec![]);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(10);
        let t2 = t0 + Duration::from_millis(20);

        t.ingest(&pkt(ipv4("10.0.0.1"), ipv4("8.8.8.8"), 1, 80, 100, 1, 0, t0));
        t.ingest(&pkt(ipv4("10.0.0.2"), ipv4("8.8.8.8"), 2, 80, 100, 1, 0, t1));
        assert_eq!(t.len(), 2);
        // Third flow → oldest (10.0.0.1) evicted
        t.ingest(&pkt(ipv4("10.0.0.3"), ipv4("8.8.8.8"), 3, 80, 100, 1, 0, t2));
        assert_eq!(t.len(), 2);
    }
}
