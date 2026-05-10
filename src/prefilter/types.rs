//! Shared types for the prefilter pipeline.

use std::net::IpAddr;
use std::time::Instant;

/// Server-side direction marker. The training extractor (`select_dir = 1`)
/// treats `1 = server→client`. We mirror that convention.
pub const DIR_C2S: u8 = 0;
pub const DIR_S2C: u8 = 1;

/// 5-tuple flow identifier. Canonicalized so both directions hash equal.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Canonical form: smaller (ip, port) on side A.
    pub fn new(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, proto: u8) -> Self {
        if (src, sport) <= (dst, dport) {
            Self { a_ip: src, b_ip: dst, a_port: sport, b_port: dport, proto }
        } else {
            Self { a_ip: dst, b_ip: src, a_port: dport, b_port: sport, proto }
        }
    }
}

/// A single TCP packet observation handed to the prefilter.
#[derive(Debug, Clone, Copy)]
pub struct ParsedPkt {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub payload_len: u32,
    pub ack: u32,
    pub tcp_flags: u8,
    pub ts: Instant,
}

impl ParsedPkt {
    pub fn key(&self) -> FlowKey {
        FlowKey::new(self.src, self.dst, self.sport, self.dport, self.proto)
    }
}

/// Side resolution. Determines which endpoint is the server.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Side {
    /// Server is endpoint A (canonical).
    A,
    /// Server is endpoint B.
    B,
    /// Unresolved — direction labels guessed.
    Unknown,
}

/// Per-flow rolling state. Bounded growth — we stop appending once enough
/// `select_dir` packets are buffered for feature extraction.
#[derive(Debug)]
pub struct FlowState {
    pub key: FlowKey,
    pub server_side: Side,
    pub guessed: bool,
    pub lens: Vec<u32>,
    pub dirs: Vec<u8>,
    pub acks: Vec<u32>,
    pub last_seen: Instant,
    pub created: Instant,
    pub classified: bool,
}

/// Verdict for a classified flow.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Verdict {
    Benign,
    Known,
    Malicious,
    Unknown,
}

/// Result emitted once a flow is classified.
#[derive(Debug, Clone)]
pub struct PrefilterOutput {
    pub class_id: u32,
    pub class_name: String,
    pub confidence: f32,
    pub verdict: Verdict,
    pub typical_domains: Vec<String>,
    pub direction_guessed: bool,
}
