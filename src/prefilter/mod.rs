//! Prefilter — passive ARI flow classifier.
//!
//! Pipeline position: between packet capture and `ip_to_domain`. Buffers TCP
//! flows by 5-tuple, extracts ARI features (`2×dim` length+ACK-delta vector)
//! once enough server→client packets are seen, runs an XGBoost booster
//! (loaded from native JSON, no C deps), and emits a `(FlowKey, PrefilterOutput)`
//! verdict per flow.
//!
//! See `prefilter.md` for the design and `core/utils.py::feature_extraction_ari`
//! in the reference repo for the exact extraction semantics.

pub mod features;
pub mod flow_table;
pub mod labels;
pub mod model;
pub mod types;

use std::path::Path;
use std::time::{Duration, Instant};

pub use flow_table::FlowTable;
pub use labels::{ClassKind, LabelMap};
pub use model::Booster;
pub use types::{FlowKey, FlowState, ParsedPkt, PrefilterOutput, Side, Verdict};

use crate::config::PrefilterConfig;

#[derive(Debug)]
pub enum InitError {
    MissingPath(&'static str),
    Model(model::LoadError),
    Labels(labels::LoadError),
    DimMismatch { expected: usize, got: u32 },
    ClassMismatch { booster: u32, labels: usize },
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPath(s) => write!(f, "missing config path: {s}"),
            Self::Model(e) => write!(f, "model load: {e}"),
            Self::Labels(e) => write!(f, "labels load: {e}"),
            Self::DimMismatch { expected, got } =>
                write!(f, "feature dim mismatch: cfg expects 2*{expected} = {} but model has {got}",
                       expected * 2),
            Self::ClassMismatch { booster, labels } =>
                write!(f, "class count mismatch: booster {booster} vs labels {labels}"),
        }
    }
}

impl std::error::Error for InitError {}

pub struct Prefilter {
    table: FlowTable,
    booster: Booster,
    labels: LabelMap,
    select_dir: u8,
    length_dim: usize,
    conf_threshold: f32,
    pub benign_skip: bool,
}

impl Prefilter {
    pub fn load(cfg: &PrefilterConfig) -> Result<Self, InitError> {
        let model_path = cfg
            .model_path
            .as_ref()
            .ok_or(InitError::MissingPath("prefilter.model_path"))?;
        let labels_path = cfg
            .labels_path
            .as_ref()
            .ok_or(InitError::MissingPath("prefilter.labels_path"))?;

        let model_path = crate::paths::expand_tilde(model_path);
        let labels_path = crate::paths::expand_tilde(labels_path);

        let booster = Booster::load_json_file(Path::new(&model_path)).map_err(InitError::Model)?;
        let labels = LabelMap::load(Path::new(&labels_path)).map_err(InitError::Labels)?;

        // Feature dim: cfg.length_dim * 2 must equal booster.num_feature
        // (zero is allowed when booster doesn't report it).
        let want = (cfg.length_dim * 2) as u32;
        if booster.num_feature != 0 && booster.num_feature != want {
            return Err(InitError::DimMismatch {
                expected: cfg.length_dim,
                got: booster.num_feature,
            });
        }
        if booster.num_class as usize != labels.len() {
            return Err(InitError::ClassMismatch {
                booster: booster.num_class,
                labels: labels.len(),
            });
        }

        Ok(Self {
            table: FlowTable::new(
                cfg.length_dim,
                cfg.select_dir,
                Duration::from_secs(cfg.flow_timeout_s),
                cfg.max_flows,
            ),
            booster,
            labels,
            select_dir: cfg.select_dir,
            length_dim: cfg.length_dim,
            conf_threshold: cfg.conf_threshold,
            benign_skip: cfg.benign_skip,
        })
    }

    pub fn ingest(&mut self, pkt: &ParsedPkt) {
        self.table.ingest(pkt);
    }

    /// Drain ready/aged flows, classify each, return `(key, output)` pairs.
    pub fn drain_classified(&mut self, now: Instant) -> Vec<(FlowKey, PrefilterOutput)> {
        let drained = self.table.drain_ready(now);
        let mut out = Vec::with_capacity(drained.len());
        for s in drained {
            let feat = features::extract_ari(&s.lens, &s.acks, &s.dirs, self.length_dim, self.select_dir);
            let probs = self.booster.predict_proba(&feat);
            let (cid, conf) = argmax(&probs);
            let entry = self.labels.get(cid);
            let class_name = entry.map(|e| e.name.clone()).unwrap_or_else(|| format!("class_{cid}"));
            let typical_domains = entry.map(|e| e.typical_domains.clone()).unwrap_or_default();
            let verdict = self.labels.verdict(cid, conf, self.conf_threshold);
            // Server IP: side B is server by convention when side is resolved;
            // fall back to lower-port heuristic.
            let server_ip = match s.server_side {
                Side::A => s.key.a_ip,
                Side::B => s.key.b_ip,
                Side::Unknown => {
                    if s.key.a_port <= s.key.b_port { s.key.a_ip } else { s.key.b_ip }
                }
            };
            out.push((s.key, PrefilterOutput {
                class_id: cid,
                class_name,
                confidence: conf,
                verdict,
                typical_domains,
                direction_guessed: s.guessed,
                server_ip,
            }));
        }
        out
    }

    pub fn flow_count(&self) -> usize { self.table.len() }
}

fn argmax(p: &[f32]) -> (u32, f32) {
    let mut best_i = 0u32;
    let mut best_v = f32::NEG_INFINITY;
    for (i, &v) in p.iter().enumerate() {
        if v > best_v {
            best_v = v;
            best_i = i as u32;
        }
    }
    (best_i, best_v)
}
