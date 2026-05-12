pub mod baseline;
pub mod suspect;

mod compare;

pub use compare::{probe_and_compare, probe_baseline, ProbeVerdict};
