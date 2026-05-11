#![allow(dead_code)] // fields wired progressively; all used by final phase

use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub ip_to_domain: IpToDomainConfig,
    #[serde(default)]
    pub prefilter: PrefilterConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoreConfig {
    pub db_path: String,
    pub snapshot_dir: String,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            db_path: "~/.local/share/capstone/capstone.db".into(),
            snapshot_dir: "~/.local/share/capstone/snapshots".into(),
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub pcap_file: Option<String>,
    #[serde(default = "default_ip_cooldown")]
    pub ip_cooldown_s: u64,
    #[serde(default = "default_true")]
    pub skip_private: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProbeConfig {
    #[serde(default = "default_probe_timeout")]
    pub timeout_s: f64,
    #[serde(default = "default_max_assets")]
    pub max_assets: u32,
    #[serde(default = "default_true")]
    pub screenshot: bool,
    pub chromium: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_s: 15.0,
            max_assets: 50,
            screenshot: true,
            chromium: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct FilterConfig {
    #[serde(default = "default_probe_threshold")]
    pub probe_threshold: u32,
    #[serde(default = "default_watch_threshold")]
    pub watch_threshold: u32,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            probe_threshold: 60,
            watch_threshold: 30,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_workers")]
    pub workers: u32,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            workers: 4,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct IpToDomainConfig {
    #[serde(default = "default_sources")]
    pub sources: Vec<String>,
    pub cache_path: Option<String>,
    #[serde(default = "default_cache_ttl_days")]
    pub cache_ttl_days: u64,
    #[serde(default)]
    pub verify_doh: bool,
}

impl Default for IpToDomainConfig {
    fn default() -> Self {
        Self {
            sources: vec!["ptr".into(), "hackertarget".into()],
            cache_path: None,
            cache_ttl_days: default_cache_ttl_days(),
            verify_doh: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrefilterConfig {
    #[serde(default)]
    pub enabled: bool,
    pub model_path: Option<String>,
    pub labels_path: Option<String>,
    #[serde(default = "default_length_dim")]
    pub length_dim: usize,
    #[serde(default = "default_select_dir")]
    pub select_dir: u8,
    #[serde(default = "default_flow_timeout")]
    pub flow_timeout_s: u64,
    #[serde(default = "default_max_flows")]
    pub max_flows: usize,
    #[serde(default = "default_true")]
    pub benign_skip: bool,
    #[serde(default = "default_conf_threshold")]
    pub conf_threshold: f32,
    /// TCP server ports to skip (not trained on these). Configurable so no hardcoding in binary.
    #[serde(default = "default_skip_ports")]
    pub skip_ports: Vec<u16>,
    /// Server IPs to skip (e.g. DNS resolvers whose DoH traffic is not training data).
    #[serde(default)]
    pub skip_ips: Vec<String>,
}

impl Default for PrefilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model_path: None,
            labels_path: None,
            length_dim: default_length_dim(),
            select_dir: default_select_dir(),
            flow_timeout_s: default_flow_timeout(),
            max_flows: default_max_flows(),
            benign_skip: true,
            conf_threshold: default_conf_threshold(),
            skip_ports: default_skip_ports(),
            skip_ips: vec![],
        }
    }
}

fn default_skip_ports() -> Vec<u16> {
    // Non-web service ports — prefilter is trained on HTTP/HTTPS streaming traffic.
    // Override in capstone.toml [prefilter] skip_ports = [...] if needed.
    vec![22, 23, 25, 53, 110, 123, 143, 389, 3478, 5353]
}

fn default_length_dim() -> usize { 10 }
fn default_select_dir() -> u8 { 1 }
fn default_flow_timeout() -> u64 { 30 }
fn default_max_flows() -> usize { 10_000 }
fn default_conf_threshold() -> f32 { 0.5 }

fn default_ip_cooldown() -> u64 {
    60
}
fn default_true() -> bool {
    true
}
fn default_probe_timeout() -> f64 {
    15.0
}
fn default_max_assets() -> u32 {
    50
}
fn default_probe_threshold() -> u32 {
    60
}
fn default_watch_threshold() -> u32 {
    30
}
fn default_bind() -> String {
    "127.0.0.1:8080".into()
}
fn default_workers() -> u32 {
    4
}
fn default_sources() -> Vec<String> {
    vec!["passive-dns".into(), "ptr".into(), "hackertarget".into()]
}
fn default_cache_ttl_days() -> u64 {
    7
}

impl Config {
    /// Load from `capstone.toml` in current dir, then `~/.config/capstone/capstone.toml`.
    /// Returns default config (not an error) if no file found.
    pub fn load() -> Self {
        let candidates: &[&str] = &["capstone.toml", "~/.config/capstone/capstone.toml"];
        for path in candidates {
            let expanded = crate::paths::expand_tilde(path);
            if let Ok(text) = std::fs::read_to_string(&expanded) {
                match toml::from_str::<Config>(&text) {
                    Ok(cfg) => return cfg,
                    Err(e) => log::error!("parse error in {expanded}: {e}"),
                }
            }
        }
        Config::default()
    }
}
