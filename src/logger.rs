//! Minimal stderr logger implementing the `log` facade.
//!
//! Format:  `2026-05-08 12:34:56 [WARN ] capstone::capture: message`
//! Level:   reads `CAPSTONE_LOG` env var (trace/debug/info/warn/error), default = info.

use std::sync::atomic::{AtomicUsize, Ordering};
use log::{LevelFilter, Log, Metadata, Record};

static MAX_LEVEL: AtomicUsize = AtomicUsize::new(LevelFilter::Info as usize);

struct Logger;

static LOGGER: Logger = Logger;

impl Log for Logger {
    fn enabled(&self, meta: &Metadata) -> bool {
        (meta.level() as usize) <= MAX_LEVEL.load(Ordering::Relaxed)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let ts = timestamp();
        // Shorten "capstone::foo::bar" → "foo::bar" for readability
        let target = record.target()
            .strip_prefix("capstone::")
            .unwrap_or(record.target());
        eprintln!("{ts} [{:5}] {target}: {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

pub fn init() {
    let level = parse_env_level().unwrap_or(LevelFilter::Info);
    MAX_LEVEL.store(level as usize, Ordering::Relaxed);
    log::set_logger(&LOGGER).ok(); // fails silently if already set
    log::set_max_level(level);
}

fn parse_env_level() -> Option<LevelFilter> {
    let val = std::env::var("CAPSTONE_LOG").ok()?;
    match val.to_ascii_lowercase().as_str() {
        "trace" => Some(LevelFilter::Trace),
        "debug" => Some(LevelFilter::Debug),
        "info"  => Some(LevelFilter::Info),
        "warn"  => Some(LevelFilter::Warn),
        "error" => Some(LevelFilter::Error),
        "off"   => Some(LevelFilter::Off),
        _       => None,
    }
}

// ── timestamp (no external crate) ─────────────────────────────────────────────

fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let days = secs / 86400;
    let rem  = secs % 86400;
    let hh   = rem / 3600;
    let mm   = (rem % 3600) / 60;
    let ss   = rem % 60;

    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z   = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
