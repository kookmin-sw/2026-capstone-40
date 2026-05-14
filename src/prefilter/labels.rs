//! Class-id → app metadata. Loaded from a TOML file generated alongside the
//! XGBoost model. Order MUST match `model.classes_` from the training pipeline.

use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;

use super::types::Verdict;

#[derive(Debug, Deserialize, Clone)]
pub struct ClassEntry {
    pub name: String,
    #[serde(default)]
    pub kind: ClassKind,
    #[serde(default)]
    pub typical_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ClassKind {
    #[default]
    Known,
    Benign,
    Malicious,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LabelFile {
    pub classes: Vec<ClassEntry>,
}

#[derive(Debug, Clone)]
pub struct LabelMap {
    pub entries: Vec<ClassEntry>,
}

#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Toml(e) => write!(f, "toml: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}
impl From<std::io::Error> for LoadError { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
impl From<toml::de::Error> for LoadError { fn from(e: toml::de::Error) -> Self { Self::Toml(e) } }

impl LabelMap {
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path)?;
        text.parse()
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn get(&self, class_id: u32) -> Option<&ClassEntry> {
        self.entries.get(class_id as usize)
    }

    pub fn verdict(&self, class_id: u32, confidence: f32, conf_threshold: f32) -> Verdict {
        let Some(e) = self.get(class_id) else { return Verdict::Unknown };
        if confidence < conf_threshold {
            return Verdict::Unknown;
        }
        match e.kind {
            ClassKind::Malicious => Verdict::Malicious,
            ClassKind::Benign => Verdict::Benign,
            ClassKind::Known => Verdict::Known,
        }
    }
}

impl FromStr for LabelMap {
    type Err = LoadError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let lf: LabelFile = toml::from_str(text)?;
        Ok(Self { entries: lf.classes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_class_table() {
        let toml = r#"
[[classes]]
name = "YouTube"
kind = "benign"
typical_domains = ["youtube.com", "googlevideo.com"]

[[classes]]
name = "MalwareC2"
kind = "malicious"

[[classes]]
name = "Zoom"
"#;
        let m: LabelMap = toml.parse().unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(0).unwrap().kind, ClassKind::Benign);
        assert_eq!(m.get(2).unwrap().kind, ClassKind::Known);
        assert!(m.get(0).unwrap().typical_domains.contains(&"youtube.com".to_string()));
    }

    #[test]
    fn verdict_logic() {
        let toml = r#"
[[classes]]
name = "YouTube"
kind = "benign"

[[classes]]
name = "C2"
kind = "malicious"

[[classes]]
name = "Other"
"#;
        let m: LabelMap = toml.parse().unwrap();
        // Malicious still requires minimum confidence
        assert_eq!(m.verdict(1, 0.1, 0.5), Verdict::Unknown);
        assert_eq!(m.verdict(1, 0.6, 0.5), Verdict::Malicious);
        // Benign requires confidence
        assert_eq!(m.verdict(0, 0.9, 0.5), Verdict::Benign);
        assert_eq!(m.verdict(0, 0.4, 0.5), Verdict::Unknown);
        // Known
        assert_eq!(m.verdict(2, 0.6, 0.5), Verdict::Known);
        // Out of range
        assert_eq!(m.verdict(99, 1.0, 0.5), Verdict::Unknown);
    }
}
