use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct PageFingerprint {
    /// 64-bit SimHash over visible-text byte trigrams.
    pub simhash: i64,
    pub title: Option<String>,
    pub h1: Option<String>,
    /// Visible-text word tokens, lowercase and at least two bytes long.
    pub word_tokens: HashSet<String>,
    /// Structural tag parent-child bigrams, such as `nav>ul` or `form>input`.
    pub tag_bigrams: HashSet<String>,
    /// Lowercase CSS class attribute tokens.
    pub css_classes: HashSet<String>,
}

#[derive(Debug, PartialEq)]
pub enum Similarity {
    Identical,
    High,
    Moderate,
    Corroborated,
    Distinct,
}
