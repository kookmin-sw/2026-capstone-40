//! HTML content fingerprinting for cross-domain similarity detection.
//!
//! Signals (mirrors utils/html_similarity Python evaluation):
//!   - SimHash on visible text trigrams (FNV-1a) — near-duplicate text detection
//!   - CSS class token Jaccard — template/kit sharing even when text differs
//!   - Title + h1 Levenshtein ratio — brand/heading corroboration

use std::collections::HashSet;

// ── public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PageFingerprint {
    pub simhash:    i64,
    pub title:      Option<String>,
    pub h1:         Option<String>,
    /// Unique normalised CSS class tokens extracted from all class="..." attributes.
    pub css_classes: HashSet<String>,
}

#[derive(Debug, PartialEq)]
pub enum Similarity {
    /// Hamming == 0: bit-exact duplicate (mirror / clone)
    Identical,
    /// Hamming <= 3: near-duplicate with very high confidence
    High,
    /// Hamming <= 6: strong content overlap (rebrand / migration)
    Moderate,
    /// Hamming <= 10 AND title or h1 ratio >= 0.80: corroborated by heading text
    Corroborated,
    Distinct,
}

// ── public API ────────────────────────────────────────────────────────────────

pub fn fingerprint(html: &str) -> PageFingerprint {
    let text = visible_text(html);
    PageFingerprint {
        simhash:     simhash_text(&text),
        title:       extract_tag_text(html, "title"),
        h1:          extract_tag_text(html, "h1"),
        css_classes: extract_css_classes(html),
    }
}

/// Jaccard similarity of CSS class token sets: |A ∩ B| / |A ∪ B|.
pub fn css_jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() { return 1.0; }
    if a.is_empty() || b.is_empty() { return 0.0; }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    inter as f32 / union as f32
}

pub fn hamming(a: i64, b: i64) -> u32 {
    (a ^ b).count_ones()
}

/// Levenshtein similarity ratio in [0.0, 1.0]. Inputs capped at 200 chars.
pub fn title_similarity(a: &str, b: &str) -> f32 {
    let a = a.trim();
    let b = b.trim();
    let a = &a[..a.len().min(200)];
    let b = &b[..b.len().min(200)];
    if a.is_empty() && b.is_empty() { return 1.0; }
    if a.is_empty() || b.is_empty() { return 0.0; }
    let dist = levenshtein(a, b);
    1.0 - dist as f32 / a.len().max(b.len()) as f32
}

pub fn classify(a: &PageFingerprint, b: &PageFingerprint) -> Similarity {
    let h = hamming(a.simhash, b.simhash);
    match h {
        0 => Similarity::Identical,
        1..=3 => Similarity::High,
        4..=6 => Similarity::Moderate,
        7..=10 => {
            let title_sim = match (&a.title, &b.title) {
                (Some(ta), Some(tb)) => title_similarity(ta, tb),
                _ => 0.0,
            };
            let h1_sim = match (&a.h1, &b.h1) {
                (Some(ha), Some(hb)) => title_similarity(ha, hb),
                _ => 0.0,
            };
            let css_sim = css_jaccard(&a.css_classes, &b.css_classes);
            if title_sim >= 0.80 || h1_sim >= 0.80 || css_sim >= 0.70 {
                Similarity::Corroborated
            } else {
                Similarity::Distinct
            }
        }
        _ => Similarity::Distinct,
    }
}

// ── visible text extraction ───────────────────────────────────────────────────

fn visible_text(html: &str) -> String {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(len / 3);
    let mut i = 0;

    while i < len {
        if bytes[i] != b'<' {
            let b = bytes[i];
            if b.is_ascii_whitespace() {
                if out.last() != Some(&b' ') {
                    out.push(b' ');
                }
            } else if b.is_ascii_alphanumeric() {
                out.push(b.to_ascii_lowercase());
            }
            i += 1;
            continue;
        }

        // bytes[i] == b'<' — read tag name (up to 10 bytes)
        let name_start = i + 1;
        let name_bytes: Vec<u8> = bytes[name_start..]
            .iter()
            .take(10)
            .map(|b| b.to_ascii_lowercase())
            .take_while(|b| b.is_ascii_alphabetic() || *b == b'/')
            .collect();

        if name_bytes == b"script" || name_bytes == b"style" {
            let close: &[u8] = if name_bytes == b"script" { b"</script>" } else { b"</style>" };
            match find_close(bytes, i, close) {
                Some(pos) => i = pos + close.len(),
                None      => break,
            }
        } else {
            // skip to end of tag
            while i < len && bytes[i] != b'>' {
                i += 1;
            }
            i += 1;
            if out.last() != Some(&b' ') {
                out.push(b' ');
            }
        }
    }

    let s: String = String::from_utf8_lossy(&out).into_owned();
    s.trim().to_string()
}

fn find_close(bytes: &[u8], from: usize, close: &[u8]) -> Option<usize> {
    let cl = close.len();
    if cl == 0 { return Some(from); }
    'outer: for i in from..bytes.len().saturating_sub(cl - 1) {
        for (j, &c) in close.iter().enumerate() {
            if bytes[i + j].to_ascii_lowercase() != c.to_ascii_lowercase() {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

// ── SimHash (FNV-1a over byte trigrams) ───────────────────────────────────────

fn simhash_text(text: &str) -> i64 {
    let bytes = text.as_bytes();
    let mut v = [0i32; 64];

    for w in bytes.windows(3) {
        let h = fnv1a_64(w);
        for bit in 0..64u64 {
            if (h >> bit) & 1 == 1 {
                v[bit as usize] += 1;
            } else {
                v[bit as usize] -= 1;
            }
        }
    }

    let mut fp: u64 = 0;
    for bit in 0..64u64 {
        if v[bit as usize] > 0 {
            fp |= 1 << bit;
        }
    }
    fp as i64
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

// ── tag text extraction ───────────────────────────────────────────────────────

fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open  = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let tag_start = lower.find(&open)?;
    let gt        = lower[tag_start..].find('>')? + tag_start + 1;
    let end       = lower[gt..].find(&close)? + gt;

    let raw = strip_tags(&html[gt..end]);
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _   => if !in_tag { out.push(c); },
        }
    }
    out
}

// ── CSS class extraction ──────────────────────────────────────────────────────

/// Extract all unique normalised CSS class tokens from class="..." attributes.
/// Mirrors the Python shape_content method's "cls:" token pool.
fn extract_css_classes(html: &str) -> HashSet<String> {
    let mut classes = HashSet::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // scan for class= attribute
        if i + 6 < bytes.len() {
            let chunk: Vec<u8> = bytes[i..i + 6]
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect();
            if chunk == b"class=" {
                i += 6;
                // skip optional quote
                let quote = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                    let q = bytes[i];
                    i += 1;
                    q
                } else {
                    b' '
                };
                let end_char = if quote == b'\'' { b'\'' } else { b'"' };
                let start = i;
                while i < bytes.len() && bytes[i] != end_char && bytes[i] != b'>' {
                    i += 1;
                }
                let value = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
                for token in value.split_ascii_whitespace() {
                    if !token.is_empty() {
                        classes.insert(token.to_ascii_lowercase());
                    }
                }
                continue;
            }
        }
        i += 1;
    }
    classes
}

// ── Levenshtein distance ──────────────────────────────────────────────────────

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1]
            } else {
                1 + prev[j - 1].min(prev[j]).min(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_pages_zero_hamming() {
        let html = "<html><body><h1>Hello World</h1><p>Some content here</p></body></html>";
        let fp = fingerprint(html);
        assert_eq!(hamming(fp.simhash, fp.simhash), 0);
    }

    #[test]
    fn similar_pages_low_hamming() {
        let a = "<html><body><h1>Acme Corp</h1><p>We sell widgets and gadgets online today.</p></body></html>";
        let b = "<html><body><h1>Acme Corp</h1><p>We sell widgets and gadgets online now.</p></body></html>";
        let fp_a = fingerprint(a);
        let fp_b = fingerprint(b);
        assert!(hamming(fp_a.simhash, fp_b.simhash) <= 6, "near-identical pages should have low hamming");
    }

    #[test]
    fn distinct_pages_high_hamming() {
        let a = fingerprint("<html><body><p>Buy cheap flights to Paris now</p></body></html>");
        let b = fingerprint("<html><body><p>Quantum computing breakthroughs in 2025</p></body></html>");
        assert!(hamming(a.simhash, b.simhash) > 6);
    }

    #[test]
    fn script_content_excluded() {
        let with_script    = "<html><body><script>var x = 'unrelated javascript';</script><p>hello</p></body></html>";
        let without_script = "<html><body><p>hello</p></body></html>";
        let a = fingerprint(with_script);
        let b = fingerprint(without_script);
        assert_eq!(hamming(a.simhash, b.simhash), 0);
    }

    #[test]
    fn title_extraction() {
        let html = "<html><head><title>Acme Corp — Home</title></head><body></body></html>";
        let fp = fingerprint(html);
        assert_eq!(fp.title.as_deref(), Some("Acme Corp — Home"));
    }

    #[test]
    fn title_similarity_high() {
        assert!(title_similarity("Acme Corp Home", "Acme Corp Homepage") >= 0.70);
    }

    #[test]
    fn title_similarity_distinct() {
        assert!(title_similarity("Buy Flights", "Quantum Physics Journal") < 0.40);
    }

    #[test]
    fn classify_identical() {
        let fp = fingerprint("<p>same content</p>");
        assert_eq!(classify(&fp, &fp), Similarity::Identical);
    }

    #[test]
    fn css_classes_extracted() {
        let html = r#"<div class="navbar container-fluid"><p class="text-primary btn">hi</p></div>"#;
        let fp = fingerprint(html);
        assert!(fp.css_classes.contains("navbar"));
        assert!(fp.css_classes.contains("container-fluid"));
        assert!(fp.css_classes.contains("text-primary"));
        assert!(fp.css_classes.contains("btn"));
    }

    #[test]
    fn css_jaccard_same_template() {
        let a = fingerprint(r#"<div class="navbar hero footer"><p class="btn primary">A</p></div>"#);
        let b = fingerprint(r#"<div class="navbar hero footer"><p class="btn primary">B</p></div>"#);
        assert!(css_jaccard(&a.css_classes, &b.css_classes) >= 0.90);
    }

    #[test]
    fn css_jaccard_different_templates() {
        let a = fingerprint(r#"<div class="sidebar-menu dark-theme rounded">X</div>"#);
        let b = fingerprint(r#"<table class="data-grid striped responsive">Y</table>"#);
        assert!(css_jaccard(&a.css_classes, &b.css_classes) < 0.20);
    }
}
