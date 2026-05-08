//! HTML content fingerprinting for cross-domain similarity detection.
//!
//! Mirrors the Python utils/html_similarity shape_content_weighted algorithm
//! (AUC=0.9860) without a DOM parser dependency:
//!
//!   score = 0.85 × tag_bigram_jaccard  +  0.15 × content_jaccard
//!
//! tag_bigram_jaccard  ≈ s1 (structural shape-type Jaccard in the Python)
//! content_jaccard     ≈ s2 (text-quality ratio, Python mixes text + CSS classes)
//!
//! SimHash kept as a fast pre-filter / identical-clone detector.

use std::collections::HashSet;

// ── noise tags: block content removed entirely (matches preprocessor.py) ──────

const BLOCK_SKIP: &[&str] = &[
    "script", "style", "head", "link", "meta", "noscript", "iframe", "svg", "canvas", "template",
];

// ── structural tags that enter the topology signal (_tree_utils.py) ───────────

const STRUCTURAL: &[&str] = &[
    "html",
    "body",
    "div",
    "section",
    "article",
    "aside",
    "main",
    "header",
    "footer",
    "nav",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tfoot",
    "tr",
    "th",
    "td",
    "form",
    "input",
    "button",
    "select",
    "textarea",
    "label",
    "figure",
    "figcaption",
];

// void elements in STRUCTURAL that never push onto the nesting stack
const VOID_STRUCTURAL: &[&str] = &["input"];

// ── public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct PageFingerprint {
    /// 64-bit SimHash over visible-text byte trigrams — fast clone pre-filter.
    pub simhash: i64,
    pub title: Option<String>,
    pub h1: Option<String>,
    /// Visible-text word tokens (len >= 2, lowercase), matching Python _tokenize.
    pub word_tokens: HashSet<String>,
    /// Structural tag parent→child bigrams, e.g. "nav>ul", "form>input".
    /// First-order topology; far lower false-positive rate than tag-type presence alone.
    pub tag_bigrams: HashSet<String>,
    /// CSS class attribute tokens. Template-sharing signal.
    pub css_classes: HashSet<String>,
}

#[derive(Debug, PartialEq)]
pub enum Similarity {
    /// SimHash identical: bit-exact clone / mirror.
    Identical,
    /// shape_content_score >= 0.65 AND simhash Hamming <= 3.
    High,
    /// shape_content_score >= 0.50 OR simhash Hamming <= 6.
    Moderate,
    /// score >= 0.30 AND (title/h1 Levenshtein >= 0.80 OR css_jaccard >= 0.70).
    Corroborated,
    Distinct,
}

// ── public API ────────────────────────────────────────────────────────────────

pub fn fingerprint(html: &str) -> PageFingerprint {
    let clean = strip_noise_blocks(html);
    let text = visible_text(&clean);
    PageFingerprint {
        simhash: simhash_text(&text),
        title: extract_tag_text(html, "title"), // raw: title lives in blocked <head>
        h1: extract_tag_text(&clean, "h1"),
        word_tokens: tokenize(&text),
        tag_bigrams: extract_tag_bigrams(&clean),
        css_classes: extract_css_classes(&clean),
    }
}

/// shape_content_weighted score [0.0, 1.0]: 0.85 × s1 + 0.15 × s2
///
/// s1 = tag-bigram Jaccard (parent→child structural pairs)
/// s2 = Jaccard of (word_tokens ∪ css_classes), matching Python's combined token pool
pub fn shape_content_score(a: &PageFingerprint, b: &PageFingerprint) -> f32 {
    let s1 = jaccard_str(&a.tag_bigrams, &b.tag_bigrams);

    // merge word tokens + css classes into one pool (matches Python text_tokens ∪ css_classes)
    let pool_a: HashSet<&String> = a.word_tokens.iter().chain(a.css_classes.iter()).collect();
    let pool_b: HashSet<&String> = b.word_tokens.iter().chain(b.css_classes.iter()).collect();
    let s2 = {
        if pool_a.is_empty() && pool_b.is_empty() {
            1.0
        } else if pool_a.is_empty() || pool_b.is_empty() {
            0.0
        } else {
            let inter = pool_a.intersection(&pool_b).count();
            let union = pool_a.len() + pool_b.len() - inter;
            inter as f32 / union as f32
        }
    };

    0.85 * s1 + 0.15 * s2
}

pub fn css_jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    jaccard_str(a, b)
}

pub fn hamming(a: i64, b: i64) -> u32 {
    (a ^ b).count_ones()
}

/// Levenshtein similarity ratio [0.0, 1.0]. Char-safe, handles Korean/Unicode. Capped at 200 chars.
pub fn title_similarity(a: &str, b: &str) -> f32 {
    let a: String = a.trim().chars().take(200).collect();
    let b: String = b.trim().chars().take(200).collect();
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let ca = a.chars().count();
    let cb = b.chars().count();
    1.0 - levenshtein(&a, &b) as f32 / ca.max(cb) as f32
}

pub fn classify(a: &PageFingerprint, b: &PageFingerprint) -> Similarity {
    if a.simhash == b.simhash {
        return Similarity::Identical;
    }

    let sc = shape_content_score(a, b);
    let h = hamming(a.simhash, b.simhash);

    if sc >= 0.65 && h <= 3 {
        return Similarity::High;
    }
    if sc >= 0.50 || h <= 6 {
        return Similarity::Moderate;
    }

    if sc >= 0.30 {
        let title_ok = matches!((&a.title, &b.title),
            (Some(ta), Some(tb)) if title_similarity(ta, tb) >= 0.80);
        let h1_ok = matches!((&a.h1, &b.h1),
            (Some(ha), Some(hb)) if title_similarity(ha, hb) >= 0.80);
        let css_ok = css_jaccard(&a.css_classes, &b.css_classes) >= 0.70;
        if title_ok || h1_ok || css_ok {
            return Similarity::Corroborated;
        }
    }

    Similarity::Distinct
}

// ── preprocessing: remove noise blocks + HTML comments ───────────────────────

fn strip_noise_blocks(html: &str) -> String {
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut out = Vec::with_capacity(len);
    let mut i = 0;

    while i < len {
        if bytes[i] == b'<' {
            // HTML comment: <!-- ... -->
            if bytes.get(i + 1) == Some(&b'!')
                && bytes.get(i + 2) == Some(&b'-')
                && bytes.get(i + 3) == Some(&b'-')
            {
                match find_close(bytes, i + 4, b"-->") {
                    Some(pos) => {
                        i = pos + 3;
                        continue;
                    }
                    None => break,
                }
            }

            let name = read_opening_tag_name(bytes, i + 1);
            if let Some(&skip) = BLOCK_SKIP.iter().find(|&&t| t == name.as_str()) {
                let close = format!("</{}>", skip);
                match find_close(bytes, i, close.as_bytes()) {
                    Some(pos) => {
                        i = pos + close.len();
                        continue;
                    }
                    None => break,
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ── visible text extraction (operates on pre-cleaned HTML) ───────────────────

fn visible_text(clean: &str) -> String {
    let bytes = clean.as_bytes();
    let len = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(len / 3);
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'<' => {
                while i < len && bytes[i] != b'>' {
                    i += 1;
                }
                i += 1;
                if out.last() != Some(&b' ') {
                    out.push(b' ');
                }
            }
            b'&' => {
                // skip entity reference (e.g. &nbsp; → skip, not "nbsp")
                let j = i + 1;
                if let Some(off) = bytes[j..].iter().take(8).position(|&b| b == b';') {
                    i = j + off + 1;
                } else {
                    i += 1;
                }
            }
            b if b.is_ascii_whitespace() => {
                if out.last() != Some(&b' ') {
                    out.push(b' ');
                }
                i += 1;
            }
            b if b.is_ascii_alphanumeric() => {
                out.push(b.to_ascii_lowercase());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).trim().to_string()
}

// ── tag topology: parent→child bigrams ───────────────────────────────────────

fn extract_tag_bigrams(clean: &str) -> HashSet<String> {
    let bytes = clean.as_bytes();
    let mut bigrams: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = vec!["_root".to_string()];
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'<' && i + 1 < bytes.len() {
            let is_close = bytes[i + 1] == b'/';
            let name = if is_close {
                read_opening_tag_name(bytes, i + 2)
            } else {
                read_opening_tag_name(bytes, i + 1)
            };

            if !name.is_empty() && STRUCTURAL.contains(&name.as_str()) {
                if is_close {
                    if let Some(pos) = stack.iter().rposition(|t| t == &name) {
                        stack.truncate(pos);
                    }
                } else {
                    if let Some(parent) = stack.last() {
                        bigrams.insert(format!("{}>{}", parent, name));
                    }
                    if !VOID_STRUCTURAL.contains(&name.as_str()) {
                        stack.push(name);
                    }
                }
            }

            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
        }
        i += 1;
    }

    bigrams
}

// ── CSS class extraction (operates on pre-cleaned HTML) ──────────────────────

fn extract_css_classes(clean: &str) -> HashSet<String> {
    let bytes = clean.as_bytes();
    let mut classes = HashSet::new();
    let mut i = 0;

    while i + 6 < bytes.len() {
        let chunk = [
            bytes[i].to_ascii_lowercase(),
            bytes[i + 1].to_ascii_lowercase(),
            bytes[i + 2].to_ascii_lowercase(),
            bytes[i + 3].to_ascii_lowercase(),
            bytes[i + 4].to_ascii_lowercase(),
            bytes[i + 5].to_ascii_lowercase(),
        ];
        if &chunk == b"class=" {
            i += 6;
            let end_char = match bytes.get(i) {
                Some(b'"') => {
                    i += 1;
                    b'"'
                }
                Some(b'\'') => {
                    i += 1;
                    b'\''
                }
                _ => b' ',
            };
            let start = i;
            while i < bytes.len() && bytes[i] != end_char && bytes[i] != b'>' {
                i += 1;
            }
            if let Ok(v) = std::str::from_utf8(&bytes[start..i]) {
                for tok in v.split_ascii_whitespace() {
                    if !tok.is_empty() {
                        classes.insert(tok.to_ascii_lowercase());
                    }
                }
            }
            continue;
        }
        i += 1;
    }

    classes
}

// ── tag text extraction (case-insensitive, no full lowercase allocation) ──────

fn extract_tag_text(html: &str, tag: &str) -> Option<String> {
    let bytes = html.as_bytes();
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let tag_start = find_close(bytes, 0, open.as_bytes())?;
    let content_start = bytes[tag_start..].iter().position(|&b| b == b'>')? + tag_start + 1;
    let content_end = find_close(bytes, content_start, close.as_bytes())?;

    let raw = strip_tags(&html[content_start..content_end]);
    let t = raw.trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ => {
                if !in_tag {
                    out.push(c);
                }
            }
        }
    }
    out
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn read_opening_tag_name(bytes: &[u8], start: usize) -> String {
    bytes[start..]
        .iter()
        .take(16)
        .map(|b| b.to_ascii_lowercase())
        .take_while(|b| b.is_ascii_alphanumeric())
        .map(|b| b as char)
        .collect()
}

fn find_close(bytes: &[u8], from: usize, close: &[u8]) -> Option<usize> {
    let cl = close.len();
    if cl == 0 {
        return Some(from);
    }
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

fn tokenize(text: &str) -> HashSet<String> {
    text.split_ascii_whitespace()
        .filter(|w| w.len() >= 2)
        .map(|w| w.to_ascii_lowercase())
        .collect()
}

fn jaccard_str(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    inter as f32 / (a.len() + b.len() - inter) as f32
}

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
    fn identical_zero_hamming() {
        let fp = fingerprint("<html><body><h1>Hello</h1><p>content here</p></body></html>");
        assert_eq!(hamming(fp.simhash, fp.simhash), 0);
    }

    #[test]
    fn similar_pages_low_hamming() {
        let a = "<html><body><h1>Acme</h1><p>We sell widgets and gadgets online today.</p></body></html>";
        let b =
            "<html><body><h1>Acme</h1><p>We sell widgets and gadgets online now.</p></body></html>";
        assert!(hamming(fingerprint(a).simhash, fingerprint(b).simhash) <= 6);
    }

    #[test]
    fn distinct_pages_high_hamming() {
        let a = fingerprint("<html><body><p>Buy cheap flights to Paris today</p></body></html>");
        let b =
            fingerprint("<html><body><p>Quantum computing breakthroughs in 2025</p></body></html>");
        assert!(hamming(a.simhash, b.simhash) > 6);
    }

    #[test]
    fn noise_tags_excluded() {
        let noisy = "<html><body><script>var x=1; document.createElement('div')</script>\
                     <noscript>enable js</noscript><p>hello</p></body></html>";
        let clean = "<html><body><p>hello</p></body></html>";
        // script content must not pollute word tokens or struct tags
        let fp_n = fingerprint(noisy);
        let fp_c = fingerprint(clean);
        assert_eq!(hamming(fp_n.simhash, fp_c.simhash), 0);
        assert!(
            !fp_n.word_tokens.contains("createelement"),
            "script content must not enter word tokens"
        );
    }

    #[test]
    fn html_comments_excluded() {
        let with_comment =
            "<html><body><!-- if (x > 0) { hidden content } --><p>hello</p></body></html>";
        let without_comment = "<html><body><p>hello</p></body></html>";
        assert_eq!(
            hamming(
                fingerprint(with_comment).simhash,
                fingerprint(without_comment).simhash
            ),
            0
        );
    }

    #[test]
    fn entity_refs_not_in_word_tokens() {
        let html = "<html><body><p>Terms &amp; Conditions &nbsp; privacy</p></body></html>";
        let fp = fingerprint(html);
        assert!(
            !fp.word_tokens.contains("amp"),
            "&amp; must not produce 'amp' token"
        );
        assert!(
            !fp.word_tokens.contains("nbsp"),
            "&nbsp; must not produce 'nbsp' token"
        );
        assert!(fp.word_tokens.contains("terms"));
        assert!(fp.word_tokens.contains("conditions"));
        assert!(fp.word_tokens.contains("privacy"));
    }

    #[test]
    fn self_closing_input_in_bigrams() {
        let html = "<html><body><form><input/><button>ok</button></form></body></html>";
        let fp = fingerprint(html);
        // input as XHTML self-close must not produce "input/"
        assert!(
            fp.tag_bigrams.contains("form>input"),
            "form>input bigram expected"
        );
        assert!(
            fp.tag_bigrams.contains("form>button"),
            "form>button bigram expected"
        );
    }

    #[test]
    fn tag_bigrams_topology() {
        let html = "<html><body><nav><ul><li>A</li></ul></nav>\
                    <main><article><h1>Title</h1></article></main></body></html>";
        let fp = fingerprint(html);
        assert!(fp.tag_bigrams.contains("nav>ul"));
        assert!(fp.tag_bigrams.contains("ul>li"));
        assert!(fp.tag_bigrams.contains("main>article"));
        assert!(fp.tag_bigrams.contains("article>h1"));
    }

    #[test]
    fn shape_content_score_same_template() {
        let a = r#"<html><body>
            <nav><ul><li>Home</li><li>About</li></ul></nav>
            <main><article><h1>Acme</h1><p>We build things for you</p></article></main>
            <footer><p>Copyright Acme</p></footer></body></html>"#;
        let b = r#"<html><body>
            <nav><ul><li>Home</li><li>Contact</li></ul></nav>
            <main><article><h1>Acme</h1><p>We make stuff for clients</p></article></main>
            <footer><p>Copyright Acme 2025</p></footer></body></html>"#;
        let sc = shape_content_score(&fingerprint(a), &fingerprint(b));
        assert!(
            sc >= 0.50,
            "same-template pages should score >= 0.50, got {sc:.3}"
        );
    }

    #[test]
    fn shape_content_score_different_structure() {
        // table-heavy page vs form-heavy page — same tag vocab but different topology
        let a = r#"<html><body><table><thead><tr><th>Col</th></tr></thead>
                   <tbody><tr><td>Data</td></tr></tbody></table></body></html>"#;
        let b = r#"<html><body><form><label>Name</label><input/>
                   <select><option>A</option></select>
                   <button>Submit</button></form></body></html>"#;
        let sc = shape_content_score(&fingerprint(a), &fingerprint(b));
        assert!(
            sc < 0.50,
            "structurally different pages should score < 0.50, got {sc:.3}"
        );
    }

    #[test]
    fn title_extraction() {
        let html = "<html><head><title>Acme Corp — Home</title></head><body></body></html>";
        assert_eq!(fingerprint(html).title.as_deref(), Some("Acme Corp — Home"));
    }

    #[test]
    fn title_similarity_unicode_safe() {
        // Korean titles must not panic (multibyte UTF-8)
        let a = "링크킹 – 무료 애니메이션 스트리밍";
        let b = "링크킹 TV – 애니메이션";
        let sim = title_similarity(a, b);
        assert!(
            sim > 0.0 && sim <= 1.0,
            "title_similarity out of range: {sim}"
        );
    }

    #[test]
    fn title_similarity_values() {
        assert!(title_similarity("Acme Corp Home", "Acme Corp Homepage") >= 0.70);
        assert!(title_similarity("Buy Flights", "Quantum Physics Journal") < 0.40);
    }

    #[test]
    fn css_classes_extracted() {
        let html =
            r#"<div class="navbar container-fluid"><p class="text-primary btn">hi</p></div>"#;
        let fp = fingerprint(html);
        assert!(fp.css_classes.contains("navbar"));
        assert!(fp.css_classes.contains("container-fluid"));
        assert!(fp.css_classes.contains("btn"));
    }

    #[test]
    fn classify_identical() {
        let fp = fingerprint("<p>same content same content same content</p>");
        assert_eq!(classify(&fp, &fp), Similarity::Identical);
    }

    #[test]
    fn word_tokens_min_length() {
        let fp = fingerprint("<p>a bb ccc dddd</p>");
        assert!(
            !fp.word_tokens.contains("a"),
            "single-char words must be excluded"
        );
        assert!(fp.word_tokens.contains("bb"));
        assert!(fp.word_tokens.contains("ccc"));
    }
}
