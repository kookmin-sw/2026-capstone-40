//! HTML content fingerprinting for cross-domain similarity detection.
//!
//! Mirrors the Python `utils/html_similarity` shape-content approach without a
//! DOM parser dependency:
//!
//!   score = 0.85 x tag_bigram_jaccard + 0.15 x content_jaccard
//!
//! SimHash is kept as a fast pre-filter and identical-clone detector.

mod extract;
mod metrics;
mod simhash;
mod types;

use std::collections::HashSet;

use extract::{
    extract_css_classes, extract_tag_bigrams, extract_tag_text, strip_noise_blocks, tokenize,
    visible_text,
};
use metrics::jaccard_str;
use simhash::simhash_text;

pub use metrics::{css_jaccard, hamming, title_similarity};
pub use types::{PageFingerprint, Similarity};

/// Build all similarity signals used by this module from a raw HTML document.
pub fn fingerprint(html: &str) -> PageFingerprint {
    let clean = strip_noise_blocks(html);
    let text = visible_text(&clean);

    PageFingerprint {
        simhash: simhash_text(&text),
        title: extract_tag_text(html, "title"),
        h1: extract_tag_text(&clean, "h1"),
        word_tokens: tokenize(&text),
        tag_bigrams: extract_tag_bigrams(&clean),
        css_classes: extract_css_classes(&clean),
    }
}

/// Shape-content weighted score in [0.0, 1.0].
///
/// s1 = tag-bigram Jaccard over parent-child structural pairs.
/// s2 = Jaccard of word tokens union CSS classes.
pub fn shape_content_score(a: &PageFingerprint, b: &PageFingerprint) -> f32 {
    let structure = jaccard_str(&a.tag_bigrams, &b.tag_bigrams);
    let content = combined_content_jaccard(a, b);
    0.85 * structure + 0.15 * content
}

pub fn classify(a: &PageFingerprint, b: &PageFingerprint) -> Similarity {
    if a.simhash == b.simhash {
        return Similarity::Identical;
    }

    let shape_score = shape_content_score(a, b);
    let simhash_distance = hamming(a.simhash, b.simhash);

    if shape_score >= 0.65 && simhash_distance <= 3 {
        return Similarity::High;
    }
    if shape_score >= 0.50 || simhash_distance <= 6 {
        return Similarity::Moderate;
    }

    if shape_score >= 0.30 && corroborates_similarity(a, b) {
        return Similarity::Corroborated;
    }

    Similarity::Distinct
}

fn combined_content_jaccard(a: &PageFingerprint, b: &PageFingerprint) -> f32 {
    let pool_a = combined_content_pool(a);
    let pool_b = combined_content_pool(b);

    if pool_a.is_empty() && pool_b.is_empty() {
        return 1.0;
    }
    if pool_a.is_empty() || pool_b.is_empty() {
        return 0.0;
    }

    let intersection = pool_a.intersection(&pool_b).count();
    let union = pool_a.len() + pool_b.len() - intersection;
    intersection as f32 / union as f32
}

fn combined_content_pool(fp: &PageFingerprint) -> HashSet<&String> {
    fp.word_tokens.iter().chain(fp.css_classes.iter()).collect()
}

fn corroborates_similarity(a: &PageFingerprint, b: &PageFingerprint) -> bool {
    title_pair_similarity(&a.title, &b.title)
        || title_pair_similarity(&a.h1, &b.h1)
        || css_jaccard(&a.css_classes, &b.css_classes) >= 0.70
}

fn title_pair_similarity(a: &Option<String>, b: &Option<String>) -> bool {
    matches!((a, b), (Some(left), Some(right)) if title_similarity(left, right) >= 0.80)
}

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
        assert!(!fp.word_tokens.contains("amp"));
        assert!(!fp.word_tokens.contains("nbsp"));
        assert!(fp.word_tokens.contains("terms"));
        assert!(fp.word_tokens.contains("conditions"));
        assert!(fp.word_tokens.contains("privacy"));
    }

    #[test]
    fn self_closing_input_in_bigrams() {
        let html = "<html><body><form><input/><button>ok</button></form></body></html>";
        let fp = fingerprint(html);
        assert!(fp.tag_bigrams.contains("form>input"));
        assert!(fp.tag_bigrams.contains("form>button"));
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
        let html = "<html><head><title>Acme Corp - Home</title></head><body></body></html>";
        assert_eq!(fingerprint(html).title.as_deref(), Some("Acme Corp - Home"));
    }

    #[test]
    fn title_similarity_unicode_safe() {
        let a = "링크킹 - 무료 애니메이션 스트리밍";
        let b = "링크킹 TV - 애니메이션";
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
        assert!(!fp.word_tokens.contains("a"));
        assert!(fp.word_tokens.contains("bb"));
        assert!(fp.word_tokens.contains("ccc"));
    }
}
