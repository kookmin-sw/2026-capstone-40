use std::collections::HashSet;

pub fn css_jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    jaccard_str(a, b)
}

pub fn hamming(a: i64, b: i64) -> u32 {
    (a ^ b).count_ones()
}

/// Levenshtein similarity ratio in [0.0, 1.0]. Char-safe and capped at 200 chars.
pub fn title_similarity(a: &str, b: &str) -> f32 {
    let a: String = a.trim().chars().take(200).collect();
    let b: String = b.trim().chars().take(200).collect();

    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let left_len = a.chars().count();
    let right_len = b.chars().count();
    1.0 - levenshtein(&a, &b) as f32 / left_len.max(right_len) as f32
}

pub(crate) fn jaccard_str(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let intersection = a.intersection(b).count();
    intersection as f32 / (a.len() + b.len() - intersection) as f32
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];

    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1]
            } else {
                1 + prev[j - 1].min(prev[j]).min(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b.len()]
}
