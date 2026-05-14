//! ARI feature extraction — 1:1 port of `core/utils.py::feature_extraction_ari`.
//!
//! Output layout: `[lens(dim) | ack_delta(dim)]` length `2*dim`.
//! `lens` are zero-padded if the flow has fewer than `dim` `select_dir` packets.
//! `ack_delta[0]` is always 0 (matches Python's `uni_ack_delta = [0]` seed),
//! subsequent entries are `-(ackᵢ - ackᵢ₋₁)` with these rules:
//!   - `diff <= 0` → skip (delta vector grows shorter, trailing zeros remain)
//!   - `diff > 100000` → push 0 (different from skip — slot is consumed)
//!
//! Deltas are computed in i64 to avoid u32 wrap.

pub fn extract_ari(
    lens: &[u32],
    acks: &[u32],
    dirs: &[u8],
    dim: usize,
    select_dir: u8,
) -> Vec<f32> {
    let mut out = vec![0.0f32; dim * 2];

    let mut uni_lens: Vec<u32> = Vec::with_capacity(dim);
    let mut uni_acks: Vec<u32> = Vec::with_capacity(dim);
    for (i, &d) in dirs.iter().enumerate() {
        if d != select_dir {
            continue;
        }
        if uni_lens.len() >= dim {
            break;
        }
        uni_lens.push(lens[i]);
        uni_acks.push(acks[i]);
    }

    for (i, &v) in uni_lens.iter().enumerate() {
        out[i] = v as f32;
    }

    // Mirror Python: seed delta with 0, iterate from index 1.
    let mut delta: Vec<f32> = Vec::with_capacity(dim);
    delta.push(0.0);
    for i in 1..uni_acks.len() {
        let diff = uni_acks[i] as i64 - uni_acks[i - 1] as i64;
        if diff <= 0 {
            continue;
        }
        let val = if diff > 100_000 { 0 } else { -diff };
        delta.push(val as f32);
    }

    let copy_n = delta.len().min(dim);
    out[dim..dim + copy_n].copy_from_slice(&delta[..copy_n]);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dir_yields_zeros() {
        let lens = vec![100u32, 200, 300];
        let acks = vec![10u32, 20, 30];
        let dirs = vec![0u8, 0, 0]; // none match select_dir=1
        let f = extract_ari(&lens, &acks, &dirs, 5, 1);
        assert_eq!(f, vec![0.0; 10]);
    }

    #[test]
    fn lens_padded_when_short() {
        let lens = vec![100u32, 200];
        let acks = vec![10u32, 50];
        let dirs = vec![1u8, 1];
        let f = extract_ari(&lens, &acks, &dirs, 4, 1);
        // lens[0..4] = [100, 200, 0, 0]
        assert_eq!(&f[0..4], &[100.0, 200.0, 0.0, 0.0]);
        // delta[0]=0 (seed), delta[1] = -(50-10) = -40
        assert_eq!(&f[4..8], &[0.0, -40.0, 0.0, 0.0]);
    }

    #[test]
    fn diff_le_zero_skipped() {
        // ack sequence: 100, 100, 200 → diffs: 0 (skip), 100 (-100)
        // delta = [0, -100]; rest zero-padded.
        let lens = vec![10u32, 20, 30];
        let acks = vec![100u32, 100, 200];
        let dirs = vec![1u8, 1, 1];
        let f = extract_ari(&lens, &acks, &dirs, 4, 1);
        assert_eq!(&f[4..8], &[0.0, -100.0, 0.0, 0.0]);
    }

    #[test]
    fn diff_over_100k_becomes_zero_not_skipped() {
        // diffs: 200000 (→ 0, slot consumed), 50 (→ -50)
        let lens = vec![10u32, 20, 30];
        let acks = vec![0u32, 200_000, 200_050];
        let dirs = vec![1u8, 1, 1];
        let f = extract_ari(&lens, &acks, &dirs, 4, 1);
        // delta = [0, 0, -50]
        assert_eq!(&f[4..8], &[0.0, 0.0, -50.0, 0.0]);
    }

    #[test]
    fn truncates_to_dim() {
        let lens: Vec<u32> = (1..=10).collect();
        let acks: Vec<u32> = (0..10).map(|i| i * 100).collect();
        let dirs = vec![1u8; 10];
        let f = extract_ari(&lens, &acks, &dirs, 3, 1);
        assert_eq!(&f[0..3], &[1.0, 2.0, 3.0]);
        // delta[0]=0, delta[1] = -100, delta[2] = -100
        assert_eq!(&f[3..6], &[0.0, -100.0, -100.0]);
    }

    #[test]
    fn mixed_directions_filtered() {
        let lens = vec![999, 100, 999, 200, 999];
        let acks = vec![0u32, 50, 0, 150, 0];
        let dirs = vec![0u8, 1, 0, 1, 0];
        let f = extract_ari(&lens, &acks, &dirs, 3, 1);
        assert_eq!(&f[0..3], &[100.0, 200.0, 0.0]);
        // delta = [0, -100]
        assert_eq!(&f[3..6], &[0.0, -100.0, 0.0]);
    }
}
