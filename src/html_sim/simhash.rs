pub(crate) fn simhash_text(text: &str) -> i64 {
    let bytes = text.as_bytes();
    let mut weights = [0i32; 64];

    for window in bytes.windows(3) {
        let hash = fnv1a_64(window);
        for bit in 0..64u64 {
            if (hash >> bit) & 1 == 1 {
                weights[bit as usize] += 1;
            } else {
                weights[bit as usize] -= 1;
            }
        }
    }

    let mut fingerprint = 0u64;
    for bit in 0..64u64 {
        if weights[bit as usize] > 0 {
            fingerprint |= 1 << bit;
        }
    }
    fingerprint as i64
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = 14695981039346656037u64;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}
