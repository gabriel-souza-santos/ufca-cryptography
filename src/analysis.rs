use crate::cryptogram::Cryptogram;
use crate::dictionary::LanguageStats;

/// Calculate the Index of Coincidence for a sequence of byte values (0-25).
pub fn index_of_coincidence(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let mut counts = [0u64; 26];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ic = 0.0;
    for &c in &counts {
        ic += c as f64 * (c as f64 - 1.0);
    }
    ic / (n * (n - 1.0))
}

/// For a given key length k, split ciphertext into k columns and compute
/// the average IC across all columns.
pub fn average_column_ic(ciphertext: &[u8], key_len: usize) -> f64 {
    if key_len == 0 || key_len >= ciphertext.len() {
        return 0.0;
    }
    let mut total_ic = 0.0;
    let mut valid_cols = 0;
    for col in 0..key_len {
        let column: Vec<u8> = ciphertext
            .iter()
            .skip(col)
            .step_by(key_len)
            .copied()
            .collect();
        if column.len() >= 2 {
            total_ic += index_of_coincidence(&column);
            valid_cols += 1;
        }
    }
    if valid_cols == 0 {
        0.0
    } else {
        total_ic / valid_cols as f64
    }
}

/// Rank candidate key lengths for a Vigenère cipher by average column IC.
/// Returns a list of (key_length, avg_ic) sorted descending by IC score.
pub fn rank_key_lengths(cryptogram: &Cryptogram, stats: &LanguageStats) -> Vec<(usize, f64)> {
    let max_key_len = cryptogram.size - 1;
    let mut candidates: Vec<(usize, f64)> = (1..=max_key_len)
        .map(|k| {
            let avg_ic = average_column_ic(&cryptogram.data, k);
            (k, avg_ic)
        })
        .collect();

    // Sort by proximity to the target IC (closer = better), then by IC descending
    let target = stats.target_ic;
    candidates.sort_by(|a, b| {
        let diff_a = (a.1 - target).abs();
        let diff_b = (b.1 - target).abs();
        diff_a
            .partial_cmp(&diff_b)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    candidates
}

/// Compute a chi-squared-like fitness score for a decrypted text against
/// expected language letter probabilities. Lower is better.
pub fn chi_squared_score(plaintext: &[u8], stats: &LanguageStats) -> f64 {
    let mut counts = [0u64; 26];
    for &b in plaintext {
        counts[b as usize] += 1;
    }
    let n = plaintext.len() as f64;
    let mut score = 0.0;
    for i in 0..26 {
        let expected = stats.letter_probs[i] * n;
        let observed = counts[i] as f64;
        if expected > 0.0 {
            score += (observed - expected).powi(2) / expected;
        }
    }
    score
}

/// For a given column of ciphertext and a shift value, decrypt the column
/// and compute chi-squared against expected distribution. Lower is better.
pub fn column_shift_score(column: &[u8], shift: u8, stats: &LanguageStats) -> f64 {
    let decrypted: Vec<u8> = column.iter().map(|&c| (c + 26 - shift) % 26).collect();
    chi_squared_score(&decrypted, stats)
}

/// For a given key length k, find the best shift for each column position
/// by minimizing chi-squared. Returns (key, total_score).
pub fn best_key_for_length(
    ciphertext: &[u8],
    key_len: usize,
    stats: &LanguageStats,
) -> (Vec<u8>, f64) {
    let mut key = Vec::with_capacity(key_len);
    let mut total_score = 0.0;

    for col in 0..key_len {
        let column: Vec<u8> = ciphertext
            .iter()
            .skip(col)
            .step_by(key_len)
            .copied()
            .collect();

        let mut best_shift = 0u8;
        let mut best_score = f64::MAX;
        for shift in 0..26u8 {
            let score = column_shift_score(&column, shift, stats);
            if score < best_score {
                best_score = score;
                best_shift = shift;
            }
        }
        key.push(best_shift);
        total_score += best_score;
    }

    (key, total_score)
}

/// Decrypt ciphertext with a Vigenère key (both as 0-25 byte arrays).
pub fn decrypt_vigenere(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    ciphertext
        .iter()
        .enumerate()
        .map(|(i, &c)| (c + 26 - key[i % key.len()]) % 26)
        .collect()
}

/// Convert 0-25 byte array back to uppercase string.
pub fn bytes_to_string(data: &[u8]) -> String {
    data.iter().map(|&b| (b + b'A') as char).collect()
}

/// Convert key bytes (0-25) to a readable key string.
pub fn key_to_string(key: &[u8]) -> String {
    bytes_to_string(key)
}
