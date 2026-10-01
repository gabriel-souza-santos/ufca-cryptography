use crate::analysis;
use crate::cryptogram::Cryptogram;
use crate::dictionary::Dictionary;

/// A candidate solution with its key, segmented plaintext, and score.
#[derive(Debug, Clone)]
pub struct Solution {
    pub cryptogram_id: usize,
    /// Key as 0-25 byte array.
    pub key: Vec<u8>,
    /// Decrypted plaintext as 0-25 byte array (no spaces).
    pub plaintext: Vec<u8>,
    /// Segmented plaintext with spaces.
    pub segmented: String,
    /// Number of dictionary words found in segmentation.
    pub word_count: usize,
    /// Chi-squared score (lower = better fit to language distribution).
    pub chi_score: f64,
}

/// Attempt to segment a plaintext (0-25 bytes) into valid dictionary words
/// using recursive backtracking on the trie.
pub fn segment_text(plaintext: &[u8], dict: &Dictionary) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    let mut current_words = Vec::new();
    segment_recursive(plaintext, 0, dict, &mut current_words, &mut results);
    results
}

fn segment_recursive(
    text: &[u8],
    pos: usize,
    dict: &Dictionary,
    current_words: &mut Vec<String>,
    results: &mut Vec<Vec<String>>,
) {
    if pos == text.len() {
        results.push(current_words.clone());
        return;
    }

    // Cap to avoid combinatorial explosion
    if results.len() >= 50 {
        return;
    }

    let mut node = &dict.trie;
    for end in pos..text.len() {
        let ch = text[end];
        match node.get_child(ch) {
            Some(child) => {
                node = child;
                if node.is_word {
                    let word_len = end - pos + 1;
                    // Enforce single-letter word constraint
                    if word_len == 1 && !dict.is_valid_single_letter(ch) {
                        continue;
                    }
                    let word: String =
                        text[pos..=end].iter().map(|&b| (b + b'A') as char).collect();
                    current_words.push(word);
                    segment_recursive(text, end + 1, dict, current_words, results);
                    current_words.pop();
                }
            }
            None => break,
        }
    }
}

/// For each column, get the top-N best shifts by chi-squared score.
fn top_shifts_per_column(
    ciphertext: &[u8],
    key_len: usize,
    dict: &Dictionary,
    top_n: usize,
) -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(key_len);
    for col in 0..key_len {
        let column: Vec<u8> = ciphertext
            .iter()
            .skip(col)
            .step_by(key_len)
            .copied()
            .collect();
        let mut scores: Vec<(u8, f64)> = (0..26u8)
            .map(|shift| (shift, analysis::column_shift_score(&column, shift, &dict.stats)))
            .collect();
        scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        scores.truncate(top_n);
        result.push(scores.into_iter().map(|(s, _)| s).collect());
    }
    result
}

/// Multi-shift exploration: try top-N shifts per column, validate with segmentation.
/// Total combinations capped to avoid explosion.
fn solve_multi_shift(
    cryptogram: &Cryptogram,
    key_len: usize,
    dict: &Dictionary,
    top_n: usize,
) -> Vec<Solution> {
    let top_shifts = top_shifts_per_column(&cryptogram.data, key_len, dict, top_n);
    let mut solutions = Vec::new();
    let mut key = vec![0u8; key_len];
    let mut attempts = 0usize;

    explore_shifts(cryptogram, &top_shifts, 0, &mut key, dict, &mut solutions, &mut attempts);

    solutions
}

fn explore_shifts(
    cryptogram: &Cryptogram,
    top_shifts: &[Vec<u8>],
    col: usize,
    key: &mut Vec<u8>,
    dict: &Dictionary,
    solutions: &mut Vec<Solution>,
    attempts: &mut usize,
) {
    const MAX_ATTEMPTS: usize = 5000;
    if solutions.len() >= 20 || *attempts >= MAX_ATTEMPTS {
        return;
    }

    if col == top_shifts.len() {
        *attempts += 1;
        // Full key — decrypt and try segmentation
        let plaintext = analysis::decrypt_vigenere(&cryptogram.data, key);
        let segs = segment_text(&plaintext, dict);
        for seg in segs {
            if solutions.len() >= 20 {
                break;
            }
            let segmented = seg.join(" ");
            let chi = analysis::chi_squared_score(&plaintext, &dict.stats);
            solutions.push(Solution {
                cryptogram_id: cryptogram.id,
                key: key.clone(),
                plaintext: plaintext.clone(),
                segmented,
                word_count: seg.len(),
                chi_score: chi,
            });
        }
        return;
    }

    for &shift in &top_shifts[col] {
        key[col] = shift;
        explore_shifts(cryptogram, top_shifts, col + 1, key, dict, solutions, attempts);
    }
}

/// Main solver entry point for a single Vigenère cryptogram.
/// Strategy:
///   1. For each candidate key length, try the statistical best key + segmentation.
///   2. Multi-shift exploration with bounded top_n to keep it fast.
pub fn solve_cryptogram(cryptogram: &Cryptogram, dict: &Dictionary) -> Vec<Solution> {
    let ranked = analysis::rank_key_lengths(cryptogram, &dict.stats);
    let mut all_solutions = Vec::new();

    // Only try top 5 key lengths — enough to find the right one
    for &(key_len, _ic) in ranked.iter().take(5) {
        if key_len == 0 {
            continue;
        }

        // Strategy 1: Statistical best-key estimation + segmentation (instant)
        let (stat_key, _score) =
            analysis::best_key_for_length(&cryptogram.data, key_len, &dict.stats);
        let plaintext = analysis::decrypt_vigenere(&cryptogram.data, &stat_key);
        let segs = segment_text(&plaintext, dict);
        for seg in &segs {
            let segmented = seg.join(" ");
            let chi = analysis::chi_squared_score(&plaintext, &dict.stats);
            all_solutions.push(Solution {
                cryptogram_id: cryptogram.id,
                key: stat_key.clone(),
                plaintext: plaintext.clone(),
                segmented,
                word_count: seg.len(),
                chi_score: chi,
            });
        }

        // Strategy 2: Multi-shift exploration
        // Pick top_n so total combos (top_n ^ key_len) stays under ~5000
        let top_n = match key_len {
            1 => 26,    // 26
            2 => 10,    // 100
            3 => 8,     // 512
            4 => 6,     // 1296
            5 => 5,     // 3125
            6 => 4,     // 4096
            7 => 3,     // 2187
            8 => 3,     // 6561
            9 => 2,     // 512
            10 => 2,    // 1024
            _ => 2,     // 2^k
        };

        let multi_solutions = solve_multi_shift(cryptogram, key_len, dict, top_n);
        all_solutions.extend(multi_solutions);
    }

    // Deduplicate and sort by chi-squared (lower = better)
    all_solutions.sort_by(|a, b| a.chi_score.partial_cmp(&b.chi_score).unwrap());
    let mut seen = std::collections::HashSet::new();
    all_solutions.retain(|s| seen.insert(s.segmented.clone()));

    all_solutions
}

