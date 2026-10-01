mod analysis;
mod cryptogram;
mod dictionary;
mod solver;

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;

/// Confirmed Vigenère cryptogram IDs.
const VIGENERE_IDS: &[usize] = &[7, 11, 17, 22, 27, 33, 37, 44, 47, 55, 57, 66, 67];

/// Paired plaintexts: (Monoalphabetic ID, Vigenère ID).
const PAIRED_IDS: &[(usize, usize)] = &[
    (10, 11),
    (21, 22),
    (32, 33),
    (43, 44),
    (54, 55),
    (65, 66),
];

fn main() {
    println!("=== Multi-Threaded Vigenère & Polyalphabetic Cryptanalysis Engine ===");
    println!();

    // Phase 1: Load dictionary and compute language statistics
    println!("[Phase 1] Loading dictionary and computing language statistics...");
    let dict = Arc::new(dictionary::Dictionary::load("res/dictionary.txt"));
    println!("  Dictionary: {} words loaded", dict.words.len());
    println!("  Total letters analyzed: {}", dict.stats.total_letters);
    println!("  Target IC: {:.6}", dict.stats.target_ic);
    println!("  Top letter frequencies:");
    let mut freq_pairs: Vec<(char, f64)> = (0..26)
        .map(|i| ((i as u8 + b'A') as char, dict.stats.letter_probs[i]))
        .collect();
    freq_pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    for &(ch, prob) in freq_pairs.iter().take(5) {
        println!("    {}: {:.4}", ch, prob);
    }
    println!();

    // Parse cryptograms
    println!("[Phase 1] Parsing cryptograms...");
    let cryptograms = cryptogram::Cryptogram::parse_file("res/cryptograms.txt");
    println!("  {} cryptograms parsed", cryptograms.len());
    println!();

    // Build lookup
    let vigenere_set: HashSet<usize> = VIGENERE_IDS.iter().copied().collect();

    // Create output directory
    fs::create_dir_all("solutions").expect("Failed to create solutions directory");

    // Phase 2: Solve confirmed Vigenère cryptograms in parallel
    println!("[Phase 2] Solving confirmed Vigenère cryptograms...");
    println!("  Target IDs: {:?}", VIGENERE_IDS);
    println!();

    let vigenere_cryptograms: Vec<&cryptogram::Cryptogram> = cryptograms
        .iter()
        .filter(|c| vigenere_set.contains(&c.id))
        .collect();

    let dict_ref = Arc::clone(&dict);
    let results: Vec<(usize, Vec<solver::Solution>)> = vigenere_cryptograms
        .par_iter()
        .map(|c| {
            let solutions = solver::solve_cryptogram(c, &dict_ref);
            (c.id, solutions)
        })
        .collect();

    // Phase 3: Output results
    println!("[Phase 3] Writing solutions...");
    println!();

    let mut solution_map: HashMap<usize, Vec<solver::Solution>> = HashMap::new();

    for (id, solutions) in &results {
        solution_map.insert(*id, solutions.clone());

        // Write solution file
        write_solution_file(*id, solutions);

        // Print summary
        if solutions.is_empty() {
            println!("  Cryptogram #{:>2}: No valid segmentation found", id);
        } else {
            let best = &solutions[0];
            println!(
                "  Cryptogram #{:>2}: Key={:<10} | Words={} | χ²={:.2} | {}",
                id,
                analysis::key_to_string(&best.key),
                best.word_count,
                best.chi_score,
                &best.segmented
            );
        }
    }

    // Phase 3b: Handle paired cryptograms
    println!();
    println!("[Phase 3b] Cross-referencing paired cryptograms...");
    for &(mono_id, vig_id) in PAIRED_IDS {
        if let Some(solutions) = solution_map.get(&vig_id) {
            if let Some(best) = solutions.first() {
                println!(
                    "  Pair ({}, {}): Vigenère #{} solution => Mono #{} plaintext: {}",
                    mono_id, vig_id, vig_id, mono_id, &best.segmented
                );

                let mut paired_output = String::new();
                paired_output.push_str(&format!("Cryptogram #{} (Monoalphabetic)\n", mono_id));
                paired_output.push_str(&format!("Paired with Vigenère Cryptogram #{}\n", vig_id));
                paired_output.push_str(&format!("Shared Plaintext: {}\n", &best.segmented));
                paired_output.push_str("(Deduced from Vigenère twin)\n");
                paired_output.push_str("--------------------------------------------------\n");
                let path = format!("solutions/cryptogram_{:02}.txt", mono_id);
                fs::write(&path, paired_output).expect("Failed to write paired solution");
            }
        }
    }

    println!();
    println!("=== Analysis complete. Solutions written to solutions/ ===");
}

/// Write solution(s) for a single cryptogram to a file.
fn write_solution_file(id: usize, solutions: &[solver::Solution]) {
    let path = format!("solutions/cryptogram_{:02}.txt", id);
    let mut output = String::new();

    output.push_str(&format!("Cryptogram #{}\n", id));

    if solutions.is_empty() {
        output.push_str("No valid candidate plaintexts found.\n");
    } else {
        for (i, sol) in solutions.iter().enumerate() {
            if i > 0 {
                output.push('\n');
            }
            output.push_str(&format!("Key: {}\n", analysis::key_to_string(&sol.key)));
            output.push_str(&format!("Decrypted Text: {}\n", sol.segmented));
            output.push_str(&format!("Words: {} | Chi-Squared: {:.4}\n", sol.word_count, sol.chi_score));
            output.push_str("--------------------------------------------------\n");
        }
    }

    fs::write(&path, &output).expect("Failed to write solution file");
}
