use std::collections::{HashMap, HashSet};
use std::fs;

/// A node in the prefix trie for dictionary-based word segmentation.
#[derive(Debug, Clone)]
pub struct TrieNode {
    pub children: HashMap<u8, TrieNode>,
    pub is_word: bool,
}

impl TrieNode {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_word: false,
        }
    }

    /// Insert a word (uppercase ASCII bytes A-Z mapped to 0-25) into the trie.
    pub fn insert(&mut self, word: &[u8]) {
        let mut node = self;
        for &ch in word {
            let idx = ch - b'A';
            node = node.children.entry(idx).or_insert_with(TrieNode::new);
        }
        node.is_word = true;
    }

    /// Check if a prefix exists in the trie starting from this node.
    pub fn get_child(&self, idx: u8) -> Option<&TrieNode> {
        self.children.get(&idx)
    }
}

/// Language statistics derived from the dictionary.
pub struct LanguageStats {
    /// Letter frequency counts.
    pub letter_counts: [u64; 26],
    /// Total letters in dictionary.
    pub total_letters: u64,
    /// Letter probabilities p_i.
    pub letter_probs: [f64; 26],
    /// Target index of coincidence = sum(p_i^2).
    pub target_ic: f64,
}

/// The full dictionary context: word set, prefix trie, and language stats.
pub struct Dictionary {
    pub words: HashSet<String>,
    pub trie: TrieNode,
    pub stats: LanguageStats,
    /// Valid single-letter words.
    pub valid_single_letters: HashSet<u8>,
}

impl Dictionary {
    /// Load and parse the dictionary from a file path.
    pub fn load(path: &str) -> Self {
        let content = fs::read_to_string(path).expect("Failed to read dictionary file");
        let mut words = HashSet::new();
        let mut trie = TrieNode::new();
        let mut letter_counts = [0u64; 26];
        let mut total_letters = 0u64;

        for token in content.split_whitespace() {
            let word = token.trim().to_uppercase();
            if word.is_empty() {
                continue;
            }
            // Count letters
            for &b in word.as_bytes() {
                if b >= b'A' && b <= b'Z' {
                    letter_counts[(b - b'A') as usize] += 1;
                    total_letters += 1;
                }
            }
            // Insert into trie
            trie.insert(word.as_bytes());
            words.insert(word);
        }

        // Calculate probabilities and IC
        let mut letter_probs = [0.0f64; 26];
        let mut target_ic = 0.0f64;
        if total_letters > 0 {
            for i in 0..26 {
                letter_probs[i] = letter_counts[i] as f64 / total_letters as f64;
                target_ic += letter_probs[i] * letter_probs[i];
            }
        }

        let stats = LanguageStats {
            letter_counts,
            total_letters,
            letter_probs,
            target_ic,
        };

        // Valid single-letter words in Portuguese: A, E, O
        let mut valid_single_letters = HashSet::new();
        valid_single_letters.insert(b'A' - b'A'); // 0
        valid_single_letters.insert(b'E' - b'A'); // 4
        valid_single_letters.insert(b'O' - b'A'); // 14

        Dictionary {
            words,
            trie,
            stats,
            valid_single_letters,
        }
    }

    /// Check if a word exists in the dictionary.
    pub fn contains(&self, word: &str) -> bool {
        self.words.contains(word)
    }

    /// Check if a single-letter word is valid (A, E, O only).
    pub fn is_valid_single_letter(&self, ch: u8) -> bool {
        self.valid_single_letters.contains(&ch)
    }
}
