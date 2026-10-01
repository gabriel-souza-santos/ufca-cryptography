use std::fs;

/// A parsed cryptogram with its ID, length, and ciphertext bytes (0-25).
#[derive(Debug, Clone)]
pub struct Cryptogram {
    pub id: usize,
    pub size: usize,
    /// Ciphertext as bytes in 0..25 (A=0, B=1, ..., Z=25).
    pub data: Vec<u8>,
    /// Original ciphertext string (uppercase A-Z).
    pub raw: String,
}

impl Cryptogram {
    /// Parse all cryptograms from the input file.
    pub fn parse_file(path: &str) -> Vec<Cryptogram> {
        let content = fs::read_to_string(path).expect("Failed to read cryptograms file");
        let lines: Vec<&str> = content.lines().collect();
        let mut cryptograms = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            // Look for header line: "Criptograma #N, tamanho: M"
            if line.starts_with("Criptograma #") {
                let parts: Vec<&str> = line.split(',').collect();
                let id_part = parts[0].trim_start_matches("Criptograma #");
                let id: usize = id_part.trim().parse().expect("Invalid cryptogram ID");

                let size_part = parts[1].trim().trim_start_matches("tamanho:").trim();
                let size: usize = size_part.parse().expect("Invalid cryptogram size");

                // Next non-empty line is the ciphertext
                i += 1;
                while i < lines.len() && lines[i].trim().is_empty() {
                    i += 1;
                }
                if i < lines.len() {
                    let raw = lines[i].trim().to_string();
                    let data: Vec<u8> = raw.bytes().map(|b| b - b'A').collect();
                    assert_eq!(
                        data.len(),
                        size,
                        "Cryptogram #{} size mismatch: expected {}, got {}",
                        id,
                        size,
                        data.len()
                    );
                    cryptograms.push(Cryptogram {
                        id,
                        size,
                        data,
                        raw,
                    });
                }
            }
            i += 1;
        }

        cryptograms
    }
}
