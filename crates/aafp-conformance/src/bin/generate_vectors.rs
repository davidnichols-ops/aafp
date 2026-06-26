//! Binary to generate test vector documentation.

use aafp_conformance::handshake_vectors::generate_handshake_markdown;
use aafp_conformance::test_vectors::generate_markdown;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("handshake") => print!("{}", generate_handshake_markdown()),
        _ => print!("{}", generate_markdown()),
    }
}
