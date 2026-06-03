use std::io::{Read, Write};
use std::process::exit;

use mordred_hermes_tpmkey::{ops::UnavailableOps, run_with};

fn main() {
    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        let _ = std::io::stdout().write_all(
            br#"{"error":{"domain":"helper","status":-1,"message":"failed to read stdin"}}"#,
        );
        exit(1);
    }

    // Phase 2a ships the pure-function scaffold only; the real TPM backend
    // (Linux + tss-esapi) lands in Phase 2b. Until then every command answers
    // with the neutral `UNAVAILABLE` reason.
    let (json, code) = run_with(&input, &UnavailableOps);

    let _ = std::io::stdout().write_all(json.as_bytes());
    exit(code);
}
